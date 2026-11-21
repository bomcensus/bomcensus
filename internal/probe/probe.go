// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package probe assembles one collection report from the collectors and
// restricts the probe process before it reads anything (see sandbox.go).
//
// Run collects the requested sections in the order host, packages,
// processes, artifacts, containers. Artifacts depend on the package owner
// index and on the running executables, so those are collected whenever
// artifacts are requested, even if their own sections are not emitted. The
// content of running containers is read through /proc/<pid>/root, once per
// image digest.
package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/bomcensus/bomcensus/internal/collect"
	"github.com/bomcensus/bomcensus/internal/collect/artifact"
	"github.com/bomcensus/bomcensus/internal/collect/hostinfo"
	"github.com/bomcensus/bomcensus/internal/collect/pkgdb"
	"github.com/bomcensus/bomcensus/internal/collect/proc"
	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/version"
)

// Defaults for policy values that are zero.
const (
	DefaultMaxRuntime    = 15 * time.Minute
	DefaultMemoryLimitMB = 512
)

// MaxRequestSize bounds the request read from standard input.
const MaxRequestSize = 64 << 20

// Options are the parts of a run that do not come from the request.
type Options struct {
	// Log receives progress and problems. Nil discards.
	Log *slog.Logger
	// Root and Proc override the host root ("/") and the proc mount
	// ("/proc"). Tests point them at fixtures.
	Root, Proc string
	// Privilege, when set, is reported and used instead of detecting it.
	Privilege *report.Privilege
	// ProcessLimits applies the memory limit, GOMAXPROCS cap and lowest
	// scheduling priority to the whole process. The command sets it; tests
	// leave it off.
	ProcessLimits bool
	// MaxContainers bounds how many containers have their content scanned
	// in one run (image scopes and writable layers). Zero means 32.
	MaxContainers int
	// ContainerTimeout bounds the scan of one container. Zero means 3
	// minutes. The overall runtime limit applies as well.
	ContainerTimeout time.Duration
	// Grace is how long a section may run past the runtime limit before it
	// is abandoned. Zero means a twentieth of the limit, between 2 and 30
	// seconds.
	Grace time.Duration
}

// DecodeRequest reads a JSON request of at most MaxRequestSize bytes. Empty
// input yields the default request. Fields missing from the policy keep
// their default values.
func DecodeRequest(r io.Reader) (report.Request, error) {
	req := report.Request{Policy: report.DefaultPolicy()}
	data, err := io.ReadAll(io.LimitReader(r, MaxRequestSize+1))
	if err != nil {
		return req, fmt.Errorf("probe: read request: %w", err)
	}
	if len(data) > MaxRequestSize {
		return req, fmt.Errorf("probe: request larger than %d bytes", MaxRequestSize)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return req, nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&req); err != nil {
		return req, fmt.Errorf("probe: decode request: %w", err)
	}
	if dec.More() {
		return req, errors.New("probe: trailing data after request")
	}
	return req, nil
}

// Run collects the sections named by req and returns the report. It
// returns an error only when no report can be produced; sections that were
// cut short by the runtime limit are returned with partial or no coverage.
func Run(ctx context.Context, req report.Request, opts Options) (*report.Report, error) {
	start := time.Now()
	log := opts.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	want, err := wantedSections(req.Sections, log)
	if err != nil {
		return nil, err
	}
	if opts.ProcessLimits {
		applyProcessLimits(req.Policy, log)
	}

	limit := DefaultMaxRuntime
	if req.Policy.MaxRuntimeSeconds > 0 {
		limit = time.Duration(req.Policy.MaxRuntimeSeconds) * time.Second
	}
	grace := opts.Grace
	if grace <= 0 {
		grace = min(max(limit/20, 2*time.Second), 30*time.Second)
	}
	runCtx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()

	env := &collect.Env{
		Root:   orDefault(opts.Root, "/"),
		Proc:   orDefault(opts.Proc, "/proc"),
		Policy: req.Policy,
		Cache:  collect.LoadHashCache(req.Cache),
		Log:    log,
	}
	var priv report.Privilege
	if opts.Privilege != nil {
		priv = *opts.Privilege
	} else {
		priv = DetectPrivilege(env.Proc)
	}
	env.Privileged = priv.Level == report.PrivilegePrivileged
	log.Info("collection started", "sections", strings.Join(want.list(), ","), "privilege", priv.Level,
		"uid", priv.UID, "limit", limit.String())

	r := &runner{
		env:      env,
		log:      log,
		opts:     opts,
		ctx:      runCtx,
		hardStop: start.Add(limit + grace),
		limit:    limit,
	}
	rep := &report.Report{
		SchemaVersion: report.SchemaVersion,
		ProbeVersion:  version.Version,
		CollectedAt:   start.UTC(),
		Privilege:     priv,
	}

	if want[report.SectionHost] {
		rep.Host = r.host()
	}
	var owner *pkgdb.Index
	// Container content is read only with privileges and when the policy
	// allows it; only then does the container section need the processes.
	scanContent := want[report.SectionContainers] && env.Privileged && req.Policy.ScanContainers
	if want[report.SectionPackages] || want[report.SectionArtifacts] {
		var sec *report.PackagesSection
		sec, owner = r.packages()
		if want[report.SectionPackages] {
			rep.Packages = sec
		}
	}
	var procs *report.ProcessesSection
	if want[report.SectionProcesses] || want[report.SectionArtifacts] || scanContent {
		procs = r.processes()
		if want[report.SectionProcesses] {
			rep.Processes = procs
		}
	}
	var running []artifact.RunningExe
	var open openFileIndex
	if want[report.SectionArtifacts] || scanContent {
		running = runningExes(procs)
		open = openJars(env.Proc, procs)
	}
	if want[report.SectionArtifacts] {
		rep.Artifacts = r.artifacts(owner, running, open)
	}
	if want[report.SectionContainers] {
		rep.Containers = r.containers(scanContent, running, open)
	}

	applyKnownDigests(rep, req.KnownDigests)
	if raw, err := env.Cache.Marshal(); err == nil {
		rep.Cache = raw
	} else {
		log.Warn("hash cache not returned", "err", err)
	}
	log.Info("collection finished", "duration", time.Since(start).Round(time.Millisecond).String())
	return rep, nil
}

type sectionSet map[string]bool

func (s sectionSet) list() []string {
	var out []string
	for _, name := range report.AllSections {
		if s[name] {
			out = append(out, name)
		}
	}
	return out
}

// wantedSections resolves the requested section names. Unknown names are
// ignored so that an older probe still answers a newer caller.
func wantedSections(names []string, log *slog.Logger) (sectionSet, error) {
	set := sectionSet{}
	if len(names) == 0 {
		for _, n := range report.AllSections {
			set[n] = true
		}
		return set, nil
	}
	for _, n := range names {
		if slices.Contains(report.AllSections, n) {
			set[n] = true
		} else {
			log.Warn("unknown section ignored", "section", n)
		}
	}
	if len(set) == 0 {
		return nil, errors.New("probe: no known section requested")
	}
	return set, nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// runner holds the state shared by the sections of one run.
type runner struct {
	env      *collect.Env
	log      *slog.Logger
	opts     Options
	ctx      context.Context
	hardStop time.Time
	limit    time.Duration
}

// bounded runs fn and waits for it until the hard stop. It reports false
// when fn was abandoned; fn then keeps running in the background and its
// results must not be used.
func (r *runner) bounded(fn func()) bool {
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	t := time.NewTimer(time.Until(r.hardStop))
	defer t.Stop()
	select {
	case <-done:
		return true
	case <-t.C:
		return false
	}
}

// skipped returns the metadata of a section that was not collected.
func (r *runner) skipped(started bool) report.SectionMeta {
	reason := fmt.Sprintf("runtime limit of %s reached before the section was collected", r.limit)
	if started {
		reason = fmt.Sprintf("section did not finish within the runtime limit of %s", r.limit)
	}
	return report.SectionMeta{Coverage: report.CoverageNone, Reason: reason, CollectedAt: time.Now().UTC()}
}

func (r *runner) expired() bool { return r.ctx.Err() != nil }

func (r *runner) host() *report.HostSection {
	if r.expired() {
		return &report.HostSection{SectionMeta: r.skipped(false)}
	}
	var sec *report.HostSection
	if !r.bounded(func() { sec = hostinfo.Collect(r.ctx, r.env) }) || sec == nil {
		return &report.HostSection{SectionMeta: r.skipped(true)}
	}
	return sec
}

func (r *runner) packages() (*report.PackagesSection, *pkgdb.Index) {
	if r.expired() {
		return &report.PackagesSection{SectionMeta: r.skipped(false)}, nil
	}
	var sec *report.PackagesSection
	var ix *pkgdb.Index
	if !r.bounded(func() { sec, ix = pkgdb.Collect(r.ctx, r.env) }) || sec == nil {
		return &report.PackagesSection{SectionMeta: r.skipped(true)}, nil
	}
	return sec, ix
}

func (r *runner) processes() *report.ProcessesSection {
	if r.expired() {
		return &report.ProcessesSection{SectionMeta: r.skipped(false)}
	}
	var sec *report.ProcessesSection
	if !r.bounded(func() { sec = proc.Collect(r.ctx, r.env) }) || sec == nil {
		return &report.ProcessesSection{SectionMeta: r.skipped(true)}
	}
	dropSelf(sec, r.env.Proc, r.log)
	return sec
}

func (r *runner) artifacts(owner *pkgdb.Index, running []artifact.RunningExe, open openFileIndex) *report.ArtifactsSection {
	if r.expired() {
		return &report.ArtifactsSection{SectionMeta: r.skipped(false)}
	}
	in := artifact.Inputs{Running: running, OpenFiles: open.forRoot(r.env.Path("/"))}
	if owner != nil {
		in.Owner = owner.Owner
	}
	var sec *report.ArtifactsSection
	if !r.bounded(func() { sec = artifact.Collect(r.ctx, r.env, in) }) || sec == nil {
		return &report.ArtifactsSection{SectionMeta: r.skipped(true)}
	}
	if r.env.Root == "/" {
		dropOwnBinary(sec, r.log)
	}
	return sec
}

// dropOwnBinary removes the probe binary from the artifacts. A scanner
// uploads it for one run, often under a new name each time.
func dropOwnBinary(sec *report.ArtifactsSection, log *slog.Logger) {
	if selfPath == "" || sec.Unchanged {
		return
	}
	n := len(sec.Artifacts)
	sec.Artifacts = slices.DeleteFunc(sec.Artifacts, func(a report.Artifact) bool { return a.Path == selfPath })
	if len(sec.Artifacts) == n || sec.Digest == "" {
		return
	}
	// Same body as the artifact collector's digest.
	if d, err := report.Digest(sec.Artifacts); err == nil {
		sec.Digest = d
	} else {
		log.Warn("artifact digest", "err", err)
	}
}

// applyKnownDigests empties the sections the caller already has.
func applyKnownDigests(rep *report.Report, known map[string]string) {
	same := func(name string, m *report.SectionMeta) bool {
		return m.Digest != "" && known[name] == m.Digest
	}
	if s := rep.Host; s != nil && same(report.SectionHost, &s.SectionMeta) {
		rep.Host = &report.HostSection{SectionMeta: unchanged(s.SectionMeta)}
	}
	if s := rep.Packages; s != nil && same(report.SectionPackages, &s.SectionMeta) {
		rep.Packages = &report.PackagesSection{SectionMeta: unchanged(s.SectionMeta)}
	}
	if s := rep.Processes; s != nil && same(report.SectionProcesses, &s.SectionMeta) {
		rep.Processes = &report.ProcessesSection{SectionMeta: unchanged(s.SectionMeta)}
	}
	if s := rep.Artifacts; s != nil && same(report.SectionArtifacts, &s.SectionMeta) {
		rep.Artifacts = &report.ArtifactsSection{SectionMeta: unchanged(s.SectionMeta)}
	}
	if s := rep.Containers; s != nil && same(report.SectionContainers, &s.SectionMeta) {
		rep.Containers = &report.ContainersSection{SectionMeta: unchanged(s.SectionMeta)}
	}
}

func unchanged(m report.SectionMeta) report.SectionMeta {
	m.Unchanged = true
	return m
}
