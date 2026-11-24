// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package probe

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
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

// Run collects the sections named by req and returns the report. It
// returns an error only when no report can be produced; sections that were
// cut short by the runtime limit are returned with partial or no coverage.
func Run(ctx context.Context, req report.Request, opts Options) (*report.Report, error) {
	start := time.Now()
	log := opts.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	want, err := wantedSections(req, log)
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
	r.procs = procs
	if owner != nil {
		linkPackages(env.Proc, procs, env.Path("/"), owner.Owner)
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
	if req.GoSymbols != nil {
		rep.GoSymbols = r.goSymbols(req.GoSymbols)
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

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// runner holds the state shared by the sections of one run.
type runner struct {
	env *collect.Env
	// procs is the processes section of the run, nil when not collected;
	// container scans link its processes to their image's packages.
	procs    *report.ProcessesSection
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
	in := artifact.Inputs{Running: running, OpenFiles: open.forRoot(r.env.Path("/")), WalkPaths: r.env.Policy.WalkPaths}
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

// goSymbols answers the Go symbol query. Paths without a container are
// under the inspected root; container paths are under the root of a
// process of that container, opened so that links cannot leave it.
func (r *runner) goSymbols(q *report.GoSymbolQuery) *report.GoSymbolsSection {
	if r.expired() {
		return &report.GoSymbolsSection{SectionMeta: r.skipped(false)}
	}
	var ids []string
	for _, f := range q.Files {
		if f.Container != "" {
			ids = append(ids, f.Container)
		}
	}
	var pids map[string]int
	var roots []*os.Root
	defer func() {
		for _, rt := range roots {
			rt.Close()
		}
	}()
	openerFor := func(container string) (fileOpener, string) {
		if container == "" {
			return func(p string) (*os.File, error) { return os.Open(r.env.Path(p)) }, ""
		}
		if !r.env.Privileged {
			return nil, "container content needs privileges"
		}
		if pids == nil {
			pids = proc.ContainerPIDs(r.env.Proc, ids)
		}
		pid, ok := pids[container]
		if !ok {
			return nil, "container not running"
		}
		rt, err := os.OpenRoot(filepath.Join(r.env.Proc, strconv.Itoa(pid), "root"))
		if err != nil {
			return nil, fmt.Sprintf("cannot open container root: %v", err)
		}
		roots = append(roots, rt)
		return func(p string) (*os.File, error) { return rt.Open(strings.TrimPrefix(p, "/")) }, ""
	}
	var sec *report.GoSymbolsSection
	if !r.bounded(func() { sec = answerGoSymbols(r.ctx, q, openerFor) }) || sec == nil {
		return &report.GoSymbolsSection{SectionMeta: r.skipped(true)}
	}
	return sec
}
