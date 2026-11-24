// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package probe

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"time"

	"github.com/bomcensus/bomcensus/internal/report"
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

// wantedSections resolves the requested section names and checks the
// Go symbol query. Unknown names are ignored so that an older probe still
// answers a newer caller. The set is empty when only go_symbols was named.
func wantedSections(req report.Request, log *slog.Logger) (sectionSet, error) {
	if req.GoSymbols != nil {
		if err := req.GoSymbols.Validate(); err != nil {
			return nil, fmt.Errorf("probe: %w", err)
		}
	}
	set := sectionSet{}
	if len(req.Sections) == 0 {
		for _, n := range report.AllSections {
			set[n] = true
		}
		return set, nil
	}
	symbols := false
	for _, n := range req.Sections {
		switch {
		case slices.Contains(report.AllSections, n):
			set[n] = true
		case n == report.SectionGoSymbols:
			symbols = true
		default:
			log.Warn("unknown section ignored", "section", n)
		}
	}
	if len(set) == 0 && !(symbols && req.GoSymbols != nil) {
		return nil, errors.New("probe: no known section requested")
	}
	return set, nil
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
		rep.Artifacts = &report.ArtifactsSection{SectionMeta: unchanged(s.SectionMeta), WalkPaths: s.WalkPaths}
	}
	if s := rep.Containers; s != nil && same(report.SectionContainers, &s.SectionMeta) {
		rep.Containers = &report.ContainersSection{SectionMeta: unchanged(s.SectionMeta)}
	}
}

func unchanged(m report.SectionMeta) report.SectionMeta {
	m.Unchanged = true
	return m
}
