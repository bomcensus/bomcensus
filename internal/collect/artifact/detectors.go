// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package artifact

import (
	"github.com/bomcensus/bomcensus/internal/detectors"
	"github.com/bomcensus/bomcensus/internal/report"
)

// Detectors is the built-in known-software table, read from
// internal/detectors/detectors.yaml. To add software, add it there.
var Detectors = Load(detectors.ResolveBuiltin())

// Load builds the detectors of a resolved table (detectors.Resolve). The
// trust decisions are taken there; Load only carries them into the
// detectors: a version command is kept only where the entry allows it, and
// entries that are not built in are marked constrained.
func Load(r detectors.Resolved) []*Detector {
	out := make([]*Detector, 0, len(r.Entries))
	for _, e := range r.Entries {
		if d, ok := fromEntry(e); ok {
			out = append(out, d)
		}
	}
	return out
}

// fromEntry converts one entry. It fails only for a pattern that does not
// compile, which Resolve has already ruled out.
func fromEntry(e detectors.Entry) (*Detector, bool) {
	s := e.Spec
	d := &Detector{
		ID:    s.ID,
		Name:  s.Name,
		Names: s.Names,
		Paths: s.Paths,
		// Archive detectors never execute anything.
		Archive: s.Archive,
		PURL:    s.PURL,
		CPE:     s.CPE,
	}
	if !e.Builtin {
		d.constrained = true
		tag, err := report.Digest(s)
		if err != nil {
			return nil, false
		}
		d.cacheTag = tag[:16]
	}
	var ok bool
	if e.Exec {
		d.Exec = s.Exec
		d.AddressSpaceMB = s.AddressSpaceMB
		for _, v := range s.Env {
			d.Env = append(d.Env, EnvVar{Name: v.Name, Up: v.Up})
		}
		if d.Parse, ok = rules(s.Parse); !ok {
			return nil, false
		}
	}
	for _, st := range s.Static {
		r := StaticRule{File: st.File, Entry: st.Entry, BuildSetting: st.BuildSetting, GoMain: st.GoMain, Limit: st.Limit}
		if r.Rules, ok = rules(st.Rules); !ok {
			return nil, false
		}
		d.Static = append(d.Static, r)
	}
	return d, true
}

func rules(in []report.DetectorRule) ([]Rule, bool) {
	var out []Rule
	for _, r := range in {
		re, err := detectors.Compile(r.Pattern)
		if err != nil {
			return nil, false
		}
		out = append(out, Rule{Pattern: re, Name: r.Name, PURL: r.PURL, CPE: r.CPE})
	}
	return out, true
}
