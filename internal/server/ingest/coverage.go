// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package ingest

import (
	"sort"
	"strings"
	"time"

	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// rank orders coverages from least to most complete.
func rank(c store.Coverage) int { return store.CoverageRank(c) }

// sectionCoverage maps a report coverage to the stored one. An empty value
// is treated as full: collectors always set it, and an old agent that did
// not is assumed to have read everything.
func sectionCoverage(c report.Coverage) store.Coverage {
	switch c {
	case report.CoveragePartial:
		return store.CoveragePartial
	case report.CoverageNone:
		return store.CoverageNone
	}
	return store.CoverageFull
}

// containerCoverage maps a report container coverage. A container whose
// content was not read (none) is inventory only; empty keeps the stored
// value.
func containerCoverage(c report.Coverage) store.Coverage {
	switch c {
	case report.CoverageFull:
		return store.CoverageFull
	case report.CoveragePartial:
		return store.CoveragePartial
	case report.CoverageNone:
		return store.CoverageInventoryOnly
	}
	return ""
}

type sectionKey struct{ container, section string }

// plan is what to do with one report section.
type plan struct {
	name  string
	meta  *report.SectionMeta
	at    time.Time
	state store.SectionState
	// present: the section is in the report and not older than the stored
	// state; its state is written.
	present bool
	// apply: present and carries items (not Unchanged).
	apply bool
	// keepMissing: the coverage is below the baseline the stored items were
	// collected with, so items that are not observed are kept (ARCH 3.6).
	keepMissing bool
}

// planSection decides about one section against the stored states.
func (s *Service) planSection(r *report.Report, container, name string, m *report.SectionMeta, stored map[sectionKey]store.SectionState) plan {
	p := plan{name: name, meta: m}
	if m == nil {
		return p
	}
	p.at = s.reportTime(r, m)
	old, had := stored[sectionKey{container, name}]
	if had && p.at.Before(old.CollectedAt) {
		s.log.Debug("ignoring older section", "section", name, "container", container,
			"collected_at", p.at, "stored", old.CollectedAt)
		return p
	}
	p.present = true
	p.apply = !m.Unchanged
	cov := sectionCoverage(m.Coverage)
	digest := m.Digest
	if digest == "" && m.Unchanged && had {
		digest = old.Digest
	}
	p.state = store.SectionState{Container: container, Section: name, Coverage: cov, Reason: m.Reason,
		Digest: digest, CollectedAt: p.at}
	baseline := old.Baseline
	if baseline == "" {
		baseline = old.Coverage
	}
	p.keepMissing = had && rank(cov) < rank(baseline)
	return p
}

// hostCoverage summarizes the section states of a host asset:
//
//	full            packages, artifacts and processes collected in full (and
//	                containers, when collected, too)
//	process_only    only processes collected
//	inventory_only  none of packages, artifacts and processes collected
//	partial         anything else; the reason lists the sections
func hostCoverage(states map[sectionKey]store.SectionState) (store.Coverage, string) {
	content := []string{report.SectionPackages, report.SectionArtifacts, report.SectionProcesses}
	have := map[string]store.SectionState{}
	for k, st := range states {
		if k.container == "" {
			have[k.section] = st
		}
	}
	_, pk := have[report.SectionPackages]
	_, ar := have[report.SectionArtifacts]
	_, pr := have[report.SectionProcesses]
	switch {
	case !pk && !ar && !pr:
		return store.CoverageInventoryOnly, "no software sections collected"
	case !pk && !ar:
		if st := have[report.SectionProcesses]; st.Coverage != store.CoverageFull {
			return store.CoverageProcessOnly, "processes: " + reasonOf(st)
		}
		return store.CoverageProcessOnly, ""
	}
	var notes []string
	for _, name := range append(content, report.SectionContainers) {
		st, ok := have[name]
		switch {
		case !ok && name == report.SectionContainers:
		case !ok:
			notes = append(notes, name+": not collected")
		case st.Coverage != store.CoverageFull:
			notes = append(notes, name+": "+reasonOf(st))
		}
	}
	if len(notes) == 0 {
		return store.CoverageFull, ""
	}
	return store.CoveragePartial, strings.Join(notes, "; ")
}

func reasonOf(st store.SectionState) string {
	if st.Reason != "" {
		return st.Reason
	}
	return string(st.Coverage)
}

// workloadCoverage summarizes the current containers of a workload: all
// alike gives that coverage, a mix gives partial with the containers that
// are not full.
func workloadCoverage(cs []store.Container) (store.Coverage, string) {
	var cur []store.Container
	for _, c := range cs {
		if c.GoneAt == nil {
			cur = append(cur, c)
		}
	}
	if len(cur) == 0 {
		return store.CoverageInventoryOnly, "no containers"
	}
	sort.Slice(cur, func(i, j int) bool { return cur[i].Name < cur[j].Name })
	first := normalizeContainerCoverage(cur[0].Coverage)
	same := true
	var notes []string
	for _, c := range cur {
		cov := normalizeContainerCoverage(c.Coverage)
		if cov != first {
			same = false
		}
		if cov != store.CoverageFull {
			note := c.Name + ": " + string(cov)
			if c.CoverageReason != "" {
				note += " (" + c.CoverageReason + ")"
			}
			notes = append(notes, note)
		}
	}
	if same && (first == store.CoverageFull || first == store.CoverageProcessOnly ||
		first == store.CoverageInventoryOnly) {
		if first == store.CoverageFull {
			return first, ""
		}
		return first, strings.Join(notes, "; ")
	}
	return store.CoveragePartial, strings.Join(notes, "; ")
}

func normalizeContainerCoverage(c store.Coverage) store.Coverage {
	switch c {
	case store.CoverageUnsupported, store.CoverageNone, "":
		return store.CoverageInventoryOnly
	}
	return c
}
