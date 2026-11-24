// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package vulnsvc

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// Request and response bodies of POST /v1/match (feed-server api/openapi).

type matchRequest struct {
	Targets []target `json:"targets"`
}

type target struct {
	ID         string      `json:"id"`
	OS         *targetOS   `json:"os,omitempty"`
	Components []component `json:"components"`
}

type targetOS struct {
	ID        string `json:"id"`
	VersionID string `json:"version_id,omitempty"`
}

type component struct {
	Ref        string         `json:"ref"`
	PURL       string         `json:"purl,omitempty"`
	CPE        string         `json:"cpe,omitempty"`
	Origin     string         `json:"origin,omitempty"`
	Modularity string         `json:"modularity,omitempty"`
	Source     *sourcePackage `json:"source,omitempty"`
}

type sourcePackage struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type matchResult struct {
	Data struct {
		Revision int64  `json:"revision"`
		Rules    string `json:"rules"`
	} `json:"data"`
	Targets         []targetResult           `json:"targets"`
	Vulnerabilities map[string]vulnerability `json:"vulnerabilities"`
}

type targetResult struct {
	ID         string            `json:"id"`
	OSKey      string            `json:"os_key"`
	OSError    string            `json:"os_error"`
	Components []componentResult `json:"components"`
}

type componentResult struct {
	Ref     string  `json:"ref"`
	Status  string  `json:"status"`
	Reason  string  `json:"reason"`
	Matches []match `json:"matches"`
}

type match struct {
	VulnID       string               `json:"vuln_id"`
	Method       string               `json:"method"`
	Ecosystem    string               `json:"ecosystem"`
	FixState     string               `json:"fix_state"`
	FixedVersion string               `json:"fixed_version"`
	CPEMatch     string               `json:"cpe_match"`
	RangeSource  string               `json:"range_source"`
	Platforms    []string             `json:"platforms"`
	Advisories   []store.VulnAdvisory `json:"advisories"`
	// Symbols are the vulnerable functions of Go matches.
	Symbols []store.GoImport `json:"symbols"`
}

type vulnerability struct {
	ID          string   `json:"id"`
	Aliases     []string `json:"aliases"`
	Summary     string   `json:"summary"`
	Description string   `json:"description"`
	CVSS        []struct {
		Source   string  `json:"source"`
		Type     string  `json:"type"`
		Version  string  `json:"version"`
		Vector   string  `json:"vector"`
		Score    float64 `json:"score"`
		Severity string  `json:"severity"`
	} `json:"cvss"`
	CWEs       []string   `json:"cwes"`
	References []string   `json:"references"`
	Published  *time.Time `json:"published"`
	Modified   *time.Time `json:"modified"`
	KEV        *struct {
		DateAdded      string `json:"date_added"`
		DueDate        string `json:"due_date"`
		Name           string `json:"name"`
		RequiredAction string `json:"required_action"`
		RansomwareUse  string `json:"ransomware_use"`
	} `json:"kev"`
	EPSS *struct {
		Score      float64 `json:"score"`
		Percentile float64 `json:"percentile"`
	} `json:"epss"`
}

// osPackageTypes are the component types matched against an OS release.
var osPackageTypes = map[string]bool{"deb": true, "rpm": true, "apk": true}

// osOf returns the os-release identity of an OS package: the ID from the
// purl namespace, the VERSION_ID from the distro qualifier
// ("<id>-<version_id>"). ok is false for other components and for packages
// of an unknown distribution.
func osOf(c store.Component) (targetOS, bool) {
	if !osPackageTypes[c.Type] {
		return targetOS{}, false
	}
	rest, found := strings.CutPrefix(c.PURL, "pkg:"+c.Type+"/")
	if !found {
		return targetOS{}, false
	}
	ns, _, found := strings.Cut(rest, "/")
	if !found || ns == "" || ns == "unknown" {
		return targetOS{}, false
	}
	id := strings.ToLower(ns)
	version, _ := strings.CutPrefix(c.Distro, id+"-")
	if version == c.Distro {
		version = ""
	}
	return targetOS{ID: id, VersionID: version}, true
}

// buildRequest groups components by OS into targets. Target IDs are
// positions; nothing about the assets is sent.
func buildRequest(comps []store.Component) matchRequest {
	var req matchRequest
	index := map[targetOS]int{}
	const noOS = -1
	plain := noOS
	for _, c := range comps {
		wc := component{Ref: c.ID, PURL: c.PURL, CPE: c.CPE, Modularity: c.Modularity}
		os, hasOS := osOf(c)
		if hasOS && c.Origin != "" {
			wc.Origin = string(c.Origin)
		}
		if c.SourceName != "" && osPackageTypes[c.Type] {
			wc.Source = &sourcePackage{Name: c.SourceName, Version: c.SourceVersion}
		}
		var i int
		switch {
		case hasOS:
			n, ok := index[os]
			if !ok {
				o := os
				req.Targets = append(req.Targets, target{ID: "t" + strconv.Itoa(len(req.Targets)), OS: &o})
				n = len(req.Targets) - 1
				index[os] = n
			}
			i = n
		default:
			if plain == noOS {
				req.Targets = append(req.Targets, target{ID: "t" + strconv.Itoa(len(req.Targets))})
				plain = len(req.Targets) - 1
			}
			i = plain
		}
		req.Targets[i].Components = append(req.Targets[i].Components, wc)
	}
	return req
}

// convert turns a response into a batch. Every sent component must be in
// the response.
func convert(res *matchResult, comps []store.Component, epoch store.MatchEpoch, at time.Time) (store.MatchBatch, error) {
	sent := make(map[string]bool, len(comps))
	for _, c := range comps {
		sent[c.ID] = true
	}
	b := store.MatchBatch{Epoch: epoch, At: at}
	used := map[string]bool{}
	for _, t := range res.Targets {
		for _, cr := range t.Components {
			if !sent[cr.Ref] {
				return store.MatchBatch{}, fmt.Errorf("vulnsvc: match response names unknown component %q", cr.Ref)
			}
			delete(sent, cr.Ref)
			cm := store.ComponentMatch{ComponentID: cr.Ref, OSKey: t.OSKey, Status: cr.Status, Reason: cr.Reason}
			switch cr.Status {
			case store.MatchChecked, store.MatchUnsupported, store.MatchInvalid:
			default:
				return store.MatchBatch{}, fmt.Errorf("vulnsvc: match status %q", cr.Status)
			}
			if cm.Reason == "" && t.OSError != "" && cr.Status != store.MatchChecked {
				cm.Reason = t.OSError
			}
			for _, mt := range cr.Matches {
				if _, ok := res.Vulnerabilities[mt.VulnID]; !ok {
					return store.MatchBatch{}, fmt.Errorf("vulnsvc: match names %s without its details", mt.VulnID)
				}
				used[mt.VulnID] = true
				cm.Vulns = append(cm.Vulns, store.ComponentVuln{VulnID: mt.VulnID, Method: mt.Method, Ecosystem: mt.Ecosystem,
					FixState: mt.FixState, FixedVersion: mt.FixedVersion, CPEMatch: mt.CPEMatch, RangeSource: mt.RangeSource,
					Platforms: mt.Platforms, Advisories: mt.Advisories, Symbols: goImports(mt.Symbols)})
			}
			b.Components = append(b.Components, cm)
		}
	}
	if len(sent) > 0 {
		return store.MatchBatch{}, fmt.Errorf("vulnsvc: match response misses %d components", len(sent))
	}
	for id := range used {
		b.Vulns = append(b.Vulns, vulnMeta(id, res.Vulnerabilities[id]))
	}
	return b, nil
}

func vulnMeta(id string, v vulnerability) store.VulnMeta {
	m := store.VulnMeta{ID: id, Aliases: v.Aliases, Summary: v.Summary, Description: v.Description,
		CWEs: v.CWEs, References: v.References, Published: v.Published, Modified: v.Modified}
	for _, c := range v.CVSS {
		m.CVSS = append(m.CVSS, store.CVSSScore{Source: c.Source, Type: c.Type, Version: c.Version, Vector: c.Vector,
			Score: c.Score, Severity: c.Severity})
		if m.MaxScore == nil || c.Score > *m.MaxScore {
			s := c.Score
			m.MaxScore = &s
		}
	}
	if m.MaxScore != nil {
		m.Severity = Rating(*m.MaxScore)
	}
	if k := v.KEV; k != nil && k.DateAdded != "" {
		m.KEV = &store.KEVEntry{DateAdded: k.DateAdded, DueDate: k.DueDate, Name: k.Name,
			RequiredAction: k.RequiredAction, RansomwareUse: k.RansomwareUse}
	}
	if e := v.EPSS; e != nil {
		score, pct := e.Score, e.Percentile
		m.EPSS, m.EPSSPercentile = &score, &pct
	}
	return m
}

// Rating is the CVSS v3/v4 qualitative rating of a base score.
func Rating(score float64) string {
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0:
		return "low"
	}
	return "none"
}

// goImports keeps the imports that name a package and functions, with names
// of bounded length, so that a query built from them stays valid.
func goImports(in []store.GoImport) []store.GoImport {
	var out []store.GoImport
	for _, g := range in {
		if g.Path == "" || len(g.Symbols) == 0 {
			continue
		}
		var syms []string
		for _, s := range g.Symbols {
			if s != "" && len(g.Path)+1+len(s) <= report.MaxGoSymbolNameLen {
				syms = append(syms, s)
			}
		}
		if len(syms) == 0 {
			continue
		}
		g.Symbols = syms
		out = append(out, g)
	}
	return out
}
