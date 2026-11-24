// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package inventoryapi

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	openapi_types "github.com/oapi-codegen/runtime/types"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/apierr"
	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/internal/server/vulnsvc"
)

// summaryActions is the number of update actions in the summary.
const summaryActions = 10

// exposureLevel orders exposures for sorting, most exposed highest; an
// unknown exposure sorts below installed, as the console shows it.
var exposureLevel = map[string]int{
	store.ExposureListening: 4, store.ExposureRunning: 3, store.ExposureInstalled: 2, store.ExposureUnknown: 1,
}

// placeRank orders places most exposed first and, within one exposure,
// a linked vulnerable function before an unknown one before none.
func placeRank(exposure string, reach *gen.Reachability) int {
	r := 1
	if reach != nil {
		switch *reach {
		case gen.SymbolPresent:
			r = 2
		case gen.SymbolAbsent:
			r = 0
		}
	}
	return exposureLevel[exposure]*3 + r
}

func reachabilityDTO(r string) *gen.Reachability {
	if r == "" {
		return nil
	}
	v := gen.Reachability(r)
	return &v
}

// symbolNames lists the vulnerable functions of a match.
func symbolNames(imps []store.GoImport) *[]string {
	var out []string
	for _, g := range imps {
		out = append(out, g.Names()...)
	}
	if len(out) == 0 {
		return nil
	}
	return &out
}

func maxExposure(c store.ExposureCounts) string {
	switch {
	case c.Listening > 0:
		return store.ExposureListening
	case c.Running > 0:
		return store.ExposureRunning
	case c.Installed > 0:
		return store.ExposureInstalled
	}
	return store.ExposureUnknown
}

func exposureCountsDTO(c store.ExposureCounts) gen.ExposureCounts {
	return gen.ExposureCounts{Listening: c.Listening, Running: c.Running, Installed: c.Installed, Unknown: c.Unknown}
}

func countExposure(c *store.ExposureCounts, e string) {
	switch e {
	case store.ExposureListening:
		c.Listening++
	case store.ExposureRunning:
		c.Running++
	case store.ExposureInstalled:
		c.Installed++
	default:
		c.Unknown++
	}
}

func hasExposure(c store.ExposureCounts, e gen.Exposure) bool {
	switch e {
	case gen.ExposureListening:
		return c.Listening > 0
	case gen.ExposureRunning:
		return c.Running > 0
	case gen.ExposureInstalled:
		return c.Installed > 0
	case gen.ExposureUnknown:
		return c.Unknown > 0
	}
	return true
}

func severityOf(score *float64) *gen.Severity {
	if score == nil {
		return nil
	}
	s := gen.Severity(vulnsvc.Rating(*score))
	return &s
}

func severityPtr(s string) *gen.Severity {
	if s == "" {
		return nil
	}
	v := gen.Severity(s)
	return &v
}

func kevDate(k *store.KEVEntry) *openapi_types.Date {
	if k == nil {
		return nil
	}
	t, err := time.Parse(time.DateOnly, k.DateAdded)
	if err != nil {
		return nil
	}
	return &openapi_types.Date{Time: t}
}

func layerOf(l string) string {
	if l == "" {
		return "host"
	}
	return l
}

func processesDTO(ps []store.FindingProcessRef) []gen.FindingProcess {
	out := make([]gen.FindingProcess, 0, len(ps))
	for _, p := range ps {
		ports := p.Ports
		if ports == nil {
			ports = []string{}
		}
		out = append(out, gen.FindingProcess{Pid: p.PID, Exe: p.Exe, Pod: optStr(p.Pod), Ports: ports})
	}
	return out
}

// ── update actions ──────────────────────────────────────────────────────

func componentUnitDTO(r store.VulnComponentRow) gen.VulnComponent {
	out := gen.VulnComponent{
		ComponentId: r.Component.ID, Name: r.Component.Name, Version: r.Component.Version,
		Type: gen.ComponentType(r.Component.Type), Purl: optStr(r.Component.PURL),
		Cves: len(r.VulnIDs), Kev: len(r.KEVVulnIDs),
		SeverityCounts: gen.SeverityCounts{Critical: r.Severity.Critical, High: r.Severity.High, Medium: r.Severity.Medium,
			Low: r.Severity.Low, Unknown: r.Severity.Unknown},
		Score: r.MaxScore, Severity: severityOf(r.MaxScore), Epss: r.MaxEPSS,
		Exposure: gen.Exposure(maxExposure(r.Exposure)), ExposureCounts: exposureCountsDTO(r.Exposure),
		Assets: r.Assets, FixedVersions: r.FixedVersions, Processes: make([]gen.ProcessCount, 0, len(r.Processes)),
	}
	if out.FixedVersions == nil {
		out.FixedVersions = []string{}
	}
	slices.Sort(out.FixedVersions)
	if v := vulnsvc.MaxVersion(r.Component.Type, r.FixedVersions); v != "" {
		out.FixedVersion = &v
	}
	if r.Unfixed > 0 {
		n := r.Unfixed
		out.Unfixed = &n
	}
	if r.Deferred > 0 {
		n := r.Deferred
		out.Deferred = &n
	}
	for _, p := range r.Processes {
		out.Processes = append(out.Processes, gen.ProcessCount{Exe: p.Exe, Count: p.Count})
	}
	return out
}

// sortUnits orders update actions by exposure, then known exploitation,
// EPSS, CVSS and name.
func sortUnits(rows []store.VulnComponentRow) {
	slices.SortStableFunc(rows, func(a, b store.VulnComponentRow) int {
		return cmpRank(
			exposureLevel[maxExposure(a.Exposure)], exposureLevel[maxExposure(b.Exposure)],
			len(a.KEVVulnIDs) > 0, len(b.KEVVulnIDs) > 0, a.MaxEPSS, b.MaxEPSS, a.MaxScore, b.MaxScore,
			a.Component.Name+" "+a.Component.Version, b.Component.Name+" "+b.Component.Version)
	})
}

// cmpRank compares by exposure, KEV, EPSS and score (all descending), then
// by name.
func cmpRank(ea, eb int, ka, kb bool, epa, epb, sa, sb *float64, na, nb string) int {
	if c := cmp.Compare(eb, ea); c != 0 {
		return c
	}
	if ka != kb {
		if ka {
			return -1
		}
		return 1
	}
	if c := cmpDesc(epa, epb); c != 0 {
		return c
	}
	if c := cmpDesc(sa, sb); c != 0 {
		return c
	}
	return cmp.Compare(na, nb)
}

func cmpDesc(a, b *float64) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return 1
	case b == nil:
		return -1
	}
	return cmp.Compare(*b, *a)
}

func unitMatches(r store.VulnComponentRow, q *string, sev *gen.Severity, exp *gen.Exposure, kev *bool) bool {
	if sev != nil {
		n := map[gen.Severity]int{gen.SeverityCritical: r.Severity.Critical, gen.SeverityHigh: r.Severity.High, gen.SeverityMedium: r.Severity.Medium,
			gen.SeverityLow: r.Severity.Low, gen.SeverityNone: r.Severity.Unknown}[*sev]
		if n == 0 {
			return false
		}
	}
	if exp != nil && !hasExposure(r.Exposure, *exp) {
		return false
	}
	if kev != nil && (len(r.KEVVulnIDs) > 0) != *kev {
		return false
	}
	return textMatches(q, append([]string{r.Component.Name, r.Component.Version, r.Component.PURL}, r.VulnIDs...)...)
}

func textMatches(q *string, fields ...string) bool {
	if q == nil || *q == "" {
		return true
	}
	needle := strings.ToLower(*q)
	for _, f := range fields {
		if strings.Contains(strings.ToLower(f), needle) {
			return true
		}
	}
	return false
}

func pageSlice[T any](items []T, limit, offset *int) ([]T, error) {
	p, err := page(limit, offset)
	if err != nil {
		return nil, err
	}
	if p.Offset >= len(items) {
		return []T{}, nil
	}
	return items[p.Offset:min(p.Offset+p.Limit, len(items))], nil
}

// ListVulnerableComponents implements gen.StrictServerInterface.
func (h *Handlers) ListVulnerableComponents(ctx context.Context, req gen.ListVulnerableComponentsRequestObject) (gen.ListVulnerableComponentsResponseObject, error) {
	prm := req.Params
	rows, err := h.cfg.Store.VulnComponents(ctx, h.viewOptions(prm.IncludeDeferred))
	if err != nil {
		return nil, err
	}
	rows = slices.DeleteFunc(rows, func(r store.VulnComponentRow) bool {
		return !unitMatches(r, prm.Q, prm.Severity, prm.Exposure, prm.Kev)
	})
	sortUnits(rows)
	pg, err := pageSlice(rows, prm.Limit, prm.Offset)
	if err != nil {
		return nil, err
	}
	out := gen.ListVulnerableComponents200JSONResponse{Items: make([]gen.VulnComponent, 0, len(pg)), Total: len(rows)}
	for _, r := range pg {
		out.Items = append(out.Items, componentUnitDTO(r))
	}
	return out, nil
}

// unitOf aggregates the open findings of one component as VulnComponents
// does.
func unitOf(c store.Component, fs []store.OpenFinding) store.VulnComponentRow {
	r := store.VulnComponentRow{Component: c}
	vulns := map[string]store.OpenFinding{}
	type place struct{ asset, container string }
	places := map[place]string{}
	assets := map[string]bool{}
	fixes := map[string]bool{}
	procs := map[string]map[string]bool{}
	for _, f := range fs {
		vulns[f.VulnID] = f
		places[place{f.AssetID, f.Container}] = f.Exposure
		assets[f.AssetID] = true
		for _, p := range f.Processes {
			if procs[p.Exe] == nil {
				procs[p.Exe] = map[string]bool{}
			}
			procs[p.Exe][f.AssetID+"\x00"+f.Container+"\x00"+p.Pod+"\x00"+itoa(p.PID)] = true
		}
	}
	for id, f := range vulns {
		r.VulnIDs = append(r.VulnIDs, id)
		m := f.Meta
		switch m.Severity {
		case "critical":
			r.Severity.Critical++
			r.HotVulnIDs = append(r.HotVulnIDs, id)
		case "high":
			r.Severity.High++
			r.HotVulnIDs = append(r.HotVulnIDs, id)
		case "medium":
			r.Severity.Medium++
		case "low":
			r.Severity.Low++
		default:
			r.Severity.Unknown++
		}
		if m.KEV != nil {
			r.KEVVulnIDs = append(r.KEVVulnIDs, id)
		}
		r.MaxScore = maxPtr(r.MaxScore, m.MaxScore)
		r.MaxEPSS = maxPtr(r.MaxEPSS, m.EPSS)
		if f.Match.FixedVersion != "" {
			fixes[f.Match.FixedVersion] = true
		} else {
			r.Unfixed++
		}
	}
	for _, e := range places {
		countExposure(&r.Exposure, e)
	}
	r.Assets = len(assets)
	for v := range fixes {
		r.FixedVersions = append(r.FixedVersions, v)
	}
	for exe, set := range procs {
		r.Processes = append(r.Processes, store.ProcessCount{Exe: exe, Count: len(set)})
	}
	slices.SortFunc(r.Processes, func(a, b store.ProcessCount) int {
		if c := cmp.Compare(b.Count, a.Count); c != 0 {
			return c
		}
		return cmp.Compare(a.Exe, b.Exe)
	})
	if len(r.Processes) > 5 {
		r.Processes = r.Processes[:5]
	}
	slices.Sort(r.VulnIDs)
	return r
}

func maxPtr(a, b *float64) *float64 {
	if b == nil || (a != nil && *a >= *b) {
		return a
	}
	return b
}

func itoa(n int) string {
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
		if n == 0 {
			break
		}
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// locationsOf groups findings by place (asset and container).
func locationsOf(fs []store.OpenFinding) []gen.VulnLocation {
	type key struct{ asset, container, comp string }
	index := map[key]int{}
	var out []gen.VulnLocation
	type reach struct{ present, absent, n int }
	reaches := map[int]*reach{}
	for _, f := range fs {
		k := key{f.AssetID, f.Container, f.Component.ID}
		i, ok := index[k]
		if !ok {
			loc := gen.VulnLocation{
				AssetId: f.AssetID, AssetName: f.AssetName, AssetKind: gen.AssetKind(f.AssetKind), Container: optStr(f.Container),
				Layer: gen.FindingLayer(layerOf(f.Layer)), ImageDigest: optStr(f.ImageDigest),
				ComponentId: f.Component.ID, ComponentName: f.Component.Name, ComponentVersion: f.Component.Version,
				Locations: f.Locations, Exposure: gen.Exposure(f.Exposure), Processes: processesDTO(f.Processes), FirstSeen: f.FirstSeen,
			}
			if loc.Locations == nil {
				loc.Locations = []string{}
			}
			if f.Method != "" {
				m := gen.DetectMethod(f.Method)
				loc.Method = &m
			}
			index[k] = len(out)
			out = append(out, loc)
			i = len(out) - 1
		}
		out[i].Cves++
		if f.FirstSeen.Before(out[i].FirstSeen) {
			out[i].FirstSeen = f.FirstSeen
		}
		r := reaches[i]
		if r == nil {
			r = &reach{}
			reaches[i] = r
		}
		r.n++
		switch f.Reachability {
		case store.ReachSymbolPresent:
			r.present++
		case store.ReachSymbolAbsent:
			r.absent++
		}
	}
	for i, r := range reaches {
		switch {
		case r.present > 0:
			out[i].Reachability = reachabilityDTO(store.ReachSymbolPresent)
		case r.absent == r.n:
			out[i].Reachability = reachabilityDTO(store.ReachSymbolAbsent)
		}
		if r.absent > 0 {
			n := r.absent
			out[i].SymbolAbsent = &n
		}
	}
	slices.SortStableFunc(out, func(a, b gen.VulnLocation) int {
		if c := cmp.Compare(placeRank(string(b.Exposure), b.Reachability), placeRank(string(a.Exposure), a.Reachability)); c != 0 {
			return c
		}
		return cmp.Compare(a.AssetName, b.AssetName)
	})
	return out
}

// GetVulnerableComponent implements gen.StrictServerInterface.
func (h *Handlers) GetVulnerableComponent(ctx context.Context, req gen.GetVulnerableComponentRequestObject) (gen.GetVulnerableComponentResponseObject, error) {
	fs, err := h.cfg.Store.OpenFindings(ctx, store.OpenFindingFilter{ComponentID: req.Id, At: h.cfg.Now()})
	if err != nil {
		return nil, err
	}
	if len(fs) == 0 {
		return nil, apierr.NotFound("vulnerable component")
	}
	out := gen.GetVulnerableComponent200JSONResponse{
		Component: componentUnitDTO(unitOf(fs[0].Component, fs)),
		Locations: locationsOf(fs),
	}
	// One row per vulnerability: the most exposed place and its processes.
	type agg struct {
		f        store.OpenFinding
		assets   map[string]bool
		places   map[string]string
		rules    rulesOf
		deferred int
	}
	byVuln := map[string]*agg{}
	var order []string
	for _, f := range fs {
		a := byVuln[f.VulnID]
		if a == nil {
			a = &agg{f: f, assets: map[string]bool{}, places: map[string]string{}, rules: rulesOf{}}
			byVuln[f.VulnID] = a
			order = append(order, f.VulnID)
		}
		a.assets[f.AssetID] = true
		a.places[f.AssetID+"\x00"+f.Container] = f.Exposure
		a.rules.add(f)
		if f.Triage != nil && f.Triage.Active {
			a.deferred++
		}
		if exposureLevel[f.Exposure] > exposureLevel[a.f.Exposure] {
			a.f.Exposure, a.f.Processes = f.Exposure, f.Processes
		}
	}
	for _, id := range order {
		a := byVuln[id]
		var ec store.ExposureCounts
		for _, e := range a.places {
			countExposure(&ec, e)
		}
		v := cveDTO(a.f.Meta, 1, len(a.assets), ec)
		fs := gen.FixState(a.f.Match.FixState)
		v.FixState, v.FixedVersion = &fs, optStr(a.f.Match.FixedVersion)
		p := processesDTO(a.f.Processes)
		v.Processes = &p
		if a.deferred > 0 {
			n := a.deferred
			v.Deferred = &n
		}
		rs := a.rules.dto(h.cfg.Now())
		v.Rules = &rs
		out.Cves = append(out.Cves, v)
	}
	sortCves(out.Cves)
	return out, nil
}

// ── vulnerabilities ─────────────────────────────────────────────────────

func cveDTO(m store.VulnMeta, components, assets int, ec store.ExposureCounts) gen.VulnCve {
	return gen.VulnCve{
		VulnId: m.ID, Summary: optStr(m.Summary), Severity: severityPtr(m.Severity), Score: m.MaxScore,
		Kev: m.KEV != nil, KevAdded: kevDate(m.KEV), Epss: m.EPSS, EpssPercentile: m.EPSSPercentile,
		Components: components, Assets: assets, Exposure: gen.Exposure(maxExposure(ec)), ExposureCounts: exposureCountsDTO(ec),
	}
}

func sortCves(vs []gen.VulnCve) {
	slices.SortStableFunc(vs, func(a, b gen.VulnCve) int {
		return cmpRank(exposureLevel[string(a.Exposure)], exposureLevel[string(b.Exposure)], a.Kev, b.Kev,
			a.Epss, b.Epss, a.Score, b.Score, a.VulnId, b.VulnId)
	})
}

// ListVulnerabilities implements gen.StrictServerInterface.
func (h *Handlers) ListVulnerabilities(ctx context.Context, req gen.ListVulnerabilitiesRequestObject) (gen.ListVulnerabilitiesResponseObject, error) {
	prm := req.Params
	rows, err := h.cfg.Store.VulnCves(ctx, h.viewOptions(prm.IncludeDeferred))
	if err != nil {
		return nil, err
	}
	var items []gen.VulnCve
	for _, r := range rows {
		if prm.Severity != nil && string(*prm.Severity) != r.Meta.Severity &&
			!(*prm.Severity == gen.SeverityNone && r.Meta.Severity == "") {
			continue
		}
		if prm.Exposure != nil && !hasExposure(r.Exposure, *prm.Exposure) {
			continue
		}
		if prm.Kev != nil && (r.Meta.KEV != nil) != *prm.Kev {
			continue
		}
		if !textMatches(prm.Q, append(append([]string{r.Meta.ID, r.Meta.Summary}, r.Meta.Aliases...), r.ComponentNames...)...) {
			continue
		}
		v := cveDTO(r.Meta, r.Components, r.Assets, r.Exposure)
		if r.Deferred > 0 {
			n := r.Deferred
			v.Deferred = &n
		}
		items = append(items, v)
	}
	sortCves(items)
	pg, err := pageSlice(items, prm.Limit, prm.Offset)
	if err != nil {
		return nil, err
	}
	return gen.ListVulnerabilities200JSONResponse{Items: pg, Total: len(items)}, nil
}

func vulnDetailDTO(m store.VulnMeta) gen.VulnDetail {
	out := gen.VulnDetail{
		VulnId: m.ID, Aliases: m.Aliases, Summary: optStr(m.Summary), Description: optStr(m.Description),
		Severity: severityPtr(m.Severity), Score: m.MaxScore, Cwes: m.CWEs, References: m.References,
		Epss: m.EPSS, EpssPercentile: m.EPSSPercentile, Published: m.Published, Modified: m.Modified,
		Cvss: make([]gen.CvssScore, 0, len(m.CVSS)),
	}
	for _, s := range []*[]string{&out.Aliases, &out.Cwes, &out.References} {
		if *s == nil {
			*s = []string{}
		}
	}
	for _, c := range m.CVSS {
		out.Cvss = append(out.Cvss, gen.CvssScore{Source: optStr(c.Source), Type: optStr(c.Type), Version: c.Version,
			Vector: c.Vector, Score: c.Score, Severity: optStr(c.Severity)})
	}
	if k := m.KEV; k != nil {
		if d := kevDate(k); d != nil {
			e := gen.KevEntry{DateAdded: *d, Name: optStr(k.Name), RequiredAction: optStr(k.RequiredAction),
				RansomwareUse: optStr(k.RansomwareUse)}
			if t, err := time.Parse(time.DateOnly, k.DueDate); err == nil {
				e.DueDate = &openapi_types.Date{Time: t}
			}
			out.Kev = &e
		}
	}
	return out
}

// GetVulnerability implements gen.StrictServerInterface.
func (h *Handlers) GetVulnerability(ctx context.Context, req gen.GetVulnerabilityRequestObject) (gen.GetVulnerabilityResponseObject, error) {
	fs, err := h.cfg.Store.OpenFindings(ctx, store.OpenFindingFilter{VulnID: req.VulnId, At: h.cfg.Now()})
	if err != nil {
		return nil, err
	}
	if len(fs) == 0 {
		return nil, apierr.NotFound("vulnerability")
	}
	out := gen.GetVulnerability200JSONResponse{
		Vulnerability: vulnDetailDTO(fs[0].Meta),
		Locations:     locationsOf(fs),
	}
	type agg struct {
		f        store.OpenFinding
		assets   map[string]bool
		rules    rulesOf
		findings int
		deferred int
	}
	byComp := map[string]*agg{}
	var order []string
	for _, f := range fs {
		a := byComp[f.Component.ID]
		if a == nil {
			a = &agg{f: f, assets: map[string]bool{}, rules: rulesOf{}}
			byComp[f.Component.ID] = a
			order = append(order, f.Component.ID)
		}
		a.assets[f.AssetID] = true
		a.findings++
		a.rules.add(f)
		if f.Triage != nil && f.Triage.Active {
			a.deferred++
		}
		if exposureLevel[f.Exposure] > exposureLevel[a.f.Exposure] {
			a.f.Exposure = f.Exposure
		}
	}
	for _, id := range order {
		a := byComp[id]
		m := a.f.Match
		c := gen.VulnCveComponent{
			ComponentId: id, Name: a.f.Component.Name, Version: a.f.Component.Version, Type: gen.ComponentType(a.f.Component.Type),
			Purl: optStr(a.f.Component.PURL), Method: gen.VulnCveComponentMethod(m.Method), Ecosystem: optStr(m.Ecosystem),
			FixState: gen.FixState(m.FixState), FixedVersion: optStr(m.FixedVersion), Platforms: m.Platforms,
			Advisories: make([]gen.VulnAdvisory, 0, len(m.Advisories)), Assets: len(a.assets), Exposure: gen.Exposure(a.f.Exposure),
		}
		findings, deferred, rules := a.findings, a.deferred, a.rules.dto(h.cfg.Now())
		c.Findings, c.Deferred, c.Rules = &findings, &deferred, &rules
		if c.Platforms == nil {
			c.Platforms = []string{}
		}
		if m.CPEMatch != "" {
			v := gen.VulnCveComponentCpeMatch(m.CPEMatch)
			c.CpeMatch = &v
		}
		if m.RangeSource != "" {
			v := gen.VulnCveComponentRangeSource(m.RangeSource)
			c.RangeSource = &v
		}
		for _, adv := range m.Advisories {
			c.Advisories = append(c.Advisories, gen.VulnAdvisory{Source: adv.Source, Id: adv.ID, Severity: optStr(adv.Severity)})
		}
		out.Components = append(out.Components, c)
	}
	slices.SortStableFunc(out.Components, func(a, b gen.VulnCveComponent) int {
		return cmp.Compare(exposureLevel[string(b.Exposure)], exposureLevel[string(a.Exposure)])
	})
	return out, nil
}

// ── assets ──────────────────────────────────────────────────────────────

// ListAssetVulnerabilities implements gen.StrictServerInterface.
func (h *Handlers) ListAssetVulnerabilities(ctx context.Context, req gen.ListAssetVulnerabilitiesRequestObject) (gen.ListAssetVulnerabilitiesResponseObject, error) {
	if _, err := h.cfg.Store.GetAsset(ctx, req.Id); errors.Is(err, store.ErrNotFound) {
		return nil, apierr.NotFound("asset")
	} else if err != nil {
		return nil, err
	}
	fs, err := h.cfg.Store.OpenFindings(ctx, store.OpenFindingFilter{AssetID: req.Id, At: h.cfg.Now()})
	if err != nil {
		return nil, err
	}
	out := gen.ListAssetVulnerabilities200JSONResponse{Items: make([]gen.AssetVuln, 0, len(fs))}
	for _, f := range fs {
		out.Items = append(out.Items, gen.AssetVuln{
			ComponentId: f.Component.ID, ComponentName: f.Component.Name, ComponentVersion: f.Component.Version,
			ComponentPurl: optStr(f.Component.PURL),
			Container:     optStr(f.Container), Layer: gen.FindingLayer(layerOf(f.Layer)), ImageDigest: optStr(f.ImageDigest),
			VulnId: f.VulnID, Summary: optStr(f.Meta.Summary), Severity: severityPtr(f.Meta.Severity), Score: f.Meta.MaxScore,
			Kev: f.Meta.KEV != nil, Epss: f.Meta.EPSS, Exposure: gen.Exposure(f.Exposure), FixState: gen.FixState(f.Match.FixState),
			FixedVersion: optStr(f.Match.FixedVersion), Processes: processesDTO(f.Processes), FirstSeen: f.FirstSeen,
			Triage:       findingTriageDTO(f, h.cfg.Now()),
			Reachability: reachabilityDTO(f.Reachability), Symbols: symbolNames(f.Match.Symbols),
		})
	}
	slices.SortStableFunc(out.Items, func(a, b gen.AssetVuln) int {
		return cmpRank(placeRank(string(a.Exposure), a.Reachability), placeRank(string(b.Exposure), b.Reachability), a.Kev, b.Kev,
			a.Epss, b.Epss, a.Score, b.Score, a.ComponentName+" "+a.VulnId, b.ComponentName+" "+b.VulnId)
	})
	return out, nil
}

// ── summary ─────────────────────────────────────────────────────────────

// GetVulnerabilitySummary implements gen.StrictServerInterface.
func (h *Handlers) GetVulnerabilitySummary(ctx context.Context, _ gen.GetVulnerabilitySummaryRequestObject) (gen.GetVulnerabilitySummaryResponseObject, error) {
	now := h.cfg.Now()
	rows, err := h.cfg.Store.VulnComponents(ctx, store.VulnViewOptions{At: now})
	if err != nil {
		return nil, err
	}
	sortUnits(rows)
	var out gen.GetVulnerabilitySummary200JSONResponse
	if out.Deferred, err = h.cfg.Store.CountDeferred(ctx, now); err != nil {
		return nil, err
	}
	cves, kev, urgent := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, r := range rows {
		for _, v := range r.VulnIDs {
			cves[v] = true
		}
		for _, v := range r.KEVVulnIDs {
			kev[v] = true
		}
		if len(r.HotVulnIDs) > 0 && r.Exposure.Listening+r.Exposure.Running > 0 {
			out.Urgent.Components++
			for _, v := range r.HotVulnIDs {
				urgent[v] = true
			}
		}
	}
	out.Urgent.Cves = len(urgent)
	out.Totals.Cves, out.Totals.Kev, out.Totals.Components = len(cves), len(kev), len(rows)
	if out.Totals.Assets, err = h.cfg.Store.CountFindingAssets(ctx, now); err != nil {
		return nil, err
	}
	out.ActionsTotal = len(rows)
	out.Actions = make([]gen.VulnComponent, 0, summaryActions)
	for _, r := range rows[:min(summaryActions, len(rows))] {
		out.Actions = append(out.Actions, componentUnitDTO(r))
	}
	srv, err := h.cfg.Store.GetActiveFeedServer(ctx)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return nil, err
	case srv.Revision != nil:
		out.Revision, out.CheckedAt = srv.Revision, srv.StatusCheckedAt
		c, err := h.cfg.Store.CountMatches(ctx, store.MatchEpoch{ServerID: srv.ID, Revision: *srv.Revision, Rules: deref(srv.RulesDigest)})
		if err != nil {
			return nil, err
		}
		out.Unsupported = c.Unsupported
	}
	return out, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
