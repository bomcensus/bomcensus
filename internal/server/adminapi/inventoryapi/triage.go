// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package inventoryapi

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/apierr"
	"github.com/bomcensus/bomcensus/internal/server/auth"
	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/internal/server/vulnsvc"
)

// viewOptions are the options of a list; asking for negligible ones by
// severity includes them.
func (h *Handlers) viewOptions(includeDeferred, includeNegligible *bool, sev *gen.Severity) store.VulnViewOptions {
	return store.VulnViewOptions{At: h.cfg.Now(), IncludeDeferred: includeDeferred != nil && *includeDeferred,
		IncludeNegligible: (includeNegligible != nil && *includeNegligible) || (sev != nil && *sev == gen.SeverityNegligible)}
}

func triageRuleDTO(r store.TriageRule, now time.Time) gen.TriageRule {
	return gen.TriageRule{
		Id: r.ID, VulnId: r.VulnID, Scope: gen.TriageScope{Kind: gen.TriageScopeKind(r.ScopeKind), Value: r.ScopeValue},
		Status: gen.TriageRuleStatus(r.Status), Justification: gen.TriageJustification(r.Justification), Note: optStr(r.Note),
		ExpiresAt: r.ExpiresAt, ExpiredAt: r.ExpiredAt, Active: r.Active(now), CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt,
		RevokedAt: r.RevokedAt, RevokedBy: optStr(r.RevokedBy),
	}
}

// findingTriageDTO is the rule deciding a finding, active or ended.
func findingTriageDTO(f store.OpenFinding, now time.Time) *gen.TriageRule {
	if f.Triage == nil {
		return nil
	}
	r := triageRuleDTO(f.Triage.Rule, now)
	r.Active = f.Triage.Active
	if r.Scope.Kind == gen.TriageScopeKindAsset && r.Scope.Value == f.AssetID {
		r.ScopeName = &f.AssetName
	}
	return &r
}

// rulesOf collects the distinct rules deciding a set of findings.
type rulesOf map[string]*gen.TriageRule

func (rs rulesOf) add(f store.OpenFinding) {
	if f.Triage == nil {
		return
	}
	if _, ok := rs[f.Triage.Rule.ID]; ok {
		return
	}
	r := findingTriageDTO(f, time.Time{})
	r.Active = f.Triage.Active
	rs[f.Triage.Rule.ID] = r
}

func (rs rulesOf) dto(time.Time) []gen.TriageRule {
	out := make([]gen.TriageRule, 0, len(rs))
	for _, r := range rs {
		out = append(out, *r)
	}
	slices.SortFunc(out, func(a, b gen.TriageRule) int { return b.CreatedAt.Compare(a.CreatedAt) })
	return out
}

func principal(ctx context.Context) string {
	p, _ := auth.FromContext(ctx)
	if p.Name != "" {
		return p.Name
	}
	return p.ID
}

// ── rules ───────────────────────────────────────────────────────────────

// ListTriageRules implements gen.StrictServerInterface.
func (h *Handlers) ListTriageRules(ctx context.Context, req gen.ListTriageRulesRequestObject) (gen.ListTriageRulesResponseObject, error) {
	now := h.cfg.Now()
	rows, err := h.cfg.Store.ListTriageRules(ctx, now, req.Params.IncludeRevoked != nil && *req.Params.IncludeRevoked)
	if err != nil {
		return nil, err
	}
	names := map[string]string{}
	out := gen.ListTriageRules200JSONResponse{Items: make([]gen.TriageRule, 0, len(rows)), Total: len(rows)}
	for _, r := range rows {
		d := triageRuleDTO(r.TriageRule, now)
		findings, assets := r.Findings, r.Assets
		d.Findings, d.Assets = &findings, &assets
		if r.ScopeKind == store.TriageScopeAsset {
			name, ok := names[r.ScopeValue]
			if !ok {
				if a, err := h.cfg.Store.GetAsset(ctx, r.ScopeValue); err == nil {
					name = a.Name
				}
				names[r.ScopeValue] = name
			}
			d.ScopeName = optStr(name)
		}
		out.Items = append(out.Items, d)
	}
	return out, nil
}

// CreateTriageRule implements gen.StrictServerInterface.
func (h *Handlers) CreateTriageRule(ctx context.Context, req gen.CreateTriageRuleRequestObject) (gen.CreateTriageRuleResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, apierr.Invalid("request body is required")
	}
	now := h.cfg.Now()
	r := store.TriageRule{
		VulnID: strings.TrimSpace(b.VulnId), ScopeKind: string(b.Scope.Kind), ScopeValue: strings.TrimSpace(b.Scope.Value),
		Status: store.TriageStatusNotAffected, Justification: string(b.Justification), Note: strings.TrimSpace(deref(b.Note)),
		ExpiresAt: b.ExpiresAt, CreatedBy: principal(ctx), CreatedAt: now,
	}
	if !slices.Contains(store.TriageJustifications, r.Justification) {
		return nil, apierr.Invalid("unknown justification %q", r.Justification)
	}
	if r.ExpiresAt != nil && !r.ExpiresAt.After(now) {
		return nil, apierr.Invalid("expiresAt must be in the future")
	}
	if _, err := h.cfg.Store.GetVulnMeta(ctx, r.VulnID); errors.Is(err, store.ErrNotFound) {
		return nil, apierr.Invalid("unknown vulnerability %q", r.VulnID)
	} else if err != nil {
		return nil, err
	}
	switch r.ScopeKind {
	case store.TriageScopePURL:
		like, err := vulnsvc.PURLLike(r.ScopeValue)
		if err != nil {
			return nil, apierr.Invalid("%s", err.Error())
		}
		r.ScopeValue, r.PURLLike = vulnsvc.PURLScope(r.ScopeValue), like
	case store.TriageScopeAsset:
		if _, err := h.cfg.Store.GetAsset(ctx, r.ScopeValue); errors.Is(err, store.ErrNotFound) {
			return nil, apierr.Invalid("unknown asset %q", r.ScopeValue)
		} else if err != nil {
			return nil, err
		}
	case store.TriageScopeGroup:
	default:
		return nil, apierr.Invalid("scope kind must be purl, asset or group")
	}
	created, err := h.cfg.Store.CreateTriageRule(ctx, r)
	if err != nil {
		return nil, err
	}
	h.logChange(ctx, "triage rule created", "rule", created.ID, "vulnerability", created.VulnID,
		"scope", created.ScopeKind+":"+created.ScopeValue, "justification", created.Justification, "expires", created.ExpiresAt)
	return gen.CreateTriageRule201JSONResponse(triageRuleDTO(created, now)), nil
}

// RevokeTriageRule implements gen.StrictServerInterface.
func (h *Handlers) RevokeTriageRule(ctx context.Context, req gen.RevokeTriageRuleRequestObject) (gen.RevokeTriageRuleResponseObject, error) {
	now := h.cfg.Now()
	r, err := h.cfg.Store.RevokeTriageRule(ctx, req.Id, principal(ctx), now)
	if errors.Is(err, store.ErrNotFound) {
		return nil, apierr.NotFound("triage rule")
	}
	if errors.Is(err, store.ErrInvalidState) {
		return nil, apierr.New(http.StatusConflict, apierr.CodeInvalidState, "the rule is already revoked")
	}
	if err != nil {
		return nil, err
	}
	h.logChange(ctx, "triage rule revoked", "rule", r.ID, "vulnerability", r.VulnID)
	return gen.RevokeTriageRule200JSONResponse(triageRuleDTO(r, now)), nil
}

// ListTriageEvents implements gen.StrictServerInterface.
func (h *Handlers) ListTriageEvents(ctx context.Context, req gen.ListTriageEventsRequestObject) (gen.ListTriageEventsResponseObject, error) {
	var after int64
	limit := 200
	if req.Params.After != nil {
		after = *req.Params.After
	}
	if req.Params.Limit != nil {
		limit = *req.Params.Limit
	}
	if after < 0 || limit < 1 || limit > 1000 {
		return nil, apierr.Invalid("after must be at least 0 and limit between 1 and 1000")
	}
	events, err := h.cfg.Store.ListTriageEvents(ctx, after, limit)
	if err != nil {
		return nil, err
	}
	now := h.cfg.Now()
	out := gen.ListTriageEvents200JSONResponse{Items: make([]gen.TriageEvent, 0, len(events))}
	for _, e := range events {
		out.Items = append(out.Items, gen.TriageEvent{Id: e.ID, Kind: gen.TriageEventKind(e.Kind), At: e.At, Actor: optStr(e.Actor),
			Findings: e.Findings, Rule: triageRuleDTO(e.Rule, now)})
	}
	return out, nil
}

// ── OpenVEX ─────────────────────────────────────────────────────────────

// openvexJustification maps CycloneDX justifications to OpenVEX ones.
var openvexJustification = map[string]string{
	"code_not_present":                "vulnerable_code_not_present",
	"code_not_reachable":              "vulnerable_code_not_in_execute_path",
	"requires_configuration":          "vulnerable_code_cannot_be_controlled_by_adversary",
	"requires_environment":            "vulnerable_code_cannot_be_controlled_by_adversary",
	"protected_at_runtime":            "inline_mitigations_already_exist",
	"protected_by_mitigating_control": "inline_mitigations_already_exist",
}

// ExportVex implements gen.StrictServerInterface. Each active rule is one
// not_affected statement; its products are the purls of the components
// whose open findings it decides, or its purl scope when it decides none.
func (h *Handlers) ExportVex(ctx context.Context, _ gen.ExportVexRequestObject) (gen.ExportVexResponseObject, error) {
	now := h.cfg.Now().UTC()
	rows, err := h.cfg.Store.ListTriageRules(ctx, now, false)
	if err != nil {
		return nil, err
	}
	statements := []map[string]any{}
	digest := sha256.New()
	for _, r := range rows {
		if !r.Active(now) {
			continue
		}
		fs, err := h.cfg.Store.OpenFindings(ctx, store.OpenFindingFilter{VulnID: r.VulnID, At: now})
		if err != nil {
			return nil, err
		}
		purls := map[string]bool{}
		for _, f := range fs {
			if f.Triage != nil && f.Triage.Rule.ID == r.ID && f.Component.PURL != "" {
				purls[f.Component.PURL] = true
			}
		}
		if len(purls) == 0 && r.ScopeKind == store.TriageScopePURL && !strings.HasSuffix(r.ScopeValue, "*") {
			purls[r.ScopeValue] = true
		}
		if len(purls) == 0 {
			continue
		}
		var products []map[string]any
		for _, p := range slices.Sorted(mapKeys(purls)) {
			products = append(products, map[string]any{"@id": p})
		}
		notes := fmt.Sprintf("scope %s:%s", r.ScopeKind, r.ScopeValue)
		if r.ExpiresAt != nil {
			notes += "; deferred until " + r.ExpiresAt.UTC().Format(time.RFC3339)
		}
		st := map[string]any{
			"vulnerability": map[string]any{"name": r.VulnID},
			"products":      products,
			"status":        "not_affected",
			"justification": openvexJustification[r.Justification],
			"timestamp":     r.CreatedAt.UTC().Format(time.RFC3339),
			"status_notes":  notes,
		}
		if r.Note != "" {
			st["impact_statement"] = r.Note
		}
		statements = append(statements, st)
		fmt.Fprintf(digest, "%s|%s|%s\n", r.ID, r.VulnID, strings.Join(slices.Sorted(mapKeys(purls)), ","))
	}
	return gen.ExportVex200JSONResponse{
		"@context":   "https://openvex.dev/ns/v0.2.0",
		"@id":        "urn:bomcensus:vex:" + hex.EncodeToString(digest.Sum(nil))[:32],
		"author":     "bomcensus",
		"timestamp":  now.Format(time.RFC3339),
		"version":    1,
		"statements": statements,
	}, nil
}

func mapKeys[K comparable, V any](m map[K]V) func(func(K) bool) {
	return func(yield func(K) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// ── processes ───────────────────────────────────────────────────────────

func processDTO(r store.VulnProcessRow) gen.VulnProcess {
	return gen.VulnProcess{
		Exe: r.Exe, Assets: r.Assets, Processes: r.Processes, Listening: r.Listening, Components: r.Components,
		Cves: len(r.VulnIDs), Kev: r.KEV, Score: r.MaxScore, Severity: topSeverity(r.Severity),
		SeverityCounts: severityCountsDTO(r.Severity),
	}
}

// ListVulnerableProcesses implements gen.StrictServerInterface.
func (h *Handlers) ListVulnerableProcesses(ctx context.Context, req gen.ListVulnerableProcessesRequestObject) (gen.ListVulnerableProcessesResponseObject, error) {
	prm := req.Params
	rows, err := h.cfg.Store.VulnProcesses(ctx, h.viewOptions(prm.IncludeDeferred, prm.IncludeNegligible, nil))
	if err != nil {
		return nil, err
	}
	rows = slices.DeleteFunc(rows, func(r store.VulnProcessRow) bool { return !textMatches(prm.Q, r.Exe) })
	slices.SortStableFunc(rows, func(a, b store.VulnProcessRow) int {
		if c := negligibleLast(negligibleOnly(a.Severity, len(a.VulnIDs)), negligibleOnly(b.Severity, len(b.VulnIDs))); c != 0 {
			return c
		}
		if (a.Listening > 0) != (b.Listening > 0) {
			if a.Listening > 0 {
				return -1
			}
			return 1
		}
		if c := cmpDesc(a.MaxScore, b.MaxScore); c != 0 {
			return c
		}
		if c := cmp.Compare(len(b.VulnIDs), len(a.VulnIDs)); c != 0 {
			return c
		}
		return cmp.Compare(a.Exe, b.Exe)
	})
	pg, err := pageSlice(rows, prm.Limit, prm.Offset)
	if err != nil {
		return nil, err
	}
	out := gen.ListVulnerableProcesses200JSONResponse{Items: make([]gen.VulnProcess, 0, len(pg)), Total: len(rows)}
	for _, r := range pg {
		out.Items = append(out.Items, processDTO(r))
	}
	return out, nil
}

// GetVulnerableProcess implements gen.StrictServerInterface.
func (h *Handlers) GetVulnerableProcess(ctx context.Context, req gen.GetVulnerableProcessRequestObject) (gen.GetVulnerableProcessResponseObject, error) {
	now := h.cfg.Now()
	fs, err := h.cfg.Store.OpenFindings(ctx, store.OpenFindingFilter{Exe: req.Params.Exe, At: now})
	if err != nil {
		return nil, err
	}
	fs = slices.DeleteFunc(fs, func(f store.OpenFinding) bool { return f.Triage != nil && f.Triage.Active })
	if len(fs) == 0 {
		return nil, apierr.NotFound("vulnerable process")
	}
	// Negligible findings are left out as the list leaves them out, unless
	// the executable has no others.
	o := store.VulnViewOptions{At: now}
	if shown := slices.DeleteFunc(slices.Clone(fs), negligibleFinding); len(shown) > 0 {
		fs = shown
	} else {
		o.IncludeNegligible = true
	}
	// The process row, as the list computes it.
	var row store.VulnProcessRow
	rows, err := h.cfg.Store.VulnProcesses(ctx, o)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if r.Exe == req.Params.Exe {
			row = r
		}
	}
	row.Exe = req.Params.Exe
	byComp := map[string][]store.OpenFinding{}
	var order []string
	for _, f := range fs {
		if _, ok := byComp[f.Component.ID]; !ok {
			order = append(order, f.Component.ID)
		}
		byComp[f.Component.ID] = append(byComp[f.Component.ID], f)
	}
	units := make([]store.VulnComponentRow, 0, len(order))
	for _, id := range order {
		units = append(units, unitOf(byComp[id][0].Component, byComp[id]))
	}
	sortUnits(units)
	out := gen.GetVulnerableProcess200JSONResponse{Process: processDTO(row), Locations: locationsOf(fs)}
	for _, u := range units {
		out.Components = append(out.Components, componentUnitDTO(u))
	}
	return out, nil
}

// ── images ──────────────────────────────────────────────────────────────

func imageDTO(r store.VulnImageRow) gen.VulnImage {
	tags := r.Tags
	if tags == nil {
		tags = []string{}
	}
	return gen.VulnImage{
		Digest: r.Digest, Tags: tags, Components: r.Components, Cves: len(r.VulnIDs), Kev: r.KEV,
		Score: r.MaxScore, Severity: topSeverity(r.Severity), Epss: r.MaxEPSS,
		SeverityCounts: severityCountsDTO(r.Severity),
		Containers:     r.Containers, Assets: r.Assets,
	}
}

// ListVulnerableImages implements gen.StrictServerInterface.
func (h *Handlers) ListVulnerableImages(ctx context.Context, req gen.ListVulnerableImagesRequestObject) (gen.ListVulnerableImagesResponseObject, error) {
	prm := req.Params
	rows, err := h.cfg.Store.VulnImages(ctx, h.viewOptions(prm.IncludeDeferred, prm.IncludeNegligible, nil))
	if err != nil {
		return nil, err
	}
	rows = slices.DeleteFunc(rows, func(r store.VulnImageRow) bool { return !textMatches(prm.Q, append([]string{r.Digest}, r.Tags...)...) })
	slices.SortStableFunc(rows, func(a, b store.VulnImageRow) int {
		if c := negligibleLast(negligibleOnly(a.Severity, len(a.VulnIDs)), negligibleOnly(b.Severity, len(b.VulnIDs))); c != 0 {
			return c
		}
		if (a.Containers > 0) != (b.Containers > 0) {
			if a.Containers > 0 {
				return -1
			}
			return 1
		}
		return cmpRank(0, 0, a.KEV > 0, b.KEV > 0, a.MaxEPSS, b.MaxEPSS, a.MaxScore, b.MaxScore, a.Digest, b.Digest)
	})
	pg, err := pageSlice(rows, prm.Limit, prm.Offset)
	if err != nil {
		return nil, err
	}
	out := gen.ListVulnerableImages200JSONResponse{Items: make([]gen.VulnImage, 0, len(pg)), Total: len(rows)}
	for _, r := range pg {
		out.Items = append(out.Items, imageDTO(r))
	}
	return out, nil
}

// GetVulnerableImage implements gen.StrictServerInterface.
func (h *Handlers) GetVulnerableImage(ctx context.Context, req gen.GetVulnerableImageRequestObject) (gen.GetVulnerableImageResponseObject, error) {
	now := h.cfg.Now()
	vs, err := h.cfg.Store.ImageVulns(ctx, req.Digest, now)
	if err != nil {
		return nil, err
	}
	if len(vs) == 0 {
		return nil, apierr.NotFound("vulnerable image")
	}
	rows, err := h.cfg.Store.VulnImages(ctx, store.VulnViewOptions{At: now, IncludeDeferred: true, IncludeNegligible: true})
	if err != nil {
		return nil, err
	}
	var img gen.VulnImage
	for _, r := range rows {
		if r.Digest == req.Digest {
			img = imageDTO(r)
		}
	}
	img.Digest = req.Digest
	if img.Tags == nil {
		img.Tags = []string{}
	}
	type comp struct {
		dto   gen.VulnImageComponent
		fixes []string
	}
	byComp := map[string]*comp{}
	var order []string
	for _, v := range vs {
		c := byComp[v.Component.ID]
		if c == nil {
			locs := v.Locations
			if locs == nil {
				locs = []string{}
			}
			c = &comp{dto: gen.VulnImageComponent{ComponentId: v.Component.ID, Name: v.Component.Name, Version: v.Component.Version,
				Type: gen.ComponentType(v.Component.Type), Purl: optStr(v.Component.PURL), Locations: locs}}
			byComp[v.Component.ID] = c
			order = append(order, v.Component.ID)
		}
		if v.Match.FixedVersion != "" && !slices.Contains(c.fixes, v.Match.FixedVersion) {
			c.fixes = append(c.fixes, v.Match.FixedVersion)
		}
		c.dto.Cves = append(c.dto.Cves, gen.VulnImageCve{VulnId: v.Meta.ID, Summary: optStr(v.Meta.Summary),
			Severity: severityPtr(store.MatchSeverity(v.Match, v.Meta)), Score: v.Meta.MaxScore, Kev: v.Meta.KEV != nil, Epss: v.Meta.EPSS,
			FixState: gen.FixState(v.Match.FixState), FixedVersion: optStr(v.Match.FixedVersion), Deferred: v.Deferred})
	}
	out := gen.GetVulnerableImage200JSONResponse{Image: img}
	for _, id := range order {
		c := byComp[id]
		slices.Sort(c.fixes)
		c.dto.FixedVersions = c.fixes
		if c.dto.FixedVersions == nil {
			c.dto.FixedVersions = []string{}
		}
		if v := vulnsvc.MaxVersion(string(c.dto.Type), c.fixes); v != "" {
			c.dto.FixedVersion = &v
		}
		slices.SortStableFunc(c.dto.Cves, func(a, b gen.VulnImageCve) int {
			if c := negligibleLast(isNegligible(a.Severity), isNegligible(b.Severity)); c != 0 {
				return c
			}
			return cmpRank(0, 0, a.Kev, b.Kev, a.Epss, b.Epss, a.Score, b.Score, a.VulnId, b.VulnId)
		})
		out.Components = append(out.Components, c.dto)
	}
	// Cves are sorted, negligible last: the first one ranks the component.
	slices.SortStableFunc(out.Components, func(a, b gen.VulnImageComponent) int {
		if c := negligibleLast(len(a.Cves) > 0 && isNegligible(a.Cves[0].Severity), len(b.Cves) > 0 && isNegligible(b.Cves[0].Severity)); c != 0 {
			return c
		}
		var sa, sb *float64
		if len(a.Cves) > 0 {
			sa = a.Cves[0].Score
		}
		if len(b.Cves) > 0 {
			sb = b.Cves[0].Score
		}
		if c := cmpDesc(sa, sb); c != 0 {
			return c
		}
		return cmp.Compare(len(b.Cves), len(a.Cves))
	})
	return out, nil
}
