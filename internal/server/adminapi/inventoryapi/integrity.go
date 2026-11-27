// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package inventoryapi

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/apierr"
	"github.com/bomcensus/bomcensus/internal/server/integritysvc"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// maxAssetIntegrityFindings bounds the findings of the asset view.
const maxAssetIntegrityFindings = 1000

func integrityFindingDTO(f store.IntegrityFinding) gen.IntegrityFinding {
	d := gen.IntegrityFinding{
		Id: f.ID, AssetId: f.AssetID, AssetName: f.AssetName, Collector: f.Collector, Path: f.Path,
		Status: gen.IntegrityStatus(f.Status), PkgType: f.PkgType, Package: f.Package, Version: f.Version,
		Arch: optStr(f.Arch), Algo: f.Algo, Expected: f.Expected, Actual: optStr(f.Actual),
		ActualSha256: optStr(f.ActualSHA256), Mtime: f.Mtime, Ctime: f.Ctime,
		FirstSeen: f.FirstSeen, LastSeen: f.LastSeen, AllowedBy: optStr(f.AllowedBy),
	}
	if f.Size > 0 {
		size := f.Size
		d.Size = &size
	}
	return d
}

func integrityPassDTO(p store.IntegrityPass) *gen.IntegrityPass {
	return &gen.IntegrityPass{
		StartedAt: p.StartedAt, LastChunkAt: p.LastChunkAt, CompletedAt: p.CompletedAt, Checked: p.Checked,
		Excluded: p.Excluded, Unreadable: p.Unreadable, Coverage: gen.IntegrityPassCoverage(p.Coverage),
		Reason: optStr(p.Reason),
	}
}

func integrityRuleDTO(r store.IntegrityAllowRule) gen.IntegrityAllowRule {
	return gen.IntegrityAllowRule{
		Id: r.ID, Scope: gen.IntegrityAllowRuleScope(r.Scope), AssetId: optStr(r.AssetID), AssetName: optStr(r.AssetName),
		Path: r.Path, Status: gen.IntegrityStatus(r.Status), ActualSha256: optStr(r.ActualSHA256), Note: r.Note,
		CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, RevokedBy: optStr(r.RevokedBy), RevokedAt: r.RevokedAt,
		Hidden: r.Hidden, ScopeId: r.ScopeID,
	}
}

func integrityStatus(s *gen.IntegrityStatus) (string, error) {
	if s == nil {
		return "", nil
	}
	if !s.Valid() {
		return "", apierr.Invalid("unknown status %q", *s)
	}
	return string(*s), nil
}

func (h *Handlers) integrityPolicy(ctx context.Context) (integritysvc.Policy, error) {
	return integritysvc.Load(ctx, h.cfg.Store)
}

// GetIntegritySummary implements gen.StrictServerInterface.
func (h *Handlers) GetIntegritySummary(ctx context.Context, _ gen.GetIntegritySummaryRequestObject) (gen.GetIntegritySummaryResponseObject, error) {
	pol, err := h.integrityPolicy(ctx)
	if err != nil {
		return nil, err
	}
	after := h.cfg.Now().Add(-2 * time.Duration(pol.IntervalDays) * 24 * time.Hour)
	s, err := h.cfg.Store.IntegritySummary(ctx, after)
	if err != nil {
		return nil, err
	}
	return gen.GetIntegritySummary200JSONResponse{Groups: s.Groups, Assets: s.Assets, Rules: s.Rules,
		Tracked: s.Tracked, Completed: s.Completed}, nil
}

// ListIntegrityFiles implements gen.StrictServerInterface.
func (h *Handlers) ListIntegrityFiles(ctx context.Context, req gen.ListIntegrityFilesRequestObject) (gen.ListIntegrityFilesResponseObject, error) {
	p := req.Params
	pg, err := page(p.Limit, p.Offset)
	if err != nil {
		return nil, err
	}
	status, err := integrityStatus(p.Status)
	if err != nil {
		return nil, err
	}
	f := store.IntegrityFilter{Status: status, IncludeAllowed: p.IncludeAllowed != nil && *p.IncludeAllowed}
	if p.AssetId != nil {
		f.AssetID = *p.AssetId
	}
	if p.Q != nil {
		f.Q = strings.TrimSpace(*p.Q)
	}
	if f.Sort, err = sortKey(p.Sort, map[string]string{
		"assets": "assets", "path": "path", "package": "package", "firstSeen": "first_seen", "lastSeen": "last_seen",
	}); err != nil {
		return nil, err
	}
	gs, total, err := h.cfg.Store.ListIntegrityGroups(ctx, f, pg)
	if err != nil {
		return nil, err
	}
	out := gen.ListIntegrityFiles200JSONResponse{Items: make([]gen.IntegrityGroup, 0, len(gs)), Total: total}
	for _, g := range gs {
		out.Items = append(out.Items, gen.IntegrityGroup{
			Path: g.Path, Status: gen.IntegrityStatus(g.Status), ActualSha256: optStr(g.ActualSHA256),
			PkgType: g.PkgType, Package: g.Package, Version: g.Version, Algo: g.Algo, Expected: g.Expected,
			Actual: optStr(g.Actual), Assets: g.Assets, AllowedAssets: g.AllowedAssets,
			FirstSeen: g.FirstSeen, LastSeen: g.LastSeen,
		})
	}
	return out, nil
}

// ListIntegrityFileNodes implements gen.StrictServerInterface.
func (h *Handlers) ListIntegrityFileNodes(ctx context.Context, req gen.ListIntegrityFileNodesRequestObject) (gen.ListIntegrityFileNodesResponseObject, error) {
	p := req.Params
	pg, err := page(p.Limit, p.Offset)
	if err != nil {
		return nil, err
	}
	if !p.Status.Valid() {
		return nil, apierr.Invalid("unknown status %q", p.Status)
	}
	if !strings.HasPrefix(p.Path, "/") {
		return nil, apierr.Invalid("path must be absolute")
	}
	sha := ""
	if p.Sha256 != nil {
		sha = strings.ToLower(*p.Sha256)
	}
	f := store.IntegrityFilter{Status: string(p.Status), Path: p.Path, SHA256: &sha,
		IncludeAllowed: p.IncludeAllowed != nil && *p.IncludeAllowed}
	fs, total, err := h.cfg.Store.ListIntegrityFindings(ctx, f, pg)
	if err != nil {
		return nil, err
	}
	out := gen.ListIntegrityFileNodes200JSONResponse{Items: make([]gen.IntegrityFinding, 0, len(fs)), Total: total}
	for _, x := range fs {
		out.Items = append(out.Items, integrityFindingDTO(x))
	}
	return out, nil
}

// GetAssetIntegrity implements gen.StrictServerInterface.
func (h *Handlers) GetAssetIntegrity(ctx context.Context, req gen.GetAssetIntegrityRequestObject) (gen.GetAssetIntegrityResponseObject, error) {
	a, err := h.cfg.Store.GetAsset(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	pol, err := h.integrityPolicy(ctx)
	if err != nil {
		return nil, err
	}
	out := gen.GetAssetIntegrity200JSONResponse{Findings: []gen.IntegrityFinding{}}
	setMode := func(mode string, def bool) {
		m := gen.IntegrityMode(mode)
		out.Mode = &m
		out.Enabled = integritysvc.Enabled(mode, def)
	}
	switch {
	case a.AgentID != "":
		if ag, err := h.cfg.Agents.GetAgent(ctx, a.AgentID); err == nil && ag.Kind == store.AgentKindAgent {
			setMode(ag.Integrity, pol.Agents)
		} else if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	case a.ScanTargetID != "":
		if t, err := h.cfg.Store.GetScanTarget(ctx, a.ScanTargetID); err == nil {
			setMode(t.Integrity, pol.SSH)
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}
	if p, err := h.cfg.Store.LastIntegrityPass(ctx, a.ID); err == nil {
		out.LastPass = integrityPassDTO(p)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if p, err := h.cfg.Store.LastCompletedIntegrityPass(ctx, a.ID); err == nil {
		out.LastCompletedPass = integrityPassDTO(p)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	f := store.IntegrityFilter{AssetID: a.ID, IncludeAllowed: req.Params.IncludeAllowed != nil && *req.Params.IncludeAllowed}
	fs, _, err := h.cfg.Store.ListIntegrityFindings(ctx, f, store.Page{Limit: maxAssetIntegrityFindings})
	if err != nil {
		return nil, err
	}
	for _, x := range fs {
		out.Findings = append(out.Findings, integrityFindingDTO(x))
	}
	return out, nil
}

// ListIntegrityAllowRules implements gen.StrictServerInterface.
func (h *Handlers) ListIntegrityAllowRules(ctx context.Context, req gen.ListIntegrityAllowRulesRequestObject) (gen.ListIntegrityAllowRulesResponseObject, error) {
	pg, err := page(req.Params.Limit, req.Params.Offset)
	if err != nil {
		return nil, err
	}
	rs, total, err := h.cfg.Store.ListIntegrityAllowRules(ctx, req.Params.IncludeRevoked != nil && *req.Params.IncludeRevoked, pg)
	if err != nil {
		return nil, err
	}
	out := gen.ListIntegrityAllowRules200JSONResponse{Items: make([]gen.IntegrityAllowRule, 0, len(rs)), Total: total}
	for _, r := range rs {
		out.Items = append(out.Items, integrityRuleDTO(r))
	}
	return out, nil
}

// CreateIntegrityAllowRules implements gen.StrictServerInterface.
func (h *Handlers) CreateIntegrityAllowRules(ctx context.Context, req gen.CreateIntegrityAllowRulesRequestObject) (gen.CreateIntegrityAllowRulesResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, apierr.Invalid("request body is required")
	}
	if !b.Scope.Valid() || !b.Status.Valid() {
		return nil, apierr.Invalid("unknown scope or status")
	}
	note := strings.TrimSpace(b.Note)
	if note == "" {
		return nil, apierr.Invalid("a note is required")
	}
	sha := ""
	if b.ActualSha256 != nil {
		sha = strings.ToLower(strings.TrimSpace(*b.ActualSha256))
	}
	base := store.IntegrityAllowRule{Scope: string(b.Scope), Path: b.Path, Status: string(b.Status),
		ActualSHA256: sha, Note: note, CreatedBy: principal(ctx), CreatedAt: h.cfg.Now()}
	var rules []store.IntegrityAllowRule
	switch b.Scope {
	case gen.IntegrityAllowRuleScopeFleet:
		if b.AssetIds != nil && len(*b.AssetIds) > 0 {
			return nil, apierr.Invalid("assetIds apply to scope asset only")
		}
		var err error
		if base.ScopeID, err = newScopeID(ctx, b.ScopeId); err != nil {
			return nil, err
		}
		rules = append(rules, base)
	case gen.IntegrityAllowRuleScopeAsset:
		if b.AssetIds == nil || len(*b.AssetIds) == 0 {
			return nil, apierr.Invalid("scope asset needs assetIds")
		}
		// Asset rules have the scope of their asset, which the store sets.
		base.ScopeID = deref(b.ScopeId)
		ids := slices.Compact(slices.Sorted(slices.Values(*b.AssetIds)))
		for _, id := range ids {
			if _, err := h.cfg.Store.GetAsset(ctx, id); err != nil {
				return nil, err
			}
			r := base
			r.AssetID = id
			rules = append(rules, r)
		}
	}
	out := gen.CreateIntegrityAllowRules201JSONResponse{Items: make([]gen.IntegrityAllowRule, 0, len(rules))}
	for _, r := range rules {
		created, err := h.cfg.Store.CreateIntegrityAllowRule(ctx, r)
		if err != nil {
			return nil, err
		}
		h.cfg.Logger.Info("integrity allow rule created", "rule", created.ID, "scope", created.Scope,
			"asset", created.AssetID, "path", created.Path, "sha256", created.ActualSHA256, "by", created.CreatedBy)
		out.Items = append(out.Items, integrityRuleDTO(created))
	}
	out.Total = len(out.Items)
	return out, nil
}

// RevokeIntegrityAllowRule implements gen.StrictServerInterface.
func (h *Handlers) RevokeIntegrityAllowRule(ctx context.Context, req gen.RevokeIntegrityAllowRuleRequestObject) (gen.RevokeIntegrityAllowRuleResponseObject, error) {
	by := principal(ctx)
	if err := h.cfg.Store.RevokeIntegrityAllowRule(ctx, req.Id, by, h.cfg.Now()); err != nil {
		return nil, err
	}
	h.cfg.Logger.Info("integrity allow rule revoked", "rule", req.Id, "by", by)
	return gen.RevokeIntegrityAllowRule204Response{}, nil
}

func integrityPolicyDTO(p integritysvc.Policy) gen.IntegrityPolicy {
	return gen.IntegrityPolicy{Agents: p.Agents, Ssh: p.SSH, WindowStart: p.WindowStart, WindowEnd: p.WindowEnd,
		IntervalDays: p.IntervalDays, MaxReadMbps: p.MaxReadMBps, FullRehashDays: p.FullRehashDays,
		ExcludePaths: slices.Clone(p.ExcludePaths)}
}

// GetIntegrityPolicy implements gen.StrictServerInterface.
func (h *Handlers) GetIntegrityPolicy(ctx context.Context, _ gen.GetIntegrityPolicyRequestObject) (gen.GetIntegrityPolicyResponseObject, error) {
	p, err := h.integrityPolicy(ctx)
	if err != nil {
		return nil, err
	}
	return gen.GetIntegrityPolicy200JSONResponse(integrityPolicyDTO(p)), nil
}

// PutIntegrityPolicy implements gen.StrictServerInterface.
func (h *Handlers) PutIntegrityPolicy(ctx context.Context, req gen.PutIntegrityPolicyRequestObject) (gen.PutIntegrityPolicyResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, apierr.Invalid("request body is required")
	}
	p := integritysvc.Policy{Agents: b.Agents, SSH: b.Ssh, WindowStart: b.WindowStart, WindowEnd: b.WindowEnd,
		IntervalDays: b.IntervalDays, MaxReadMBps: b.MaxReadMbps, FullRehashDays: b.FullRehashDays,
		ExcludePaths: b.ExcludePaths}
	if err := p.Normalize().Validate(); err != nil {
		return nil, apierr.Invalid("%s", err.Error())
	}
	saved, err := integritysvc.Save(ctx, h.cfg.Store, p)
	if err != nil {
		return nil, err
	}
	h.cfg.Logger.Info("integrity policy changed", "by", principal(ctx), "agents", saved.Agents, "ssh", saved.SSH,
		"window", saved.WindowStart+"-"+saved.WindowEnd)
	return gen.PutIntegrityPolicy200JSONResponse(integrityPolicyDTO(saved)), nil
}
