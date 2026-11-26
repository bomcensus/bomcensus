// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package inventoryapi

import (
	"net/http"
	"strings"
	"testing"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

func TestIntegrityAPI(t *testing.T) {
	f := seed(t)
	ctx := f.ctx
	page := "/usr/share/nginx/html/index.html"
	sha := strings.Repeat("a", 64)
	for _, a := range []string{f.web, f.db1} {
		must(t, f.db.RecordIntegrityChunk(ctx, store.IntegrityChunk{AssetID: a, PassKey: "p", At: t0, Done: true,
			Coverage: "full", Checked: 10, Findings: []store.IntegrityObservation{{Path: page, Status: "modified",
				PkgType: "deb", Package: "nginx", Version: "1.24", Algo: "md5", Expected: strings.Repeat("e", 32),
				Actual: strings.Repeat("b", 32), ActualSHA256: sha, Size: 5}}}))
	}
	files := func(includeAllowed bool) []gen.IntegrityGroup {
		t.Helper()
		r, err := f.h.ListIntegrityFiles(ctx, gen.ListIntegrityFilesRequestObject{Params: gen.ListIntegrityFilesParams{IncludeAllowed: &includeAllowed}})
		must(t, err)
		return r.(gen.ListIntegrityFiles200JSONResponse).Items
	}
	gs := files(false)
	if len(gs) != 1 || gs[0].Assets != 2 || *gs[0].ActualSha256 != sha || gs[0].Algo != "md5" {
		t.Fatalf("files %+v", gs)
	}
	for _, srt := range []gen.ListIntegrityFilesParamsSort{"path", "-package", "lastSeen", "-firstSeen", "assets"} {
		r, err := f.h.ListIntegrityFiles(ctx, gen.ListIntegrityFilesRequestObject{Params: gen.ListIntegrityFilesParams{Sort: &srt}})
		must(t, err)
		if l := r.(gen.ListIntegrityFiles200JSONResponse); l.Total != 1 {
			t.Fatalf("sort %s: %+v", srt, l)
		}
	}
	_, err := f.h.ListIntegrityFiles(ctx, gen.ListIntegrityFilesRequestObject{Params: gen.ListIntegrityFilesParams{
		Sort: ptr(gen.ListIntegrityFilesParamsSort("status"))}})
	wantStatus(t, "unknown integrity sort", err, http.StatusBadRequest)
	nodes, err := f.h.ListIntegrityFileNodes(ctx, gen.ListIntegrityFileNodesRequestObject{Params: gen.ListIntegrityFileNodesParams{
		Path: page, Status: "modified", Sha256: &sha}})
	must(t, err)
	if n := nodes.(gen.ListIntegrityFileNodes200JSONResponse); n.Total != 2 || *n.Items[0].Size != 5 {
		t.Errorf("nodes %+v", n)
	}

	// Validation.
	for name, b := range map[string]gen.IntegrityAllowRuleCreate{
		"no note":          {Scope: "fleet", Path: page, Status: "modified", ActualSha256: &sha, Note: " "},
		"asset without id": {Scope: "asset", Path: page, Status: "modified", ActualSha256: &sha, Note: "n"},
		"fleet with ids":   {Scope: "fleet", AssetIds: &[]string{f.web}, Path: page, Status: "modified", ActualSha256: &sha, Note: "n"},
		"no sha":           {Scope: "fleet", Path: page, Status: "modified", Note: "n"},
	} {
		_, err := f.h.CreateIntegrityAllowRules(ctx, gen.CreateIntegrityAllowRulesRequestObject{Body: &b})
		wantStatus(t, name, err, http.StatusBadRequest)
	}
	_, err = f.h.CreateIntegrityAllowRules(ctx, gen.CreateIntegrityAllowRulesRequestObject{Body: &gen.IntegrityAllowRuleCreate{
		Scope: "asset", AssetIds: &[]string{"00000000-0000-0000-0000-000000000000"}, Path: page, Status: "modified",
		ActualSha256: &sha, Note: "n"}})
	wantStatus(t, "unknown asset", err, http.StatusNotFound)

	// Allow on one node, then on all.
	r, err := f.h.CreateIntegrityAllowRules(ctx, gen.CreateIntegrityAllowRulesRequestObject{Body: &gen.IntegrityAllowRuleCreate{
		Scope: "asset", AssetIds: &[]string{f.web, f.web}, Path: page, Status: "modified", ActualSha256: ptr(strings.ToUpper(sha)), Note: "manual"}})
	must(t, err)
	if c := r.(gen.CreateIntegrityAllowRules201JSONResponse); c.Total != 1 || c.Items[0].CreatedBy != "admin" || *c.Items[0].ActualSha256 != sha {
		t.Errorf("created %+v", c)
	}
	if gs := files(false); len(gs) != 1 || gs[0].Assets != 1 {
		t.Errorf("after the node rule: %+v", gs)
	}
	r, err = f.h.CreateIntegrityAllowRules(ctx, gen.CreateIntegrityAllowRulesRequestObject{Body: &gen.IntegrityAllowRuleCreate{
		Scope: "fleet", Path: page, Status: "modified", ActualSha256: &sha, Note: "deployed"}})
	must(t, err)
	fleet := r.(gen.CreateIntegrityAllowRules201JSONResponse).Items[0]
	if gs := files(false); len(gs) != 0 {
		t.Errorf("after the fleet rule: %+v", gs)
	}
	if gs := files(true); len(gs) != 1 || gs[0].AllowedAssets != 2 {
		t.Errorf("with allowed: %+v", gs)
	}
	s, err := f.h.GetIntegritySummary(ctx, gen.GetIntegritySummaryRequestObject{})
	must(t, err)
	if sum := s.(gen.GetIntegritySummary200JSONResponse); sum.Groups != 0 || sum.Rules != 2 || sum.Tracked != 2 {
		t.Errorf("summary %+v", sum)
	}

	// The asset view shows allowed findings on request.
	ai, err := f.h.GetAssetIntegrity(ctx, gen.GetAssetIntegrityRequestObject{Id: f.web})
	must(t, err)
	if a := ai.(gen.GetAssetIntegrity200JSONResponse); len(a.Findings) != 0 || a.LastCompletedPass == nil || a.LastCompletedPass.Checked != 10 {
		t.Errorf("asset view %+v", a)
	}
	yes := true
	ai, err = f.h.GetAssetIntegrity(ctx, gen.GetAssetIntegrityRequestObject{Id: f.web, Params: gen.GetAssetIntegrityParams{IncludeAllowed: &yes}})
	must(t, err)
	if a := ai.(gen.GetAssetIntegrity200JSONResponse); len(a.Findings) != 1 || a.Findings[0].AllowedBy == nil {
		t.Errorf("asset view with allowed %+v", a)
	}

	// Revoking the fleet rule shows db-1 again.
	_, err = f.h.RevokeIntegrityAllowRule(ctx, gen.RevokeIntegrityAllowRuleRequestObject{Id: fleet.Id})
	must(t, err)
	_, err = f.h.RevokeIntegrityAllowRule(ctx, gen.RevokeIntegrityAllowRuleRequestObject{Id: fleet.Id})
	wantStatus(t, "second revoke", err, http.StatusNotFound)
	if gs := files(false); len(gs) != 1 || gs[0].Assets != 1 {
		t.Errorf("after revoking: %+v", gs)
	}
	rules, err := f.h.ListIntegrityAllowRules(ctx, gen.ListIntegrityAllowRulesRequestObject{})
	must(t, err)
	if l := rules.(gen.ListIntegrityAllowRules200JSONResponse); l.Total != 1 || l.Items[0].AssetName == nil || *l.Items[0].AssetName != "web-1" {
		t.Errorf("rules %+v", l)
	}
}

func TestIntegrityPolicyAPI(t *testing.T) {
	f := seed(t)
	p, err := f.h.GetIntegrityPolicy(f.ctx, gen.GetIntegrityPolicyRequestObject{})
	must(t, err)
	got := gen.IntegrityPolicy(p.(gen.GetIntegrityPolicy200JSONResponse))
	if !got.Agents || !got.Ssh || got.WindowStart != "02:00" || got.WindowEnd != "05:00" || got.ExcludePaths == nil {
		t.Fatalf("default policy %+v", got)
	}
	got.Ssh, got.WindowStart, got.ExcludePaths = false, "23:00", []string{"/opt/app/**", " ", "/opt/app/**"}
	put, err := f.h.PutIntegrityPolicy(f.ctx, gen.PutIntegrityPolicyRequestObject{Body: &got})
	must(t, err)
	saved := gen.IntegrityPolicy(put.(gen.PutIntegrityPolicy200JSONResponse))
	if saved.Ssh || saved.WindowStart != "23:00" || len(saved.ExcludePaths) != 1 {
		t.Errorf("saved %+v", saved)
	}
	bad := saved
	bad.MaxReadMbps = 0
	_, err = f.h.PutIntegrityPolicy(f.ctx, gen.PutIntegrityPolicyRequestObject{Body: &bad})
	wantStatus(t, "bad policy", err, http.StatusBadRequest)
}
