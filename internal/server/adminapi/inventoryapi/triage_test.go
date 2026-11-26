// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package inventoryapi

import (
	"net/http"
	"testing"
	"time"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/vulnsvc"
)

func TestTriage(t *testing.T) {
	f, ids := seedVulns(t)
	ctx := f.ctx
	yes := true
	create := func(b gen.TriageRuleCreate) gen.TriageRule {
		t.Helper()
		r, err := f.h.CreateTriageRule(ctx, gen.CreateTriageRuleRequestObject{Body: &b})
		must(t, err)
		return gen.TriageRule(r.(gen.CreateTriageRule201JSONResponse))
	}
	summary := func() gen.VulnSummary {
		t.Helper()
		s, err := f.h.GetVulnerabilitySummary(ctx, gen.GetVulnerabilitySummaryRequestObject{})
		must(t, err)
		return gen.VulnSummary(s.(gen.GetVulnerabilitySummary200JSONResponse))
	}
	cveAssets := func(id string) int {
		t.Helper()
		l, err := f.h.ListVulnerabilities(ctx, gen.ListVulnerabilitiesRequestObject{})
		must(t, err)
		for _, v := range l.(gen.ListVulnerabilities200JSONResponse).Items {
			if v.VulnId == id {
				return v.Assets
			}
		}
		return 0
	}

	// Validation.
	for _, b := range []gen.TriageRuleCreate{
		{VulnId: "CVE-NONE", Scope: gen.TriageScope{Kind: "purl", Value: "pkg:deb/ubuntu/nginx@1.27.0"}, Justification: "code_not_present"},
		{VulnId: "CVE-C", Scope: gen.TriageScope{Kind: "purl", Value: "nginx"}, Justification: "code_not_present"},
		{VulnId: "CVE-C", Scope: gen.TriageScope{Kind: "asset", Value: "00000000-0000-0000-0000-000000000000"}, Justification: "code_not_present"},
		{VulnId: "CVE-C", Scope: gen.TriageScope{Kind: "group", Value: "prod"}, Justification: "nope"},
		{VulnId: "CVE-C", Scope: gen.TriageScope{Kind: "group", Value: "prod"}, Justification: "code_not_present", ExpiresAt: &t0},
	} {
		_, err := f.h.CreateTriageRule(ctx, gen.CreateTriageRuleRequestObject{Body: &b})
		wantStatus(t, "invalid rule "+b.VulnId, err, http.StatusBadRequest)
	}

	// A permanent rule on nginx's version defers CVE-C everywhere.
	before := summary()
	note := "the http2 module is not built"
	purlRule := create(gen.TriageRuleCreate{VulnId: "CVE-C", Justification: "code_not_present", Note: &note,
		Scope: gen.TriageScope{Kind: "purl", Value: "pkg:deb/ubuntu/nginx@1.27.0?arch=amd64"}})
	if purlRule.Scope.Value != "pkg:deb/ubuntu/nginx@1.27.0" || !purlRule.Active || purlRule.ExpiresAt != nil || purlRule.CreatedBy != "admin" {
		t.Fatalf("rule %+v", purlRule)
	}
	after := summary()
	if after.Totals.Cves != before.Totals.Cves-1 || after.Deferred != 1 || after.Urgent.Components != 0 {
		t.Fatalf("summary before %+v after %+v", before, after)
	}
	list, _ := f.h.ListVulnerableComponents(ctx, gen.ListVulnerableComponentsRequestObject{})
	if u := list.(gen.ListVulnerableComponents200JSONResponse); u.Total != 1 || u.Items[0].Name != "openssl" {
		t.Fatalf("components without deferred %+v", u)
	}
	list, _ = f.h.ListVulnerableComponents(ctx, gen.ListVulnerableComponentsRequestObject{Params: gen.ListVulnerableComponentsParams{IncludeDeferred: &yes}})
	if u := list.(gen.ListVulnerableComponents200JSONResponse); u.Total != 2 || u.Items[0].Name != "nginx" || *u.Items[0].Deferred != 1 {
		t.Fatalf("components with deferred %+v", u)
	}
	cd, err := f.h.GetVulnerability(ctx, gen.GetVulnerabilityRequestObject{VulnId: "CVE-C"})
	must(t, err)
	if c := cd.(gen.GetVulnerability200JSONResponse).Components[0]; *c.Deferred != 1 || len(*c.Rules) != 1 || !(*c.Rules)[0].Active {
		t.Fatalf("CVE-C component %+v", c)
	}
	av, _ := f.h.ListAssetVulnerabilities(ctx, gen.ListAssetVulnerabilitiesRequestObject{Id: f.web})
	for _, v := range av.(gen.ListAssetVulnerabilities200JSONResponse).Items {
		if (v.VulnId == "CVE-C") != (v.Triage != nil) {
			t.Fatalf("asset finding %s triage %+v", v.VulnId, v.Triage)
		}
	}

	// Images take component-scoped rules.
	il, _ := f.h.ListVulnerableImages(ctx, gen.ListVulnerableImagesRequestObject{})
	if il.(gen.ListVulnerableImages200JSONResponse).Total != 0 {
		t.Fatalf("images without deferred %+v", il)
	}
	il, _ = f.h.ListVulnerableImages(ctx, gen.ListVulnerableImagesRequestObject{Params: gen.ListVulnerableImagesParams{IncludeDeferred: &yes}})
	if l := il.(gen.ListVulnerableImages200JSONResponse); l.Total != 1 || l.Items[0].Digest != digestNginx || l.Items[0].Containers != 1 {
		t.Fatalf("images %+v", l)
	}
	idet, err := f.h.GetVulnerableImage(ctx, gen.GetVulnerableImageRequestObject{Digest: digestNginx})
	must(t, err)
	if d := idet.(gen.GetVulnerableImage200JSONResponse); len(d.Components) != 1 || !d.Components[0].Cves[0].Deferred || *d.Components[0].FixedVersion != "1.27.1" {
		t.Fatalf("image detail %+v", d)
	}

	// OpenVEX: one statement with the decided component.
	vx, err := f.h.ExportVex(ctx, gen.ExportVexRequestObject{})
	must(t, err)
	doc := vx.(gen.ExportVex200JSONResponse)
	sts := doc["statements"].([]map[string]any)
	if len(sts) != 1 || sts[0]["justification"] != "vulnerable_code_not_present" || sts[0]["impact_statement"] != note ||
		sts[0]["products"].([]map[string]any)[0]["@id"] != "pkg:deb/ubuntu/nginx@1.27.0" {
		t.Fatalf("vex %+v", doc)
	}

	// A rule on one asset for an hour.
	until := t0.Add(time.Hour)
	assetRule := create(gen.TriageRuleCreate{VulnId: "CVE-A", Justification: "protected_by_mitigating_control",
		Scope: gen.TriageScope{Kind: "asset", Value: f.db1}, ExpiresAt: &until})
	if n := cveAssets("CVE-A"); n != 1 {
		t.Fatalf("CVE-A assets while deferred on db-1: %d", n)
	}
	rl, _ := f.h.ListTriageRules(ctx, gen.ListTriageRulesRequestObject{})
	rules := rl.(gen.ListTriageRules200JSONResponse)
	if rules.Total != 2 || rules.Items[0].Id != assetRule.Id || *rules.Items[0].Findings != 1 || *rules.Items[0].ScopeName != "db-1" {
		t.Fatalf("rules %+v", rules)
	}

	// Two hours later the asset rule has ended: the expire job records it
	// and the finding is back, marked as ended.
	later := t0.Add(2 * time.Hour)
	f.h.cfg.Now = func() time.Time { return later }
	if n := cveAssets("CVE-A"); n != 2 {
		t.Fatalf("CVE-A assets after expiry: %d", n)
	}
	exp := vulnsvc.NewExpirer(f.db, nil)
	events, err := f.db.ExpireTriageRules(ctx, later)
	must(t, err)
	if len(events) != 1 || events[0].Rule.ID != assetRule.Id || events[0].Findings != 1 || events[0].Rule.ExpiredAt == nil {
		t.Fatalf("expired %+v", events)
	}
	must(t, exp.Run(ctx))
	if again, _ := f.db.ExpireTriageRules(ctx, later); len(again) != 0 {
		t.Fatalf("expired twice %+v", again)
	}
	av, _ = f.h.ListAssetVulnerabilities(ctx, gen.ListAssetVulnerabilitiesRequestObject{Id: f.db1})
	for _, v := range av.(gen.ListAssetVulnerabilities200JSONResponse).Items {
		if v.VulnId == "CVE-A" && (v.Triage == nil || v.Triage.Active || v.Triage.ExpiredAt == nil) {
			t.Fatalf("ended deferral %+v", v.Triage)
		}
	}

	// Revoking brings CVE-C back; a second revoke conflicts.
	_, err = f.h.RevokeTriageRule(ctx, gen.RevokeTriageRuleRequestObject{Id: purlRule.Id})
	must(t, err)
	_, err = f.h.RevokeTriageRule(ctx, gen.RevokeTriageRuleRequestObject{Id: purlRule.Id})
	wantStatus(t, "second revoke", err, http.StatusConflict)
	if s := summary(); s.Totals.Cves != before.Totals.Cves || s.Deferred != 0 {
		t.Fatalf("summary after revoke %+v", s)
	}
	vx, _ = f.h.ExportVex(ctx, gen.ExportVexRequestObject{})
	if sts := vx.(gen.ExportVex200JSONResponse)["statements"].([]map[string]any); len(sts) != 0 {
		t.Fatalf("vex after revoke %+v", sts)
	}

	// The event log, oldest first.
	el, err := f.h.ListTriageEvents(ctx, gen.ListTriageEventsRequestObject{})
	must(t, err)
	evs := el.(gen.ListTriageEvents200JSONResponse).Items
	var kinds []string
	for _, e := range evs {
		kinds = append(kinds, string(e.Kind)+":"+e.Rule.VulnId)
	}
	if names(kinds, func(s string) string { return s }) != "created:CVE-C,created:CVE-A,expired:CVE-A,revoked:CVE-C" ||
		evs[0].Findings != 1 || evs[3].Findings != 1 {
		t.Fatalf("events %v %+v", kinds, evs)
	}
	el, _ = f.h.ListTriageEvents(ctx, gen.ListTriageEventsRequestObject{Params: gen.ListTriageEventsParams{After: &evs[1].Id}})
	if n := len(el.(gen.ListTriageEvents200JSONResponse).Items); n != 2 {
		t.Fatalf("events after %d: %d", evs[1].Id, n)
	}
	_ = ids
}

func TestVulnerableProcesses(t *testing.T) {
	f, ids := seedVulns(t)
	ctx := f.ctx
	pl, err := f.h.ListVulnerableProcesses(ctx, gen.ListVulnerableProcessesRequestObject{})
	must(t, err)
	l := pl.(gen.ListVulnerableProcesses200JSONResponse)
	if l.Total != 1 || l.Items[0].Exe != "/usr/sbin/nginx" || l.Items[0].Listening != 1 || l.Items[0].Cves != 1 {
		t.Fatalf("processes %+v", l)
	}
	pd, err := f.h.GetVulnerableProcess(ctx, gen.GetVulnerableProcessRequestObject{Params: gen.GetVulnerableProcessParams{Exe: "/usr/sbin/nginx"}})
	must(t, err)
	d := pd.(gen.GetVulnerableProcess200JSONResponse)
	if len(d.Components) != 1 || d.Components[0].ComponentId != ids["nginx"] || len(d.Locations) != 1 || d.Process.Processes != 1 {
		t.Fatalf("process detail %+v", d)
	}
	_, err = f.h.GetVulnerableProcess(ctx, gen.GetVulnerableProcessRequestObject{Params: gen.GetVulnerableProcessParams{Exe: "/nope"}})
	wantStatus(t, "unknown process", err, http.StatusNotFound)

	// Filters and sorts: nginx loads CVE-C, rated high and not known exploited.
	yes, no := true, false
	high, critical := gen.SeverityHigh, gen.SeverityCritical
	for name, c := range map[string]struct {
		prm  gen.ListVulnerableProcessesParams
		want int
	}{
		"kev":          {gen.ListVulnerableProcessesParams{Kev: &yes}, 0},
		"not kev":      {gen.ListVulnerableProcessesParams{Kev: &no}, 1},
		"high":         {gen.ListVulnerableProcessesParams{Severity: &high}, 1},
		"critical":     {gen.ListVulnerableProcessesParams{Severity: &critical}, 0},
		"by score":     {gen.ListVulnerableProcessesParams{Sort: ptr(gen.ListVulnerableProcessesParamsSort("-score"))}, 1},
		"by exe":       {gen.ListVulnerableProcessesParams{Sort: ptr(gen.ListVulnerableProcessesParamsSortExe)}, 1},
		"by listening": {gen.ListVulnerableProcessesParams{Sort: ptr(gen.ListVulnerableProcessesParamsSort("-listening"))}, 1},
	} {
		pl, err := f.h.ListVulnerableProcesses(ctx, gen.ListVulnerableProcessesRequestObject{Params: c.prm})
		must(t, err)
		if l := pl.(gen.ListVulnerableProcesses200JSONResponse); l.Total != c.want {
			t.Fatalf("processes %s: %+v", name, l)
		}
	}
	_, err = f.h.ListVulnerableProcesses(ctx, gen.ListVulnerableProcessesRequestObject{Params: gen.ListVulnerableProcessesParams{
		Sort: ptr(gen.ListVulnerableProcessesParamsSort("pid"))}})
	wantStatus(t, "unknown process sort", err, http.StatusBadRequest)

	// Images: the nginx image holds CVE-C.
	il, err := f.h.ListVulnerableImages(ctx, gen.ListVulnerableImagesRequestObject{})
	must(t, err)
	all := il.(gen.ListVulnerableImages200JSONResponse)
	if all.Total == 0 {
		t.Fatalf("images %+v", all)
	}
	for name, c := range map[string]struct {
		prm  gen.ListVulnerableImagesParams
		want int
	}{
		"kev":      {gen.ListVulnerableImagesParams{Kev: &yes}, 0},
		"not kev":  {gen.ListVulnerableImagesParams{Kev: &no}, all.Total},
		"high":     {gen.ListVulnerableImagesParams{Severity: &high}, all.Total},
		"critical": {gen.ListVulnerableImagesParams{Severity: &critical}, 0},
		"by tag":   {gen.ListVulnerableImagesParams{Sort: ptr(gen.ListVulnerableImagesParamsSortTag)}, all.Total},
		"by cves":  {gen.ListVulnerableImagesParams{Sort: ptr(gen.ListVulnerableImagesParamsSort("-cves"))}, all.Total},
	} {
		il, err := f.h.ListVulnerableImages(ctx, gen.ListVulnerableImagesRequestObject{Params: c.prm})
		must(t, err)
		if l := il.(gen.ListVulnerableImages200JSONResponse); l.Total != c.want {
			t.Fatalf("images %s: %+v", name, l)
		}
	}
	_, err = f.h.ListVulnerableImages(ctx, gen.ListVulnerableImagesRequestObject{Params: gen.ListVulnerableImagesParams{
		Sort: ptr(gen.ListVulnerableImagesParamsSort("digest"))}})
	wantStatus(t, "unknown image sort", err, http.StatusBadRequest)
}
