// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package inventoryapi

import (
	"fmt"
	"net/http"
	"slices"
	"testing"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/internal/server/vulnsvc"
)

func ptrF(f float64) *float64 { return &f }

// seedVulns matches the seed's components (openssl: CVE-A, CVE-B; nginx in
// the web-1 container image: CVE-C; curl unsupported) and computes the
// findings. It returns the component ids by name.
func seedVulns(t *testing.T) (*fixture, map[string]string) {
	t.Helper()
	return seedVulnsRated(t, nil)
}

// seedVulnsRated is seedVulns with the distribution's ratings of the
// matches, by vulnerability id.
func seedVulnsRated(t *testing.T, ratings map[string]string) (*fixture, map[string]string) {
	t.Helper()
	f := seed(t)
	ctx := f.ctx
	srv, err := f.db.GetActiveFeedServer(ctx)
	must(t, err)
	must(t, f.db.RecordFeedData(ctx, srv.ID, store.FeedData{Revision: 7}))
	epoch := store.MatchEpoch{ServerID: srv.ID, Revision: 7}
	pending, err := f.db.PendingMatches(ctx, epoch, 100)
	must(t, err)
	ids := map[string]string{}
	var batch []store.ComponentMatch
	for _, c := range pending {
		ids[c.Name] = c.ID
		m := store.ComponentMatch{ComponentID: c.ID, Status: store.MatchChecked}
		switch c.Name {
		case "openssl":
			m.Vulns = []store.ComponentVuln{
				{VulnID: "CVE-A", Method: "package", FixState: "fixed", FixedVersion: "3.0.13-1"},
				{VulnID: "CVE-B", Method: "package", FixState: "fixed", FixedVersion: "3.0.14"},
			}
		case "nginx":
			m.Vulns = []store.ComponentVuln{{VulnID: "CVE-C", Method: "package", FixState: "fixed", FixedVersion: "1.27.1"}}
		case "curl":
			m.Status = store.MatchUnsupported
		}
		for i := range m.Vulns {
			m.Vulns[i].Severity = ratings[m.Vulns[i].VulnID]
		}
		batch = append(batch, m)
	}
	must(t, f.db.SaveMatches(ctx, store.MatchBatch{Epoch: epoch, Components: batch, Vulns: []store.VulnMeta{
		{ID: "CVE-A", Summary: "overflow", MaxScore: ptrF(9.8), Severity: "critical", KEV: &store.KEVEntry{DateAdded: "2024-07-01"}, EPSS: ptrF(0.9)},
		{ID: "CVE-B", MaxScore: ptrF(5.3), Severity: "medium"},
		{ID: "CVE-C", MaxScore: ptrF(7.5), Severity: "high", EPSS: ptrF(0.1)},
	}}))
	r, err := vulnsvc.NewRefresher(f.db, nil, nil)
	must(t, err)
	must(t, r.Run(ctx))
	return f, ids
}

func TestVulnerabilityViews(t *testing.T) {
	f, ids := seedVulns(t)
	ctx := f.ctx

	// Update actions: nginx listens in its container, openssl's places are
	// not fully collected; KEV does not outrank exposure.
	list, err := f.h.ListVulnerableComponents(ctx, gen.ListVulnerableComponentsRequestObject{})
	must(t, err)
	units := list.(gen.ListVulnerableComponents200JSONResponse)
	if units.Total != 2 || units.Items[0].Name != "nginx" || units.Items[1].Name != "openssl" {
		t.Fatalf("units %+v", units)
	}
	ng, ssl := units.Items[0], units.Items[1]
	if ng.Exposure != gen.ExposureListening || ng.ExposureCounts.Listening != 1 || len(ng.Processes) != 1 || ng.Processes[0].Exe != "/usr/sbin/nginx" {
		t.Fatalf("nginx unit %+v", ng)
	}
	if ssl.Cves != 2 || ssl.Kev != 1 || ssl.Assets != 2 || *ssl.FixedVersion != "3.0.14" || ssl.SeverityCounts.Critical != 1 ||
		ssl.Exposure != gen.ExposureUnknown || ssl.ExposureCounts.Unknown != 2 || *ssl.Severity != gen.SeverityCritical {
		t.Fatalf("openssl unit %+v", ssl)
	}
	kev := true
	list, _ = f.h.ListVulnerableComponents(ctx, gen.ListVulnerableComponentsRequestObject{Params: gen.ListVulnerableComponentsParams{Kev: &kev}})
	if u := list.(gen.ListVulnerableComponents200JSONResponse); u.Total != 1 || u.Items[0].Name != "openssl" {
		t.Fatalf("kev filter %+v", u)
	}
	q := "cve-c"
	list, _ = f.h.ListVulnerableComponents(ctx, gen.ListVulnerableComponentsRequestObject{Params: gen.ListVulnerableComponentsParams{Q: &q}})
	if u := list.(gen.ListVulnerableComponents200JSONResponse); u.Total != 1 || u.Items[0].Name != "nginx" {
		t.Fatalf("q filter %+v", u)
	}

	// Component detail.
	det, err := f.h.GetVulnerableComponent(ctx, gen.GetVulnerableComponentRequestObject{Id: ids["nginx"]})
	must(t, err)
	d := det.(gen.GetVulnerableComponent200JSONResponse)
	if len(d.Locations) != 1 || d.Locations[0].Layer != gen.FindingLayerImage || *d.Locations[0].Container != "nginx" ||
		d.Locations[0].Processes[0].Ports[0] != "tcp/443" || len(d.Cves) != 1 || *d.Cves[0].FixedVersion != "1.27.1" {
		t.Fatalf("nginx detail %+v", d)
	}
	_, err = f.h.GetVulnerableComponent(ctx, gen.GetVulnerableComponentRequestObject{Id: ids["curl"]})
	wantStatus(t, "curl detail", err, http.StatusNotFound)

	// Vulnerabilities.
	cl, err := f.h.ListVulnerabilities(ctx, gen.ListVulnerabilitiesRequestObject{})
	must(t, err)
	cves := cl.(gen.ListVulnerabilities200JSONResponse)
	if cves.Total != 3 || cves.Items[0].VulnId != "CVE-C" || cves.Items[1].VulnId != "CVE-A" {
		t.Fatalf("cves %+v", cves)
	}
	cd, err := f.h.GetVulnerability(ctx, gen.GetVulnerabilityRequestObject{VulnId: "CVE-A"})
	must(t, err)
	c := cd.(gen.GetVulnerability200JSONResponse)
	if c.Vulnerability.Kev == nil || len(c.Components) != 1 || c.Components[0].Assets != 2 || len(c.Locations) != 2 {
		t.Fatalf("CVE-A detail %+v", c)
	}
	_, err = f.h.GetVulnerability(ctx, gen.GetVulnerabilityRequestObject{VulnId: "CVE-NONE"})
	wantStatus(t, "unknown cve", err, http.StatusNotFound)

	// Asset findings.
	av, err := f.h.ListAssetVulnerabilities(ctx, gen.ListAssetVulnerabilitiesRequestObject{Id: f.web})
	must(t, err)
	items := av.(gen.ListAssetVulnerabilities200JSONResponse).Items
	if len(items) != 3 || items[0].ComponentName != "nginx" || items[0].Layer != gen.FindingLayerImage {
		t.Fatalf("asset findings %+v", items)
	}

	// Summary.
	sm, err := f.h.GetVulnerabilitySummary(ctx, gen.GetVulnerabilitySummaryRequestObject{})
	must(t, err)
	s := sm.(gen.GetVulnerabilitySummary200JSONResponse)
	if s.Urgent.Components != 1 || s.Urgent.Cves != 1 || s.Totals.Cves != 3 || s.Totals.Kev != 1 || s.Totals.Assets != 2 ||
		s.Totals.Components != 2 || s.ActionsTotal != 2 || len(s.Actions) != 2 || *s.Revision != 7 || s.Unsupported != 1 {
		t.Fatalf("summary %+v", s)
	}
}

// TestNegligibleSeverity: nginx's only vulnerability is rated negligible by
// the distribution, openssl's critical one low. Negligible findings leave
// the aggregated views unless asked for and then come last; the
// distribution's rating replaces the CVSS one everywhere.
func TestNegligibleSeverity(t *testing.T) {
	f, ids := seedVulnsRated(t, map[string]string{"CVE-C": store.SeverityNegligible, "CVE-A": "low"})
	ctx := f.ctx
	yes := true

	list, err := f.h.ListVulnerableComponents(ctx, gen.ListVulnerableComponentsRequestObject{})
	must(t, err)
	units := list.(gen.ListVulnerableComponents200JSONResponse)
	if units.Total != 1 || units.Items[0].Name != "openssl" {
		t.Fatalf("units %+v", units)
	}
	ssl := units.Items[0]
	if ssl.SeverityCounts.Critical != 0 || ssl.SeverityCounts.Low != 1 || ssl.SeverityCounts.Medium != 1 || *ssl.Severity != gen.SeverityMedium {
		t.Fatalf("openssl unit %+v", ssl)
	}
	list, err = f.h.ListVulnerableComponents(ctx, gen.ListVulnerableComponentsRequestObject{
		Params: gen.ListVulnerableComponentsParams{IncludeNegligible: &yes}})
	must(t, err)
	units = list.(gen.ListVulnerableComponents200JSONResponse)
	// nginx listens, but is rated only negligible.
	if units.Total != 2 || units.Items[1].Name != "nginx" || *units.Items[1].Severity != gen.SeverityNegligible ||
		units.Items[1].SeverityCounts.Negligible != 1 {
		t.Fatalf("units with negligible %+v", units)
	}
	neg := gen.SeverityNegligible
	list, err = f.h.ListVulnerableComponents(ctx, gen.ListVulnerableComponentsRequestObject{
		Params: gen.ListVulnerableComponentsParams{Severity: &neg}})
	must(t, err)
	if u := list.(gen.ListVulnerableComponents200JSONResponse); u.Total != 1 || u.Items[0].Name != "nginx" {
		t.Fatalf("negligible filter %+v", u)
	}

	cl, err := f.h.ListVulnerabilities(ctx, gen.ListVulnerabilitiesRequestObject{})
	must(t, err)
	if c := cl.(gen.ListVulnerabilities200JSONResponse); c.Total != 2 {
		t.Fatalf("cves %+v", c)
	}
	cl, err = f.h.ListVulnerabilities(ctx, gen.ListVulnerabilitiesRequestObject{Params: gen.ListVulnerabilitiesParams{IncludeNegligible: &yes}})
	must(t, err)
	cves := cl.(gen.ListVulnerabilities200JSONResponse)
	if cves.Total != 3 || cves.Items[2].VulnId != "CVE-C" || *cves.Items[2].Severity != gen.SeverityNegligible {
		t.Fatalf("cves with negligible %+v", cves)
	}
	cd, err := f.h.GetVulnerability(ctx, gen.GetVulnerabilityRequestObject{VulnId: "CVE-C"})
	must(t, err)
	c := cd.(gen.GetVulnerability200JSONResponse)
	if *c.Vulnerability.Severity != gen.SeverityNegligible || *c.Components[0].Severity != gen.SeverityNegligible {
		t.Fatalf("CVE-C detail %+v", c)
	}

	det, err := f.h.GetVulnerableComponent(ctx, gen.GetVulnerableComponentRequestObject{Id: ids["nginx"]})
	must(t, err)
	if d := det.(gen.GetVulnerableComponent200JSONResponse); len(d.Cves) != 1 || *d.Cves[0].Severity != gen.SeverityNegligible {
		t.Fatalf("nginx detail %+v", d)
	}

	av, err := f.h.ListAssetVulnerabilities(ctx, gen.ListAssetVulnerabilitiesRequestObject{Id: f.web})
	must(t, err)
	items := av.(gen.ListAssetVulnerabilities200JSONResponse).Items
	if len(items) != 3 || items[2].VulnId != "CVE-C" || *items[2].Severity != gen.SeverityNegligible {
		t.Fatalf("asset findings %+v", items)
	}

	pl, err := f.h.ListVulnerableProcesses(ctx, gen.ListVulnerableProcessesRequestObject{})
	must(t, err)
	if p := pl.(gen.ListVulnerableProcesses200JSONResponse); p.Total != 0 {
		t.Fatalf("processes %+v", p)
	}
	pl, err = f.h.ListVulnerableProcesses(ctx, gen.ListVulnerableProcessesRequestObject{
		Params: gen.ListVulnerableProcessesParams{IncludeNegligible: &yes}})
	must(t, err)
	procs := pl.(gen.ListVulnerableProcesses200JSONResponse)
	if procs.Total != 1 || procs.Items[0].SeverityCounts.Negligible != 1 || *procs.Items[0].Severity != gen.SeverityNegligible {
		t.Fatalf("processes with negligible %+v", procs)
	}
	pd, err := f.h.GetVulnerableProcess(ctx, gen.GetVulnerableProcessRequestObject{Params: gen.GetVulnerableProcessParams{Exe: "/usr/sbin/nginx"}})
	must(t, err)
	if p := pd.(gen.GetVulnerableProcess200JSONResponse); p.Process.Cves != 1 || len(p.Components) != 1 {
		t.Fatalf("process detail %+v", p)
	}

	il, err := f.h.ListVulnerableImages(ctx, gen.ListVulnerableImagesRequestObject{})
	must(t, err)
	if i := il.(gen.ListVulnerableImages200JSONResponse); i.Total != 0 {
		t.Fatalf("images %+v", i)
	}
	il, err = f.h.ListVulnerableImages(ctx, gen.ListVulnerableImagesRequestObject{Params: gen.ListVulnerableImagesParams{IncludeNegligible: &yes}})
	must(t, err)
	if i := il.(gen.ListVulnerableImages200JSONResponse); i.Total != 1 || i.Items[0].SeverityCounts.Negligible != 1 {
		t.Fatalf("images with negligible %+v", i)
	}

	sm, err := f.h.GetVulnerabilitySummary(ctx, gen.GetVulnerabilitySummaryRequestObject{})
	must(t, err)
	s := sm.(gen.GetVulnerabilitySummary200JSONResponse)
	if s.Negligible != 1 || s.Totals.Cves != 2 || s.Totals.Components != 1 || s.Urgent.Components != 0 {
		t.Fatalf("summary %+v", s)
	}
}

// TestComponentCveReachability: a component's CVE row combines the
// reachability of its places, and a linked vulnerable function outranks KEV
// within one exposure.
func TestComponentCveReachability(t *testing.T) {
	f, ids := seedVulns(t)
	ctx := f.ctx
	set := func(vuln string, reach ...string) {
		t.Helper()
		rows, err := f.db.Pool().Query(ctx, `SELECT DISTINCT asset_id FROM findings
			WHERE component_id = $1 AND vuln_id = $2 ORDER BY asset_id`, ids["openssl"], vuln)
		must(t, err)
		var assets []string
		for rows.Next() {
			var a string
			must(t, rows.Scan(&a))
			assets = append(assets, a)
		}
		rows.Close()
		if len(assets) != len(reach) {
			t.Fatalf("%s at %d places", vuln, len(assets))
		}
		for i, a := range assets {
			var r *string
			if reach[i] != "" {
				r = &reach[i]
			}
			_, err := f.db.Pool().Exec(ctx, `UPDATE findings SET reachability = $1
				WHERE asset_id = $2 AND component_id = $3 AND vuln_id = $4`, r, a, ids["openssl"], vuln)
			must(t, err)
		}
	}
	_, err := f.db.Pool().Exec(ctx, `UPDATE component_vulns SET symbols = $1
		WHERE component_id = $2 AND vuln_id = 'CVE-B'`, `[{"path":"crypto/tls","symbols":["Conn.Handshake"]}]`, ids["openssl"])
	must(t, err)
	get := func() map[string]gen.VulnCve {
		t.Helper()
		det, err := f.h.GetVulnerableComponent(ctx, gen.GetVulnerableComponentRequestObject{Id: ids["openssl"]})
		must(t, err)
		d := det.(gen.GetVulnerableComponent200JSONResponse)
		out := map[string]gen.VulnCve{}
		for i, v := range d.Cves {
			out[v.VulnId] = v
			out[fmt.Sprint(i)] = v
		}
		return out
	}
	reach := func(v gen.VulnCve) string {
		if v.Reachability == nil {
			return ""
		}
		return string(*v.Reachability)
	}
	absent := func(v gen.VulnCve) int {
		if v.SymbolAbsent == nil {
			return 0
		}
		return *v.SymbolAbsent
	}

	set("CVE-A", store.ReachSymbolAbsent, "")
	set("CVE-B", store.ReachSymbolAbsent, store.ReachSymbolAbsent)
	got := get()
	if a := got["CVE-A"]; reach(a) != "" || absent(a) != 1 {
		t.Errorf("one place absent, one unknown: %v %d", reach(a), absent(a))
	}
	if b := got["CVE-B"]; reach(b) != store.ReachSymbolAbsent || absent(b) != 2 || b.Symbols == nil ||
		!slices.Equal(*b.Symbols, []string{"crypto/tls.Conn.Handshake"}) {
		t.Errorf("all absent: %v %d %v", reach(b), absent(b), b.Symbols)
	}
	if got["0"].VulnId != "CVE-A" {
		t.Errorf("order %s first", got["0"].VulnId)
	}

	set("CVE-B", store.ReachSymbolPresent, store.ReachSymbolAbsent)
	got = get()
	if b := got["CVE-B"]; reach(b) != store.ReachSymbolPresent || absent(b) != 1 {
		t.Errorf("one place present: %v %d", reach(b), absent(b))
	}
	if got["0"].VulnId != "CVE-B" {
		t.Errorf("present after KEV: %s first", got["0"].VulnId)
	}
}
