// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package inventoryapi

import (
	"net/http"
	"testing"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/internal/server/vulnsvc"
)

func ptrF(f float64) *float64 { return &f }

func TestVulnerabilityViews(t *testing.T) {
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
