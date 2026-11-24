// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

func TestMatches(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	srv, err := db.GetActiveFeedServer(ctx)
	ivMust(t, err)

	asset := ivHost(t, db, "web-01")
	scope := store.ComponentScope{AssetID: asset, Source: store.SourcePackages}
	openssl, curl := ivDeb("openssl", "3.0.13-0ubuntu3"), ivDeb("curl", "8.5.0-2ubuntu10")
	_, err = db.ReplaceAssetComponents(ctx, scope, ivPkgObs(openssl, curl), store.ReplaceOptions{At: ivT0})
	ivMust(t, err)

	e1 := store.MatchEpoch{ServerID: srv.ID, Revision: 10, Rules: "r1"}
	pending, err := db.PendingMatches(ctx, e1, 10)
	ivMust(t, err)
	if len(pending) != 2 || pending[0].Distro != "ubuntu-24.04" || pending[0].PURL == "" {
		t.Fatalf("pending %+v", pending)
	}
	ids := map[string]string{}
	for _, c := range pending {
		ids[c.Name] = c.ID
	}

	score, epss := 9.8, 0.97354
	kev := &store.KEVEntry{DateAdded: "2024-07-01", RequiredAction: "patch"}
	published := time.Date(2024, 7, 1, 0, 0, 0, 0, time.UTC)
	b := store.MatchBatch{
		Epoch: e1,
		Components: []store.ComponentMatch{
			{ComponentID: ids["openssl"], OSKey: "ubuntu:24.04", Status: store.MatchChecked, Vulns: []store.ComponentVuln{
				{VulnID: "CVE-2024-0001", Method: "package", Ecosystem: "ubuntu:24.04", FixState: "fixed", FixedVersion: "3.0.13-0ubuntu3.1",
					Advisories: []store.VulnAdvisory{{Source: "osv", ID: "UBUNTU-CVE-2024-0001", Severity: "high"}}},
				{VulnID: "CVE-2024-0002", Method: "cpe", Ecosystem: "nvd", FixState: "unknown", CPEMatch: "range", RangeSource: "nvd",
					Platforms: []string{"cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"}},
			}},
			{ComponentID: ids["curl"], OSKey: "ubuntu:24.04", Status: store.MatchChecked},
		},
		Vulns: []store.VulnMeta{
			{ID: "CVE-2024-0001", Summary: "overflow", CVSS: []store.CVSSScore{{Version: "3.1", Vector: "CVSS:3.1/AV:N", Score: score, Type: "Primary"}},
				MaxScore: &score, Severity: "critical", KEV: kev, EPSS: &epss, Published: &published, Aliases: []string{"GHSA-x"}},
			{ID: "CVE-2024-0002", Summary: "minor"},
		},
	}
	ivMust(t, db.SaveMatches(ctx, b))

	if p, _ := db.PendingMatches(ctx, e1, 10); len(p) != 0 {
		t.Fatalf("pending after save: %+v", p)
	}
	c, err := db.CountMatches(ctx, e1)
	ivMust(t, err)
	if c != (store.MatchCounts{Checked: 2, Vulnerable: 1}) {
		t.Fatalf("counts %+v", c)
	}

	vulns, err := db.ListComponentVulns(ctx, ids["openssl"])
	ivMust(t, err)
	if len(vulns) != 2 {
		t.Fatalf("vulns %+v", vulns)
	}
	v := vulns[0]
	if v.VulnID != "CVE-2024-0001" || v.FixedVersion != "3.0.13-0ubuntu3.1" || *v.Meta.MaxScore != 9.8 || *v.Meta.EPSS != 0.97354 ||
		v.Meta.KEV == nil || v.Meta.KEV.RequiredAction != "patch" || !v.Meta.Published.Equal(published) ||
		len(v.Advisories) != 1 || v.Advisories[0].Severity != "high" || len(v.Meta.CVSS) != 1 || v.Meta.Aliases[0] != "GHSA-x" {
		t.Fatalf("first vuln %+v", v)
	}
	if w := vulns[1]; w.CPEMatch != "range" || len(w.Platforms) != 1 || w.Meta.MaxScore != nil || w.Meta.KEV != nil {
		t.Fatalf("second vuln %+v", w)
	}

	// A newer revision makes both pending again; matching replaces the
	// vulnerabilities.
	e2 := store.MatchEpoch{ServerID: srv.ID, Revision: 11, Rules: "r1"}
	if p, _ := db.PendingMatches(ctx, e2, 10); len(p) != 2 {
		t.Fatalf("pending for a newer revision: %d", len(p))
	}
	ivMust(t, db.SaveMatches(ctx, store.MatchBatch{Epoch: e2, Components: []store.ComponentMatch{
		{ComponentID: ids["openssl"], Status: store.MatchChecked},
		{ComponentID: ids["curl"], Status: store.MatchUnsupported, Reason: "no data"},
	}}))
	if vulns, _ := db.ListComponentVulns(ctx, ids["openssl"]); len(vulns) != 0 {
		t.Fatalf("vulns not replaced: %+v", vulns)
	}
	m, e, _, err := db.GetComponentMatch(ctx, ids["curl"])
	ivMust(t, err)
	if m.Status != store.MatchUnsupported || m.Reason != "no data" || e != e2 {
		t.Fatalf("match %+v %+v", m, e)
	}
	// Changed rules make them pending too; a reset forgets everything.
	if p, _ := db.PendingMatches(ctx, store.MatchEpoch{ServerID: srv.ID, Revision: 11, Rules: "r2"}, 10); len(p) != 2 {
		t.Fatalf("pending for new rules: %d", len(p))
	}
	ivMust(t, db.ResetMatches(ctx, srv.ID))
	if _, _, _, err := db.GetComponentMatch(ctx, ids["curl"]); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after reset: %v", err)
	}

	// Removed components are not live and not matched.
	_, err = db.ReplaceAssetComponents(ctx, scope, ivPkgObs(openssl), store.ReplaceOptions{At: ivT0.Add(time.Hour)})
	ivMust(t, err)
	if p, _ := db.PendingMatches(ctx, e2, 10); len(p) != 1 || p[0].Name != "openssl" {
		t.Fatalf("pending after removal: %+v", p)
	}
}
