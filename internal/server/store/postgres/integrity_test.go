// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

func itSHA(c byte) string { return strings.Repeat(string(c), 64) }

func itModified(path, sha string) store.IntegrityObservation {
	return store.IntegrityObservation{Path: path, Status: store.IntegrityModified, PkgType: "deb", Package: "nginx",
		Version: "1.24", Algo: "md5", Expected: strings.Repeat("e", 32), Actual: sha[:32], ActualSHA256: sha, Size: 10}
}

func itMissing(path string) store.IntegrityObservation {
	return store.IntegrityObservation{Path: path, Status: store.IntegrityMissing, PkgType: "deb", Package: "at",
		Version: "3", Algo: "md5", Expected: strings.Repeat("e", 32)}
}

func itGroups(t *testing.T, db *DB, f store.IntegrityFilter) []store.IntegrityGroup {
	t.Helper()
	gs, total, err := db.ListIntegrityGroups(ivCtx(t), f, store.Page{})
	ivMust(t, err)
	if total != len(gs) {
		t.Fatalf("total %d for %d groups", total, len(gs))
	}
	return gs
}

func TestIntegrityChunksAndResolution(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	a := ivHost(t, db, "web-01")
	page := "/usr/share/nginx/html/index.html"

	// First chunk of a pass: one modified, one missing file.
	ivMust(t, db.RecordIntegrityChunk(ctx, store.IntegrityChunk{AssetID: a, PassKey: "p1", At: ivT0,
		Cursor: "deb/b", UTCOffset: 32400, Checked: 100, Excluded: 3, Coverage: "full",
		Findings: []store.IntegrityObservation{itModified(page, itSHA('a')), itMissing("/usr/bin/at")}}))
	gs := itGroups(t, db, store.IntegrityFilter{})
	if len(gs) != 2 {
		t.Fatalf("groups %+v", gs)
	}
	p, err := db.LastIntegrityPass(ctx, a)
	ivMust(t, err)
	if p.Cursor != "deb/b" || p.Checked != 100 || p.CompletedAt != nil || p.UTCOffset == nil || *p.UTCOffset != 32400 {
		t.Errorf("pass %+v", p)
	}

	// Second chunk ends the pass: the page changed again. The missing file
	// was reported by this pass's first chunk and stays.
	ivMust(t, db.RecordIntegrityChunk(ctx, store.IntegrityChunk{AssetID: a, PassKey: "p1", At: ivT0.Add(time.Hour),
		Done: true, Checked: 50, Coverage: "partial", Reason: "2 files could not be read",
		Findings: []store.IntegrityObservation{itModified(page, itSHA('b'))}}))
	gs = itGroups(t, db, store.IntegrityFilter{})
	if len(gs) != 2 || gs[0].Path != "/usr/bin/at" || gs[1].ActualSHA256 != itSHA('b') {
		t.Fatalf("after the pass: %+v", gs)
	}
	p, err = db.LastCompletedIntegrityPass(ctx, a)
	ivMust(t, err)
	if p.Checked != 150 || p.Coverage != "partial" || p.CompletedAt == nil {
		t.Errorf("completed pass %+v", p)
	}
	if n := ivCount(t, db, `SELECT count(*) FROM integrity_findings WHERE resolved_at IS NOT NULL`); n != 1 {
		t.Errorf("%d resolved findings, want 1 (the old content)", n)
	}

	// A new pass that reports the same content keeps the finding open with
	// its first_seen; the missing file it does not report is resolved.
	ivMust(t, db.RecordIntegrityChunk(ctx, store.IntegrityChunk{AssetID: a, PassKey: "p2", At: ivT0.Add(25 * time.Hour),
		Done: true, Coverage: "full", Findings: []store.IntegrityObservation{itModified(page, itSHA('b'))}}))
	fs, _, err := db.ListIntegrityFindings(ctx, store.IntegrityFilter{}, store.Page{})
	ivMust(t, err)
	if len(fs) != 1 || !fs[0].FirstSeen.Equal(ivT0.Add(time.Hour)) || !fs[0].LastSeen.Equal(ivT0.Add(25*time.Hour)) {
		t.Errorf("findings %+v", fs)
	}
	if fs[0].AssetName != "web-01" || fs[0].Collector != string(store.CollectAgent) || fs[0].Size != 10 {
		t.Errorf("finding %+v", fs[0])
	}
}

func TestIntegrityAllowRules(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	a1, a2, a3 := ivHost(t, db, "web-01"), ivHost(t, db, "web-02"), ivHost(t, db, "web-03")
	page := "/usr/share/nginx/html/index.html"
	for _, a := range []string{a1, a2} {
		ivMust(t, db.RecordIntegrityChunk(ctx, store.IntegrityChunk{AssetID: a, PassKey: "p", At: ivT0, Done: true,
			Coverage: "full", Findings: []store.IntegrityObservation{itModified(page, itSHA('a'))}}))
	}
	ivMust(t, db.RecordIntegrityChunk(ctx, store.IntegrityChunk{AssetID: a3, PassKey: "p", At: ivT0, Done: true,
		Coverage: "full", Findings: []store.IntegrityObservation{itModified(page, itSHA('c')), itMissing("/usr/bin/at")}}))

	gs := itGroups(t, db, store.IntegrityFilter{})
	if len(gs) != 3 || gs[0].ActualSHA256 != itSHA('a') || gs[0].Assets != 2 {
		t.Fatalf("groups %+v", gs)
	}

	// An asset rule hides the finding on that asset only.
	_, err := db.CreateIntegrityAllowRule(ctx, store.IntegrityAllowRule{Scope: store.IntegrityScopeAsset, AssetID: a1,
		Path: page, Status: store.IntegrityModified, ActualSHA256: itSHA('a'), Note: "manual change", CreatedBy: "admin"})
	ivMust(t, err)
	gs = itGroups(t, db, store.IntegrityFilter{SHA256: ptr(itSHA('a'))})
	if len(gs) != 1 || gs[0].Assets != 1 {
		t.Errorf("after the asset rule: %+v", gs)
	}

	// A fleet rule hides it everywhere, including on a later asset.
	_, err = db.CreateIntegrityAllowRule(ctx, store.IntegrityAllowRule{Scope: store.IntegrityScopeFleet,
		Path: page, Status: store.IntegrityModified, ActualSHA256: itSHA('a'), Note: "deployed page", CreatedBy: "admin"})
	ivMust(t, err)
	a4 := ivHost(t, db, "web-04")
	ivMust(t, db.RecordIntegrityChunk(ctx, store.IntegrityChunk{AssetID: a4, PassKey: "p", At: ivT0, Done: true,
		Coverage: "full", Findings: []store.IntegrityObservation{itModified(page, itSHA('a'))}}))
	gs = itGroups(t, db, store.IntegrityFilter{})
	if len(gs) != 2 {
		t.Fatalf("after the fleet rule: %+v", gs)
	}
	for _, g := range gs {
		if g.ActualSHA256 == itSHA('a') {
			t.Errorf("allowed content shown: %+v", g)
		}
	}
	all := itGroups(t, db, store.IntegrityFilter{IncludeAllowed: true})
	if len(all) != 3 || all[0].Assets != 3 || all[0].AllowedAssets != 3 {
		t.Errorf("with allowed: %+v", all)
	}

	// The same file changed again on web-01 shows up again.
	ivMust(t, db.RecordIntegrityChunk(ctx, store.IntegrityChunk{AssetID: a1, PassKey: "p2", At: ivT0.Add(time.Hour),
		Done: true, Coverage: "full", Findings: []store.IntegrityObservation{itModified(page, itSHA('d'))}}))
	if gs := itGroups(t, db, store.IntegrityFilter{SHA256: ptr(itSHA('d'))}); len(gs) != 1 {
		t.Errorf("new content hidden: %+v", gs)
	}

	s, err := db.IntegritySummary(ctx, ivT0.Add(-time.Hour))
	ivMust(t, err)
	if s.Groups != 3 || s.Assets != 2 || s.Rules != 2 || s.Tracked != 4 || s.Completed != 4 {
		t.Errorf("summary %+v", s)
	}

	rules, total, err := db.ListIntegrityAllowRules(ctx, false, store.Page{})
	ivMust(t, err)
	if total != 2 || rules[0].Scope != store.IntegrityScopeFleet || rules[0].Hidden != 2 || rules[1].AssetName != "web-01" {
		t.Errorf("rules %+v", rules)
	}

	// Revoking brings the findings back.
	ivMust(t, db.RevokeIntegrityAllowRule(ctx, rules[0].ID, "admin", ivT0.Add(2*time.Hour)))
	if err := db.RevokeIntegrityAllowRule(ctx, rules[0].ID, "admin", ivT0); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("second revoke: %v", err)
	}
	gs = itGroups(t, db, store.IntegrityFilter{SHA256: ptr(itSHA('a'))})
	if len(gs) != 1 || gs[0].Assets != 2 {
		t.Errorf("after revoking: %+v", gs)
	}
	all2, _, err := db.ListIntegrityAllowRules(ctx, true, store.Page{})
	ivMust(t, err)
	if len(all2) != 2 || all2[0].RevokedAt == nil || all2[0].RevokedBy != "admin" || all2[0].Hidden != 0 {
		t.Errorf("rules with revoked %+v", all2)
	}

	// Filters.
	if gs := itGroups(t, db, store.IntegrityFilter{Status: store.IntegrityMissing}); len(gs) != 1 || gs[0].Path != "/usr/bin/at" {
		t.Errorf("status filter %+v", gs)
	}
	if gs := itGroups(t, db, store.IntegrityFilter{Q: "WEB-03"}); len(gs) != 2 {
		t.Errorf("asset name filter %+v", gs)
	}
	fs, _, err := db.ListIntegrityFindings(ctx, store.IntegrityFilter{Path: page, SHA256: ptr(itSHA('a'))}, store.Page{})
	ivMust(t, err)
	if len(fs) != 2 {
		t.Errorf("findings of one group %+v", fs)
	}
}

func ptr[T any](v T) *T { return &v }

func TestIntegrityAllowRuleValidation(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	a := ivHost(t, db, "h")
	for name, r := range map[string]store.IntegrityAllowRule{
		"scope":       {Scope: "x", Path: "/a", Status: store.IntegrityModified, ActualSHA256: itSHA('a'), Note: "n"},
		"asset":       {Scope: store.IntegrityScopeAsset, Path: "/a", Status: store.IntegrityModified, ActualSHA256: itSHA('a'), Note: "n"},
		"sha":         {Scope: store.IntegrityScopeFleet, Path: "/a", Status: store.IntegrityModified, ActualSHA256: "abc", Note: "n"},
		"upper sha":   {Scope: store.IntegrityScopeFleet, Path: "/a", Status: store.IntegrityModified, ActualSHA256: strings.Repeat("A", 64), Note: "n"},
		"missing sha": {Scope: store.IntegrityScopeFleet, Path: "/a", Status: store.IntegrityMissing, ActualSHA256: itSHA('a'), Note: "n"},
		"path":        {Scope: store.IntegrityScopeFleet, Path: "a", Status: store.IntegrityModified, ActualSHA256: itSHA('a'), Note: "n"},
		"note":        {Scope: store.IntegrityScopeFleet, Path: "/a", Status: store.IntegrityModified, ActualSHA256: itSHA('a')},
	} {
		if _, err := db.CreateIntegrityAllowRule(ctx, r); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	_, err := db.CreateIntegrityAllowRule(ctx, store.IntegrityAllowRule{Scope: store.IntegrityScopeAsset, AssetID: "00000000-0000-0000-0000-000000000000",
		Path: "/a", Status: store.IntegrityMissing, Note: "n"})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown asset: %v", err)
	}
	_, err = db.CreateIntegrityAllowRule(ctx, store.IntegrityAllowRule{Scope: store.IntegrityScopeAsset, AssetID: a,
		Path: "/a", Status: store.IntegrityMissing, Note: "n"})
	ivMust(t, err)
}

func TestIntegrityModes(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	ag := mgTestAgent(t, db, nil)
	if ag.Integrity != store.IntegrityInherit {
		t.Errorf("default agent mode %q", ag.Integrity)
	}
	ivMust(t, db.SetAgentIntegrity(ctx, ag.ID, store.IntegrityOff))
	got, err := db.GetAgent(ctx, ag.ID)
	ivMust(t, err)
	if got.Integrity != store.IntegrityOff {
		t.Errorf("agent mode %q", got.Integrity)
	}
	if err := db.SetAgentIntegrity(ctx, ag.ID, "sometimes"); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("bad mode: %v", err)
	}
}
