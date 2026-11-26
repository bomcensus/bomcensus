// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/server/scope"
)

func ntNotice(id string) store.Notice {
	published := time.Date(2026, 3, 4, 0, 0, 0, 0, time.UTC)
	return store.Notice{ID: id, Source: "kisa", Title: "OpenSSL 보안 업데이트 권고", URL: "https://knvd.example/" + id,
		Published: &published, Summary: "OpenSSL fixes a buffer overflow.", CVEIDs: []string{"CVE-2026-1000"},
		RelatedCVEIDs: []string{"CVE-2025-9999"}, AdvisoryIDs: []string{"KVE-2026-0001"},
		Software: []store.NoticeSoftware{{Vendor: "OpenSSL", Product: "OpenSSL", CPEVendor: "openssl", CPEProduct: "openssl",
			Affected: "3.0.0 ~ 3.0.13", Fixed: "3.0.14"}}}
}

// ntOne returns a check that a list holds one notice, which it returns.
func ntOne(t *testing.T) func([]store.NoticeRow, int, error) store.NoticeRow {
	return func(rows []store.NoticeRow, total int, err error) store.NoticeRow {
		t.Helper()
		ivMust(t, err)
		if len(rows) != 1 || total != 1 {
			t.Fatalf("%d notices (total %d), want 1: %+v", len(rows), total, rows)
		}
		return rows[0]
	}
}

func TestNotices(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	srv, err := db.GetActiveFeedServer(ctx)
	ivMust(t, err)
	web, dbHost := ivHost(t, db, "web-01"), ivHost(t, db, "db-01")
	openssl, curl := ivDeb("openssl", "3.0.13"), ivDeb("curl", "8.5.0")
	for _, a := range []string{web, dbHost} {
		_, err := db.ReplaceAssetComponents(ctx, store.ComponentScope{AssetID: a, Source: store.SourcePackages},
			ivPkgObs(openssl, curl), store.ReplaceOptions{At: ivT0})
		ivMust(t, err)
	}
	ids, err := db.LookupComponentIDs(ctx, []store.Component{openssl, curl})
	ivMust(t, err)
	sslID, curlID := ids[0], ids[1]
	match := func(rev int64, at time.Time, notices ...string) {
		t.Helper()
		b := store.MatchBatch{Epoch: store.MatchEpoch{ServerID: srv.ID, Revision: rev}, At: at, Components: []store.ComponentMatch{
			{ComponentID: sslID, Status: store.MatchChecked, Notices: notices},
			{ComponentID: curlID, Status: store.MatchChecked},
		}}
		for _, n := range notices {
			b.Notices = append(b.Notices, ntNotice(n))
		}
		ivMust(t, db.SaveMatches(ctx, b))
	}
	match(1, ivT0, "kisa-1")

	n := ntOne(t)(db.ListNotices(ctx, store.NoticeFilter{}, scPage()))
	if n.ID != "kisa-1" || n.Assets != 2 || n.NewAssets != 2 || !n.Unread() || n.ReadAt != nil || n.Title == "" ||
		len(n.Software) != 1 || n.Software[0].Fixed != "3.0.14" || n.RelatedCVEIDs[0] != "CVE-2025-9999" ||
		!n.FirstMatched.Equal(ivT0) || n.Published == nil {
		t.Fatalf("notice %+v", n)
	}
	if c, err := db.CountNotices(ctx); err != nil || c != (store.NoticeCounts{Total: 1, Unread: 1}) {
		t.Fatalf("counts %+v %v", c, err)
	}
	ms, err := db.ListNoticeMatches(ctx, store.NoticeMatchFilter{NoticeID: "kisa-1"})
	ivMust(t, err)
	if len(ms) != 2 || ms[0].AssetName != "db-01" || ms[0].Component.Name != "openssl" || !ms[0].New ||
		len(ms[0].Locations) != 1 || !ms[0].FirstSeen.Equal(ivT0) {
		t.Fatalf("matches %+v", ms)
	}

	// Search and filters.
	for _, q := range []string{"kisa-1", "openssl 보안", "fixes a buffer", "CVE-2025-9999", "KVE-2026", "OpenSSL"} {
		ntOne(t)(db.ListNotices(ctx, store.NoticeFilter{Q: q}, scPage()))
	}
	for _, f := range []store.NoticeFilter{{Q: "nginx"}, {Source: "tmaxsoft"}, {Q: "cpe_vendor"}} {
		if rows, _, err := db.ListNotices(ctx, f, scPage()); err != nil || len(rows) != 0 {
			t.Fatalf("filter %+v: %+v %v", f, rows, err)
		}
	}
	if a := ntOne(t)(db.ListNotices(ctx, store.NoticeFilter{AssetID: web}, scPage())); a.Assets != 1 {
		t.Fatalf("asset filter %+v", a)
	}
	if rows, _, err := db.ListNotices(ctx, store.NoticeFilter{AssetID: "x"}, scPage()); err != nil || len(rows) != 0 {
		t.Fatalf("malformed asset id: %+v %v", rows, err)
	}

	// Read: hidden by default, kept with IncludeRead.
	t1 := ivT0.Add(time.Hour)
	if k, err := db.MarkNoticesRead(ctx, []string{"kisa-1", "kisa-unknown"}, "admin", t1); err != nil || k != 1 {
		t.Fatalf("mark read: %d %v", k, err)
	}
	if rows, total, err := db.ListNotices(ctx, store.NoticeFilter{}, scPage()); err != nil || len(rows) != 0 || total != 0 {
		t.Fatalf("read notice listed: %+v %v", rows, err)
	}
	n = ntOne(t)(db.ListNotices(ctx, store.NoticeFilter{IncludeRead: true}, scPage()))
	if n.Unread() || n.ReadAt == nil || !n.ReadAt.Equal(t1) || n.ReadBy != "admin" {
		t.Fatalf("read notice %+v", n)
	}
	if c, _ := db.CountNotices(ctx); c != (store.NoticeCounts{Total: 1}) {
		t.Fatalf("counts after read %+v", c)
	}

	// A new revision that keeps the link keeps it read.
	match(2, ivT0.Add(2*time.Hour), "kisa-1")
	if g, err := db.GetNotice(ctx, "kisa-1"); err != nil || g.Unread() {
		t.Fatalf("after re-match: %+v %v", g, err)
	}

	// An asset that starts matching after the read mark makes it unread
	// again; the mark stays to show why.
	app := ivHost(t, db, "app-01")
	_, err = db.ReplaceAssetComponents(ctx, store.ComponentScope{AssetID: app, Source: store.SourcePackages},
		ivPkgObs(openssl), store.ReplaceOptions{At: ivT0.Add(3 * time.Hour)})
	ivMust(t, err)
	n = ntOne(t)(db.ListNotices(ctx, store.NoticeFilter{}, scPage()))
	if n.Assets != 3 || n.NewAssets != 1 || n.ReadAt == nil || !n.LastMatched.Equal(ivT0.Add(3*time.Hour)) {
		t.Fatalf("reopened %+v", n)
	}
	ms, err = db.ListNoticeMatches(ctx, store.NoticeMatchFilter{NoticeID: "kisa-1"})
	ivMust(t, err)
	for _, m := range ms {
		if m.New != (m.AssetID == app) {
			t.Errorf("match of %s new %v", m.AssetName, m.New)
		}
	}
	ms, err = db.ListNoticeMatches(ctx, store.NoticeMatchFilter{AssetID: app})
	ivMust(t, err)
	if len(ms) != 1 || ms[0].NoticeID != "kisa-1" {
		t.Fatalf("matches of app-01 %+v", ms)
	}
	if _, err := db.ListNoticeMatches(ctx, store.NoticeMatchFilter{}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("matches without a filter: %v", err)
	}

	// Unread removes the mark.
	if k, err := db.MarkNoticesUnread(ctx, []string{"kisa-1"}); err != nil || k != 1 {
		t.Fatalf("mark unread: %d %v", k, err)
	}
	if n := ntOne(t)(db.ListNotices(ctx, store.NoticeFilter{}, scPage())); n.NewAssets != 3 || n.ReadAt != nil {
		t.Fatalf("unread %+v", n)
	}

	// A link that goes away and comes back is new.
	ivMust(t, db.SaveMatches(ctx, store.MatchBatch{Epoch: store.MatchEpoch{ServerID: srv.ID, Revision: 3},
		Components: []store.ComponentMatch{{ComponentID: sslID, Status: store.MatchChecked}}}))
	if rows, _, err := db.ListNotices(ctx, store.NoticeFilter{IncludeRead: true}, scPage()); err != nil || len(rows) != 0 {
		t.Fatalf("notices after a match without them: %+v %v", rows, err)
	}
	if _, err := db.GetNotice(ctx, "kisa-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unmatched notice: %v", err)
	}
	if k, err := db.MarkNoticesRead(ctx, []string{"kisa-1"}, "admin", t1); err != nil || k != 0 {
		t.Fatalf("mark unmatched notice read: %d %v", k, err)
	}
	match(4, ivT0.Add(4*time.Hour), "kisa-1")
	if n := ntOne(t)(db.ListNotices(ctx, store.NoticeFilter{}, scPage())); !n.FirstMatched.Equal(ivT0.Add(4 * time.Hour)) {
		t.Fatalf("relinked %+v", n)
	}

	// A removed installation or a gone asset does not count.
	_, err = db.ReplaceAssetComponents(ctx, store.ComponentScope{AssetID: app, Source: store.SourcePackages},
		nil, store.ReplaceOptions{At: ivT0.Add(5 * time.Hour)})
	ivMust(t, err)
	if n := ntOne(t)(db.ListNotices(ctx, store.NoticeFilter{}, scPage())); n.Assets != 2 {
		t.Fatalf("after removal %+v", n)
	}
}

// TestNoticeReadScopes checks that a read mark of one scope does not hide
// the notice from another.
func TestNoticeReadScopes(t *testing.T) {
	db, _, fa, fb := scSetup(t)
	ctxA := scope.With(ivCtx(t), scope.Of("a"))
	ctxB := scope.With(ivCtx(t), scope.Of("b"))
	all := ivCtx(t)
	// The fixture links notices at the current time.
	now := time.Now().Add(time.Minute)

	if k, err := db.MarkNoticesRead(ctxA, []string{"kisa-shared", fb.NoticeID}, "alice", now); err != nil || k != 1 {
		t.Fatalf("mark read in a: %d %v", k, err)
	}
	if g, err := db.GetNotice(ctxA, "kisa-shared"); err != nil || g.Unread() || g.ReadBy != "alice" || g.Assets != 1 {
		t.Fatalf("shared notice in a: %+v %v", g, err)
	}
	if g, err := db.GetNotice(ctxB, "kisa-shared"); err != nil || !g.Unread() || g.ReadAt != nil {
		t.Fatalf("shared notice in b: %+v %v", g, err)
	}
	if g, err := db.GetNotice(all, "kisa-shared"); err != nil || g.Assets != 2 || g.NewAssets != 1 || g.ReadBy != "alice" {
		t.Fatalf("shared notice for all: %+v %v", g, err)
	}
	if g, err := db.GetNotice(ctxB, fb.NoticeID); err != nil || !g.Unread() {
		t.Fatalf("own notice of b: %+v %v", g, err)
	}
	// Unread in b does not remove a's mark; All marks every scope.
	if k, err := db.MarkNoticesUnread(ctxB, []string{"kisa-shared"}); err != nil || k != 0 {
		t.Fatalf("unread in b: %d %v", k, err)
	}
	if g, _ := db.GetNotice(ctxA, "kisa-shared"); g.Unread() {
		t.Fatal("b removed the mark of a")
	}
	if k, err := db.MarkNoticesRead(all, []string{"kisa-shared", fa.NoticeID}, "root", now); err != nil || k != 2 {
		t.Fatalf("mark read for all: %d %v", k, err)
	}
	if g, _ := db.GetNotice(ctxB, "kisa-shared"); g.Unread() || g.ReadBy != "root" {
		t.Fatalf("shared notice in b after All: %+v", g)
	}
	if c, err := db.CountNotices(ctxB); err != nil || c != (store.NoticeCounts{Total: 2, Unread: 1}) {
		t.Fatalf("counts of b %+v %v", c, err)
	}
}
