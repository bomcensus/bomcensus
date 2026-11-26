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
	"github.com/bomcensus/bomcensus/server/scope"
)

// seedNotices links kisa-100 to openssl (on web-1 and db-1).
func seedNotices(t *testing.T) *fixture {
	t.Helper()
	f := seed(t)
	srv, err := f.db.GetActiveFeedServer(f.ctx)
	must(t, err)
	epoch := store.MatchEpoch{ServerID: srv.ID, Revision: 1}
	pending, err := f.db.PendingMatches(f.ctx, epoch, 100)
	must(t, err)
	var batch []store.ComponentMatch
	for _, c := range pending {
		m := store.ComponentMatch{ComponentID: c.ID, Status: store.MatchChecked}
		if c.Name == "openssl" {
			m.Notices = []string{"kisa-100"}
		}
		batch = append(batch, m)
	}
	must(t, f.db.SaveMatches(f.ctx, store.MatchBatch{Epoch: epoch, At: t0, Components: batch, Notices: []store.Notice{{
		ID: "kisa-100", Source: "kisa", Title: "OpenSSL 보안 업데이트 권고", URL: "https://knvd.example/100",
		Summary: "Buffer overflow.", CVEIDs: []string{"CVE-2026-1"},
		Software: []store.NoticeSoftware{{Vendor: "OpenSSL", Product: "OpenSSL", CPEVendor: "openssl", CPEProduct: "openssl",
			Affected: "3.0.0 ~ 3.0.13", Fixed: "3.0.14"}},
	}}}))
	return f
}

func TestNoticeHandlers(t *testing.T) {
	f := seedNotices(t)
	h, ctx := f.h, f.ctx

	r, err := h.ListNotices(ctx, gen.ListNoticesRequestObject{})
	must(t, err)
	l := r.(gen.ListNotices200JSONResponse)
	if l.Total != 1 || len(l.Items) != 1 {
		t.Fatalf("list %+v", l)
	}
	n := l.Items[0]
	if n.NoticeId != "kisa-100" || n.Assets != 2 || n.NewAssets != 2 || !n.Unread || n.ReadAt != nil ||
		*n.Url != "https://knvd.example/100" || len(n.Software) != 1 || *n.Software[0].Fixed != "3.0.14" ||
		n.RelatedCveIds == nil || n.CveIds[0] != "CVE-2026-1" {
		t.Fatalf("notice %+v", n)
	}
	s, err := h.GetNoticeSummary(ctx, gen.GetNoticeSummaryRequestObject{})
	must(t, err)
	if s.(gen.GetNoticeSummary200JSONResponse) != (gen.GetNoticeSummary200JSONResponse{Total: 1, Unread: 1}) {
		t.Fatalf("summary %+v", s)
	}

	d, err := h.GetNotice(ctx, gen.GetNoticeRequestObject{NoticeId: "kisa-100"})
	must(t, err)
	det := d.(gen.GetNotice200JSONResponse)
	if got := names(det.Matches, func(m gen.NoticeMatch) string { return m.AssetName + ":" + m.ComponentName }); got != "db-1:openssl,web-1:openssl" {
		t.Fatalf("matches %s", got)
	}
	if m := det.Matches[1]; m.AssetId != f.web || !m.New || m.Container != nil || len(m.Locations) != 1 || !m.FirstSeen.Equal(t0) {
		t.Fatalf("match %+v", m)
	}
	for _, id := range []string{"kisa-404", "", strings.Repeat("x", 200)} {
		_, err = h.GetNotice(ctx, gen.GetNoticeRequestObject{NoticeId: id})
		wantStatus(t, "unknown notice "+id, err, http.StatusNotFound)
	}

	a, err := h.ListAssetNotices(ctx, gen.ListAssetNoticesRequestObject{Id: f.web})
	must(t, err)
	an := a.(gen.ListAssetNotices200JSONResponse)
	if len(an.Items) != 1 || an.Items[0].Notice.Assets != 1 || len(an.Items[0].Matches) != 1 ||
		an.Items[0].Matches[0].ComponentName != "openssl" {
		t.Fatalf("asset notices %+v", an)
	}
	_, err = h.ListAssetNotices(ctx, gen.ListAssetNoticesRequestObject{Id: "00000000-0000-0000-0000-000000000000"})
	wantStatus(t, "unknown asset", err, http.StatusNotFound)

	// Bad requests.
	many := make([]string, store.MaxNoticeIDs+1)
	for i := range many {
		many[i] = "kisa-100"
	}
	for name, b := range map[string]*gen.NoticeIds{
		"no body": nil, "no ids": {}, "too many": {Ids: many}, "empty id": {Ids: []string{""}},
		"long id": {Ids: []string{strings.Repeat("x", 129)}},
	} {
		_, err := h.MarkNoticesRead(ctx, gen.MarkNoticesReadRequestObject{Body: b})
		wantStatus(t, "read: "+name, err, http.StatusBadRequest)
		_, err = h.MarkNoticesUnread(ctx, gen.MarkNoticesUnreadRequestObject{Body: b})
		wantStatus(t, "unread: "+name, err, http.StatusBadRequest)
	}

	// Another scope sees nothing and marks nothing.
	other := scope.With(ctx, scope.Of("other"))
	r, err = h.ListNotices(other, gen.ListNoticesRequestObject{Params: gen.ListNoticesParams{IncludeRead: ptr(true)}})
	must(t, err)
	if l := r.(gen.ListNotices200JSONResponse); l.Total != 0 {
		t.Fatalf("other scope lists %+v", l)
	}
	_, err = h.GetNotice(other, gen.GetNoticeRequestObject{NoticeId: "kisa-100"})
	wantStatus(t, "notice of another scope", err, http.StatusNotFound)
	_, err = h.ListAssetNotices(other, gen.ListAssetNoticesRequestObject{Id: f.web})
	wantStatus(t, "asset of another scope", err, http.StatusNotFound)
	u, err := h.MarkNoticesRead(other, gen.MarkNoticesReadRequestObject{Body: &gen.NoticeIds{Ids: []string{"kisa-100"}}})
	must(t, err)
	if u.(gen.MarkNoticesRead200JSONResponse).Updated != 0 {
		t.Fatalf("other scope marked %+v", u)
	}

	// Read: hidden from the default list, with who read it.
	u, err = h.MarkNoticesRead(ctx, gen.MarkNoticesReadRequestObject{Body: &gen.NoticeIds{Ids: []string{"kisa-100", "kisa-100", "kisa-404"}}})
	must(t, err)
	if u.(gen.MarkNoticesRead200JSONResponse).Updated != 1 {
		t.Fatalf("marked %+v", u)
	}
	r, err = h.ListNotices(ctx, gen.ListNoticesRequestObject{})
	must(t, err)
	if l := r.(gen.ListNotices200JSONResponse); l.Total != 0 {
		t.Fatalf("read notice listed %+v", l)
	}
	r, err = h.ListNotices(ctx, gen.ListNoticesRequestObject{Params: gen.ListNoticesParams{IncludeRead: ptr(true), Source: ptr("kisa"),
		Q: ptr("openssl")}})
	must(t, err)
	l = r.(gen.ListNotices200JSONResponse)
	if l.Total != 1 || l.Items[0].Unread || l.Items[0].ReadBy == nil || *l.Items[0].ReadBy != "admin" || !l.Items[0].ReadAt.Equal(t0) {
		t.Fatalf("read notice %+v", l)
	}
	_, err = h.ListNotices(ctx, gen.ListNoticesRequestObject{Params: gen.ListNoticesParams{Source: ptr(strings.Repeat("k", 33))}})
	wantStatus(t, "long source", err, http.StatusBadRequest)

	u2, err := h.MarkNoticesUnread(ctx, gen.MarkNoticesUnreadRequestObject{Body: &gen.NoticeIds{Ids: []string{"kisa-100"}}})
	must(t, err)
	if u2.(gen.MarkNoticesUnread200JSONResponse).Updated != 1 {
		t.Fatalf("unmarked %+v", u2)
	}
	s, err = h.GetNoticeSummary(ctx, gen.GetNoticeSummaryRequestObject{})
	must(t, err)
	if s.(gen.GetNoticeSummary200JSONResponse).Unread != 1 {
		t.Fatalf("summary after unread %+v", s)
	}
}
