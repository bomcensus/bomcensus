// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package vulnsvc

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

// answerNotices is answer with notices: the CPE component gets kisa-6219
// (twice), a reference without details and one with a malformed id.
func answerNotices(revision int64) func(int, matchRequest) (*http.Response, error) {
	return func(_ int, req matchRequest) (*http.Response, error) {
		var targets []map[string]any
		for _, t := range req.Targets {
			var comps []map[string]any
			for _, c := range t.Components {
				cr := map[string]any{"ref": c.Ref, "status": "checked", "matches": []any{}}
				if strings.Contains(c.CPE, "genians") {
					cr["notices"] = []string{"kisa-6219", "kisa-6219", "kisa-missing", "bad id"}
				}
				comps = append(comps, cr)
			}
			targets = append(targets, map[string]any{"id": t.ID, "components": comps})
		}
		return jsonResponse(http.StatusOK, map[string]any{
			"data":            map[string]any{"revision": revision, "rules": "r"},
			"targets":         targets,
			"vulnerabilities": map[string]any{},
			"notices": []any{
				map[string]any{"id": "kisa-6219", "source": "kisa", "title": " 지니언스 NAC 보안 업데이트 권고 ",
					"url": "https://knvd.krcert.or.kr/detailSecNo.do?IDX=6219", "published": "2026-03-04T00:00:00+09:00",
					"summary": "Genian NAC fixes a command injection.", "cve_ids": []string{"CVE-2026-1000", "", "CVE-2026-1000"},
					"advisory_ids": []string{"KVE-2026-0001"},
					"software": []any{map[string]any{"vendor": "지니언스", "product": "Genian NAC", "cpe_vendor": "genians",
						"cpe_product": "genian_nac", "affected": "6.0.0 ~ 6.0.41", "fixed": "6.0.42"}},
					"updated": "not a time"},
				map[string]any{"id": "bad id", "source": "kisa", "title": "x"},
				map[string]any{"id": "tmaxsoft-1", "source": "tmaxsoft", "title": "unused", "url": "javascript:alert(1)"},
			},
		}), nil
	}
}

func TestRunNotices(t *testing.T) {
	nac := store.Component{ID: "n", Type: "binary", Name: "genian-nac", CPE: "cpe:2.3:a:genians:genian_nac:6.0.40:*:*:*:*:*:*:*"}
	st := &memStore{comps: []store.Component{nac, deb("1", "openssl")}, matched: map[string]store.MatchEpoch{}}
	feed := &fakeFeed{revision: 3, reply: answerNotices(3)}
	if err := newMatcher(t, st, feed).Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(st.batches) != 1 {
		t.Fatalf("batches %+v", st.batches)
	}
	b := st.batches[0]
	byID := map[string]store.ComponentMatch{}
	for _, c := range b.Components {
		byID[c.ComponentID] = c
	}
	if got := byID["n"].Notices; len(got) != 1 || got[0] != "kisa-6219" {
		t.Fatalf("notices of the CPE component %v", got)
	}
	if got := byID["1"].Notices; got != nil {
		t.Fatalf("notices of openssl %v", got)
	}
	// Only referenced notices are kept.
	if len(b.Notices) != 1 {
		t.Fatalf("batch notices %+v", b.Notices)
	}
	n := b.Notices[0]
	published := time.Date(2026, 3, 3, 15, 0, 0, 0, time.UTC)
	if n.ID != "kisa-6219" || n.Source != "kisa" || n.Title != "지니언스 NAC 보안 업데이트 권고" ||
		n.URL != "https://knvd.krcert.or.kr/detailSecNo.do?IDX=6219" || n.Published == nil || !n.Published.Equal(published) ||
		n.Modified != nil || len(n.CVEIDs) != 1 || n.CVEIDs[0] != "CVE-2026-1000" ||
		n.AdvisoryIDs[0] != "KVE-2026-0001" || len(n.Software) != 1 || n.Software[0].CPEProduct != "genian_nac" ||
		n.Software[0].Fixed != "6.0.42" {
		t.Fatalf("notice %+v", n)
	}
}

// TestRunWithoutNotices: a feed server without notices still matches, and
// the components then have none (their earlier notices are replaced).
func TestRunWithoutNotices(t *testing.T) {
	st := &memStore{comps: []store.Component{deb("1", "openssl")}, matched: map[string]store.MatchEpoch{}}
	feed := &fakeFeed{revision: 5, reply: answer(5)}
	if err := newMatcher(t, st, feed).Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	b := st.batches[0]
	if len(b.Notices) != 0 || b.Components[0].Notices != nil || len(b.Components[0].Vulns) != 1 {
		t.Fatalf("batch %+v", b)
	}
}

func TestNoticeCleaning(t *testing.T) {
	for in, want := range map[string]string{
		"https://example.com/a?b=c": "https://example.com/a?b=c",
		"http://example.com":        "http://example.com",
		"javascript:alert(1)":       "",
		"//example.com/x":           "",
		"ftp://example.com/x":       "",
		"https:///x":                "",
		" https://example.com ":     "https://example.com",
	} {
		if got := webURL(in); got != want {
			t.Errorf("webURL(%q) = %q, want %q", in, got, want)
		}
	}
	if got := clean("a\x00b "+strings.Repeat("가", 10), 5); got != "ab 가가" {
		t.Errorf("clean: %q", got)
	}
	if parseTime("2026-01-02") == nil || parseTime("2026-01-02T03:04:05Z") == nil || parseTime("yesterday") != nil {
		t.Error("parseTime")
	}
	ns := noticesByID([]notice{{ID: "kisa-1", Source: "KISA"}, {ID: "kisa-2", Source: "kisa"}, {ID: "kisa-2", Source: "kisa", Title: "second"}})
	if _, ok := ns["kisa-1"]; ok || len(ns) != 1 || ns["kisa-2"].Title != "" {
		t.Errorf("noticesByID %+v", ns)
	}
}
