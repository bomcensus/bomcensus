// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package vulnsvc

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/feedsvc"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

func deb(id, name string) store.Component {
	return store.Component{ID: id, Type: "deb", Name: name, Version: "1.0", Distro: "ubuntu-24.04",
		PURL: "pkg:deb/ubuntu/" + name + "@1.0?arch=amd64&distro=ubuntu-24.04", SourceName: name + "-src", SourceVersion: "1.0",
		Origin: store.OriginDistro}
}

func TestOSOf(t *testing.T) {
	for _, tc := range []struct {
		c    store.Component
		want *targetOS
	}{
		{deb("a", "openssl"), &targetOS{ID: "ubuntu", VersionID: "24.04"}},
		{store.Component{Type: "rpm", Distro: "opensuse-leap-15.5", PURL: "pkg:rpm/opensuse-leap/bash@5.2?distro=opensuse-leap-15.5"},
			&targetOS{ID: "opensuse-leap", VersionID: "15.5"}},
		{store.Component{Type: "deb", Distro: "debian", PURL: "pkg:deb/debian/bash@5.2"}, &targetOS{ID: "debian"}},
		{store.Component{Type: "deb", PURL: "pkg:deb/unknown/bash@5.2"}, nil},
		{store.Component{Type: "maven", PURL: "pkg:maven/org.apache/x@1"}, nil},
		{store.Component{Type: "rpm", PURL: "pkg:generic/x@1"}, nil},
	} {
		got, ok := osOf(tc.c)
		if (tc.want == nil) != !ok || (ok && got != *tc.want) {
			t.Errorf("%s: %+v %v, want %+v", tc.c.PURL, got, ok, tc.want)
		}
	}
}

func TestBuildRequest(t *testing.T) {
	jar := store.Component{ID: "j", Type: "maven", PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		SourceName: "ignored", Origin: store.OriginUpstream}
	bin := store.Component{ID: "b", Type: "binary", Name: "nginx", CPE: "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"}
	alpine := store.Component{ID: "a", Type: "apk", Distro: "alpine-3.20", PURL: "pkg:apk/alpine/musl@1.2.5-r0?distro=alpine-3.20"}
	req := buildRequest([]store.Component{deb("d1", "openssl"), jar, alpine, deb("d2", "curl"), bin})
	if len(req.Targets) != 3 {
		t.Fatalf("targets %+v", req.Targets)
	}
	ub, plain, al := req.Targets[0], req.Targets[1], req.Targets[2]
	if ub.ID != "t0" || *ub.OS != (targetOS{ID: "ubuntu", VersionID: "24.04"}) || len(ub.Components) != 2 ||
		ub.Components[0].Source.Name != "openssl-src" || ub.Components[0].Origin != "distro" {
		t.Fatalf("ubuntu target %+v", ub)
	}
	if plain.OS != nil || len(plain.Components) != 2 || plain.Components[0].Source != nil || plain.Components[0].Origin != "" ||
		plain.Components[1].CPE == "" {
		t.Fatalf("plain target %+v", plain)
	}
	if al.OS.ID != "alpine" || al.Components[0].Source != nil {
		t.Fatalf("alpine target %+v", al)
	}
	// Only identifiers travel: no asset, host or location data.
	raw, _ := json.Marshal(req)
	for _, field := range []string{"asset", "host", "location", "name\":\"nginx"} {
		if strings.Contains(string(raw), field) {
			t.Errorf("request contains %q: %s", field, raw)
		}
	}
}

// memStore is an in-memory Store.
type memStore struct {
	mu      sync.Mutex
	comps   []store.Component
	matched map[string]store.MatchEpoch
	batches []store.MatchBatch
}

func (s *memStore) PendingMatches(_ context.Context, e store.MatchEpoch, limit int) ([]store.Component, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []store.Component
	for _, c := range s.comps {
		m, ok := s.matched[c.ID]
		if ok && m.ServerID == e.ServerID && m.Revision >= e.Revision && m.Rules == e.Rules {
			continue
		}
		out = append(out, c)
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

func (s *memStore) SaveMatches(_ context.Context, b store.MatchBatch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range b.Components {
		s.matched[c.ComponentID] = b.Epoch
	}
	s.batches = append(s.batches, b)
	return nil
}

func (s *memStore) ResetMatches(context.Context, string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.matched = map[string]store.MatchEpoch{}
	return nil
}

// fakeFeed answers match requests with reply.
type fakeFeed struct {
	mu       sync.Mutex
	none     bool
	revision int64
	requests []matchRequest
	encoding []string
	reply    func(n int, req matchRequest) (*http.Response, error)
	reported []error
}

func (f *fakeFeed) Session(context.Context) (store.FeedServer, http.RoundTripper, error) {
	if f.none {
		return store.FeedServer{}, nil, feedsvc.ErrNoServer
	}
	return store.FeedServer{ID: "srv", URL: "https://feed.example"}, f, nil
}

func (f *fakeFeed) Report(_ context.Context, _ store.FeedServer, err error) {
	f.mu.Lock()
	f.reported = append(f.reported, err)
	f.mu.Unlock()
}

func (f *fakeFeed) RefreshData(context.Context, store.FeedServer, http.RoundTripper) (store.FeedData, error) {
	return store.FeedData{Revision: f.revision, RulesDigest: "r"}, nil
}

func (f *fakeFeed) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.String() != "https://feed.example/v1/match" {
		return nil, errors.New("unexpected url " + r.URL.String())
	}
	body := io.Reader(r.Body)
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			return nil, err
		}
		body = zr
	}
	var req matchRequest
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.requests = append(f.requests, req)
	f.encoding = append(f.encoding, r.Header.Get("Content-Encoding"))
	n := len(f.requests)
	f.mu.Unlock()
	return f.reply(n, req)
}

func jsonResponse(status int, v any) *http.Response {
	b, _ := json.Marshal(v)
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(b))}
}

// answer marks every component checked; "openssl" gets CVE-2024-1.
func answer(revision int64) func(int, matchRequest) (*http.Response, error) {
	return func(_ int, req matchRequest) (*http.Response, error) {
		res := map[string]any{"data": map[string]any{"revision": revision, "rules": "r"}}
		var targets []map[string]any
		for _, t := range req.Targets {
			var comps []map[string]any
			for _, c := range t.Components {
				cr := map[string]any{"ref": c.Ref, "status": "checked", "matches": []any{}}
				if strings.Contains(c.PURL, "openssl") {
					cr["matches"] = []any{map[string]any{"vuln_id": "CVE-2024-1", "method": "package", "ecosystem": "ubuntu:24.04",
						"fix_state": "fixed", "fixed_version": "1.1", "advisories": []any{map[string]any{"source": "osv", "id": "UBUNTU-CVE-2024-1"}}}}
				}
				comps = append(comps, cr)
			}
			targets = append(targets, map[string]any{"id": t.ID, "os_key": "ubuntu:24.04", "components": comps})
		}
		res["targets"] = targets
		res["vulnerabilities"] = map[string]any{"CVE-2024-1": map[string]any{"id": "CVE-2024-1", "summary": "bad",
			"cvss": []any{map[string]any{"version": "3.1", "vector": "CVSS:3.1/AV:N", "score": 7.5}, map[string]any{"version": "4.0", "vector": "CVSS:4.0/AV:N", "score": 9.1}},
			"kev":  map[string]any{"date_added": "2024-07-01"}, "epss": map[string]any{"score": 0.5, "percentile": 0.9}}}
		return jsonResponse(http.StatusOK, res), nil
	}
}

func newMatcher(t *testing.T, st *memStore, feed *fakeFeed) *Matcher {
	t.Helper()
	m, err := New(Config{Store: st, Feed: feed, BatchSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestRun(t *testing.T) {
	st := &memStore{comps: []store.Component{deb("1", "openssl"), deb("2", "curl"), deb("3", "bash")}, matched: map[string]store.MatchEpoch{}}
	feed := &fakeFeed{revision: 5, reply: answer(5)}
	m := newMatcher(t, st, feed)
	if err := m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(feed.requests) != 2 || feed.encoding[0] != "gzip" {
		t.Fatalf("requests %d, encoding %v", len(feed.requests), feed.encoding)
	}
	if len(st.batches) != 2 || st.batches[0].Epoch != (store.MatchEpoch{ServerID: "srv", Revision: 5, Rules: "r"}) {
		t.Fatalf("batches %+v", st.batches)
	}
	first := st.batches[0]
	sort.Slice(first.Components, func(i, j int) bool { return first.Components[i].ComponentID < first.Components[j].ComponentID })
	if c := first.Components[0]; c.ComponentID != "1" || c.OSKey != "ubuntu:24.04" || len(c.Vulns) != 1 || c.Vulns[0].FixedVersion != "1.1" {
		t.Fatalf("openssl %+v", c)
	}
	if len(first.Vulns) != 1 {
		t.Fatalf("vulns %+v", first.Vulns)
	}
	v := first.Vulns[0]
	if *v.MaxScore != 9.1 || v.Severity != "critical" || v.KEV == nil || *v.EPSS != 0.5 || len(v.CVSS) != 2 {
		t.Fatalf("meta %+v", v)
	}

	// Nothing pending: no request.
	if err := m.Run(context.Background()); err != nil || len(feed.requests) != 2 {
		t.Fatalf("second run: %v, %d requests", err, len(feed.requests))
	}
	// A new revision matches everything again.
	feed.revision = 6
	feed.reply = answer(6)
	if err := m.Run(context.Background()); err != nil || len(feed.requests) != 4 {
		t.Fatalf("new revision: %v, %d requests", err, len(feed.requests))
	}
}

func TestRevisionMovesDuringRun(t *testing.T) {
	st := &memStore{comps: []store.Component{deb("1", "openssl"), deb("2", "curl"), deb("3", "bash")}, matched: map[string]store.MatchEpoch{}}
	feed := &fakeFeed{revision: 5}
	feed.reply = func(n int, req matchRequest) (*http.Response, error) {
		if n == 1 {
			return answer(5)(n, req)
		}
		return answer(6)(n, req)
	}
	m := newMatcher(t, st, feed)
	if err := m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The first batch is matched again against revision 6.
	for id, e := range st.matched {
		if e.Revision != 6 {
			t.Errorf("%s matched at %d", id, e.Revision)
		}
	}
	if len(feed.requests) != 3 {
		t.Fatalf("requests %d", len(feed.requests))
	}
}

func TestRateLimit(t *testing.T) {
	st := &memStore{comps: []store.Component{deb("1", "openssl")}, matched: map[string]store.MatchEpoch{}}
	feed := &fakeFeed{revision: 5}
	limited := func(after string) func(int, matchRequest) (*http.Response, error) {
		return func(n int, req matchRequest) (*http.Response, error) {
			if n == 1 {
				r := jsonResponse(http.StatusTooManyRequests, map[string]string{"code": "rate_limited", "message": "slow down"})
				r.Header.Set("Retry-After", after)
				return r, nil
			}
			return answer(5)(n, req)
		}
	}
	// A short wait is slept through.
	feed.reply = limited("2")
	m := newMatcher(t, st, feed)
	var slept time.Duration
	m.sleep = func(_ context.Context, d time.Duration) error { slept += d; return nil }
	if err := m.Run(context.Background()); err != nil || slept != 2*time.Second || len(st.batches) != 1 {
		t.Fatalf("short wait: %v, slept %s, %d batches", err, slept, len(st.batches))
	}
	// A long one snoozes the job.
	st.matched = map[string]store.MatchEpoch{}
	feed.requests = nil
	feed.reply = limited("3600")
	err := m.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "snoozed for 1h0m0s") {
		t.Fatalf("long wait: %v", err)
	}
	if len(feed.reported) != 0 {
		t.Fatalf("rate limit reported as a failure: %v", feed.reported)
	}
}

func TestRunErrors(t *testing.T) {
	st := &memStore{comps: []store.Component{deb("1", "openssl")}, matched: map[string]store.MatchEpoch{}}
	if err := newMatcher(t, st, &fakeFeed{none: true}).Run(context.Background()); err != nil {
		t.Fatalf("no server: %v", err)
	}
	feed := &fakeFeed{revision: 1, reply: func(int, matchRequest) (*http.Response, error) {
		return jsonResponse(http.StatusInternalServerError, map[string]string{"code": "internal", "message": "boom"}), nil
	}}
	if err := newMatcher(t, st, feed).Run(context.Background()); err == nil || len(feed.reported) != 1 {
		t.Fatalf("server error: %v, reported %v", err, feed.reported)
	}
	// A response that leaves a component out is rejected.
	feed.reply = func(int, matchRequest) (*http.Response, error) {
		return jsonResponse(http.StatusOK, map[string]any{"data": map[string]any{"revision": 1}, "targets": []any{}, "vulnerabilities": map[string]any{}}), nil
	}
	if err := newMatcher(t, st, feed).Run(context.Background()); err == nil || !strings.Contains(err.Error(), "misses 1") {
		t.Fatalf("incomplete response: %v", err)
	}
	if len(st.batches) != 0 {
		t.Fatalf("saved %+v", st.batches)
	}
}

func TestDistroRating(t *testing.T) {
	adv := func(sev ...string) []store.VulnAdvisory {
		var out []store.VulnAdvisory
		for _, s := range sev {
			out = append(out, store.VulnAdvisory{Source: "osv", ID: "X", Severity: s})
		}
		return out
	}
	for _, c := range []struct {
		advs []store.VulnAdvisory
		want string
	}{
		{adv("unimportant"), store.SeverityNegligible},
		{adv(" Unimportant "), store.SeverityNegligible},
		{adv("low*"), "low"},
		{adv("Moderate"), "medium"},
		{adv("important"), "high"},
		{adv("unimportant", "", "medium"), "medium"},
		{adv("not yet assigned"), ""},
		{adv("end-of-life"), ""},
		{adv(""), ""},
		{nil, ""},
	} {
		if got := DistroRating(c.advs); got != c.want {
			t.Errorf("DistroRating(%+v) = %q, want %q", c.advs, got, c.want)
		}
	}
}

func TestConvertRatesPackageMatches(t *testing.T) {
	res := &matchResult{
		Targets: []targetResult{{ID: "t0", Components: []componentResult{{Ref: "c1", Status: "checked", Matches: []match{
			{VulnID: "CVE-1", Method: "package", Advisories: []store.VulnAdvisory{{Source: "osv", ID: "DEBIAN-CVE-1", Severity: "unimportant"}}},
			{VulnID: "CVE-1", Method: "cpe", Advisories: []store.VulnAdvisory{{Source: "nvd", ID: "CVE-1", Severity: "unimportant"}}},
		}}}}},
		Vulnerabilities: map[string]vulnerability{"CVE-1": {ID: "CVE-1"}},
	}
	b, err := convert(res, []store.Component{{ID: "c1"}}, store.MatchEpoch{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	vs := b.Components[0].Vulns
	if vs[0].Severity != store.SeverityNegligible || vs[1].Severity != "" {
		t.Fatalf("severities %q %q", vs[0].Severity, vs[1].Severity)
	}
}
