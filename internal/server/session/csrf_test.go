// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package session

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCheckCSRF(t *testing.T) {
	cases := []struct {
		name    string
		trust   bool
		method  string
		host    string
		headers map[string]string
		ok      bool
	}{
		{"get needs nothing", false, http.MethodGet, "console.example", nil, true},
		{"head needs nothing", false, http.MethodHead, "console.example", map[string]string{"Origin": "https://evil.example"}, true},
		{"post without header", false, http.MethodPost, "console.example", nil, false},
		{"post with wrong header value", false, http.MethodPost, "console.example", map[string]string{"X-Requested-With": "XMLHttpRequest"}, false},
		{"post with header only", false, http.MethodPost, "console.example", map[string]string{"X-Requested-With": "bomcensus"}, true},
		{"same origin", false, http.MethodPost, "console.example:8080", map[string]string{
			"X-Requested-With": "bomcensus", "Origin": "http://console.example:8080"}, true},
		{"default port", false, http.MethodDelete, "console.example:443", map[string]string{
			"X-Requested-With": "bomcensus", "Origin": "https://Console.Example"}, true},
		{"other origin", false, http.MethodPost, "console.example", map[string]string{
			"X-Requested-With": "bomcensus", "Origin": "https://evil.example"}, false},
		{"other port", false, http.MethodPost, "console.example:8080", map[string]string{
			"X-Requested-With": "bomcensus", "Origin": "http://console.example:9090"}, false},
		{"null origin", false, http.MethodPost, "console.example", map[string]string{
			"X-Requested-With": "bomcensus", "Origin": "null"}, false},
		{"referer same", false, http.MethodPatch, "console.example", map[string]string{
			"X-Requested-With": "bomcensus", "Referer": "https://console.example/assets"}, true},
		{"referer other", false, http.MethodPut, "console.example", map[string]string{
			"X-Requested-With": "bomcensus", "Referer": "https://evil.example/x"}, false},
		{"origin wins over referer", false, http.MethodPost, "console.example", map[string]string{
			"X-Requested-With": "bomcensus", "Origin": "https://evil.example", "Referer": "https://console.example/"}, false},
		{"forwarded host untrusted", false, http.MethodPost, "backend:8080", map[string]string{
			"X-Requested-With": "bomcensus", "Origin": "https://console.example", "X-Forwarded-Host": "console.example"}, false},
		{"forwarded host trusted", true, http.MethodPost, "backend:8080", map[string]string{
			"X-Requested-With": "bomcensus", "Origin": "https://console.example", "X-Forwarded-Host": "console.example"}, true},
	}
	for _, c := range cases {
		s, _, _ := newTestService(c.trust)
		r := httptest.NewRequest(c.method, "/api/v1/auth/login", nil)
		r.Host = c.host
		for k, v := range c.headers {
			r.Header.Set(k, v)
		}
		err := s.CheckCSRF(r)
		if c.ok && err != nil {
			t.Errorf("%s: rejected: %v", c.name, err)
		}
		if !c.ok && !errors.Is(err, ErrCSRF) {
			t.Errorf("%s: accepted (%v)", c.name, err)
		}
	}
}

func TestLimiter(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := NewLimiter(LimiterConfig{Now: func() time.Time { return now }})
	for i := 0; i < 4; i++ {
		if _, ok := l.Attempt("addr:a", "user:x"); !ok {
			t.Fatalf("attempt %d blocked", i)
		}
	}
	// The fifth attempt goes through and starts the lockout.
	if _, ok := l.Attempt("addr:a", "user:x"); !ok {
		t.Fatal("fifth attempt blocked")
	}
	if wait, ok := l.Attempt("addr:b", "user:x"); ok || wait != 30*time.Second {
		t.Fatalf("username not locked: %v %v", wait, ok)
	}
	if wait, ok := l.Attempt("addr:a", "user:y"); ok || wait != 30*time.Second {
		t.Fatalf("address not locked: %v %v", wait, ok)
	}
	if _, ok := l.Attempt("addr:c", "user:z"); !ok {
		t.Fatal("unrelated keys blocked")
	}

	// Each further failure doubles the lockout.
	now = now.Add(30 * time.Second)
	if _, ok := l.Attempt("addr:a", "user:x"); !ok {
		t.Fatal("not unlocked after lockout")
	}
	if wait, _ := l.Attempt("addr:a", "user:x"); wait != time.Minute {
		t.Fatalf("second lockout %v", wait)
	}
	for i := 0; i < 20; i++ {
		now = now.Add(time.Hour - time.Second)
		l.Attempt("addr:a", "user:x")
	}
	if wait, _ := l.Attempt("addr:a", "user:x"); wait > 15*time.Minute {
		t.Fatalf("lockout above maximum: %v", wait)
	}

	// Success clears; a long quiet period forgets.
	l.Succeeded("addr:a", "user:x")
	if _, ok := l.Attempt("addr:a", "user:x"); !ok {
		t.Fatal("not cleared by success")
	}
}

func TestLimiterBounded(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := NewLimiter(LimiterConfig{MaxEntries: 10, Now: func() time.Time { return now }})
	for i := 0; i < 100; i++ {
		l.Attempt("user:" + string(rune('a'+i%26)) + string(rune('a'+i/26)))
	}
	if n := len(l.entries); n > 11 {
		t.Fatalf("%d entries kept", n)
	}
}
