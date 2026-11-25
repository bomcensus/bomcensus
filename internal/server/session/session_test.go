// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package session

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/server/auth"
)

// fakeSessions is an in-memory store.Sessions.
type fakeSessions struct {
	mu   sync.Mutex
	byID map[string]store.Session
}

func newFakeSessions() *fakeSessions { return &fakeSessions{byID: map[string]store.Session{}} }

func (f *fakeSessions) CreateSession(_ context.Context, pid, pname string, exp time.Time) (store.Session, error) {
	var b [32]byte
	_, _ = rand.Read(b[:])
	s := store.Session{ID: base64.RawURLEncoding.EncodeToString(b[:]), PrincipalID: pid, PrincipalName: pname,
		CreatedAt: time.Now(), ExpiresAt: exp}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byID[s.ID] = s
	return s, nil
}

func (f *fakeSessions) GetSession(_ context.Context, id string, now time.Time) (store.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.byID[id]
	if !ok || !s.ExpiresAt.After(now) {
		return store.Session{}, store.ErrNotFound
	}
	return s, nil
}

func (f *fakeSessions) DeleteSession(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.byID, id)
	return nil
}

func (f *fakeSessions) DeleteExpiredSessions(_ context.Context, now time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var n int64
	for id, s := range f.byID {
		if !s.ExpiresAt.After(now) {
			delete(f.byID, id)
			n++
		}
	}
	return n, nil
}

// fakeProvider accepts admin / secret.
type fakeProvider struct{}

func (fakeProvider) Authenticate(_ context.Context, u, p string) (auth.Principal, error) {
	if u == "admin" && p == "secret" {
		return auth.User{UserID: "env:admin", UserName: "admin"}, nil
	}
	return nil, ErrInvalidCredentials
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTestService(trustProxy bool) (*Service, *fakeSessions, *clock) {
	sess := newFakeSessions()
	clk := &clock{t: time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)}
	return NewService(Config{Provider: fakeProvider{}, Sessions: sess, TrustProxy: trustProxy, Now: clk.now}), sess, clk
}

func reqCtx(s *Service, r *http.Request) context.Context {
	ctx, err := s.Resolve(r)
	if err != nil {
		panic(err)
	}
	return ctx
}

func TestSessionRoundTrip(t *testing.T) {
	s, sess, clk := newTestService(false)
	login := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	p, cookie, err := s.Login(reqCtx(s, login), "admin", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if p.ID() != "env:admin" {
		t.Fatalf("principal %v", p)
	}
	if cookie.Name != CookieName || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode ||
		cookie.Path != "/" || cookie.Secure {
		t.Fatalf("cookie flags: %+v", cookie)
	}
	if cookie.MaxAge != int(DefaultSessionLifetime.Seconds()) {
		t.Fatalf("MaxAge %d", cookie.MaxAge)
	}

	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	r.AddCookie(cookie)
	ctx := reqCtx(s, r)
	got, ok := auth.FromContext(ctx)
	if !ok || got != p {
		t.Fatalf("principal from cookie: %v %v", got, ok)
	}

	clear, err := s.Logout(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if clear.MaxAge >= 0 || clear.Value != "" || !clear.HttpOnly {
		t.Fatalf("clearing cookie: %+v", clear)
	}
	if len(sess.byID) != 0 {
		t.Fatal("session not deleted")
	}
	if _, ok := auth.FromContext(reqCtx(s, r)); ok {
		t.Fatal("deleted session still resolves")
	}

	// Expiry: no sliding, the session ends after the lifetime.
	_, cookie, _ = s.Login(reqCtx(s, login), "admin", "secret")
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(cookie)
	clk.t = clk.t.Add(DefaultSessionLifetime - time.Minute)
	if _, ok := auth.FromContext(reqCtx(s, r)); !ok {
		t.Fatal("session expired early")
	}
	clk.t = clk.t.Add(2 * time.Minute)
	if _, ok := auth.FromContext(reqCtx(s, r)); ok {
		t.Fatal("session did not expire")
	}
	if n, _ := s.PurgeExpired(context.Background()); n != 1 {
		t.Fatalf("purged %d", n)
	}

	// Garbage cookies resolve to no principal without an error.
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: CookieName, Value: "short"})
	if _, ok := auth.FromContext(reqCtx(s, r)); ok {
		t.Fatal("garbage cookie accepted")
	}
}

func TestLoginWrongPassword(t *testing.T) {
	s, sess, _ := newTestService(false)
	_, _, err := s.Login(reqCtx(s, httptest.NewRequest(http.MethodPost, "/", nil)), "admin", "nope")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("got %v", err)
	}
	if len(sess.byID) != 0 {
		t.Fatal("session created on failure")
	}
}

func TestCookieSecure(t *testing.T) {
	cases := []struct {
		name  string
		trust bool
		tls   bool
		proto string
		want  bool
	}{
		{"plain", false, false, "", false},
		{"tls", false, true, "", true},
		{"untrusted header", false, false, "https", false},
		{"trusted proxy https", true, false, "https", true},
		{"trusted proxy http", true, false, "http", false},
	}
	for _, c := range cases {
		s, _, _ := newTestService(c.trust)
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		if c.tls {
			r.TLS = &tls.ConnectionState{}
		}
		if c.proto != "" {
			r.Header.Set("X-Forwarded-Proto", c.proto)
		}
		_, cookie, err := s.Login(reqCtx(s, r), "admin", "secret")
		if err != nil {
			t.Fatal(err)
		}
		if cookie.Secure != c.want {
			t.Errorf("%s: Secure = %v", c.name, cookie.Secure)
		}
	}
}

func TestClientAddr(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:5555"
	r.Header.Add("X-Forwarded-For", "1.1.1.1, 2.2.2.2")
	r.Header.Add("X-Forwarded-For", "3.3.3.3")

	s, _, _ := newTestService(false)
	if got := auth.RequestInfoFrom(reqCtx(s, r)).ClientAddr; got != "10.0.0.1" {
		t.Errorf("untrusted: %q", got)
	}
	s, _, _ = newTestService(true)
	if got := auth.RequestInfoFrom(reqCtx(s, r)).ClientAddr; got != "3.3.3.3" {
		t.Errorf("trusted: %q", got)
	}
}

func TestLoginThrottled(t *testing.T) {
	s, _, clk := newTestService(false)
	ctx := reqCtx(s, httptest.NewRequest(http.MethodPost, "/", nil))
	for i := 0; i < 5; i++ {
		if _, _, err := s.Login(ctx, "admin", "bad"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	_, _, err := s.Login(ctx, "admin", "secret")
	var th *ThrottledError
	if !errors.As(err, &th) || th.RetryAfter != 30*time.Second {
		t.Fatalf("expected throttle, got %v", err)
	}
	clk.t = clk.t.Add(31 * time.Second)
	if _, _, err := s.Login(ctx, "admin", "secret"); err != nil {
		t.Fatalf("after lockout: %v", err)
	}
}
