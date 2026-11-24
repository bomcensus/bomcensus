// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package feedsvc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	feedprotocol "github.com/bomcensus/feed-protocol"
	"github.com/bomcensus/feed-protocol/handshake"
	"github.com/bomcensus/feed-protocol/instancekey"
	"github.com/bomcensus/feed-protocol/server"

	"github.com/bomcensus/bomcensus/internal/server/secret"
	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/internal/server/store/postgres"
)

func newTestDB(t testing.TB) *postgres.DB {
	t.Helper()
	base := os.Getenv("BOMCENSUS_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("BOMCENSUS_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	name := "bomcensus_test_" + hex.EncodeToString(b[:])
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		admin.Close(ctx)
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			t.Errorf("drop database: %v", err)
		}
		admin.Close(ctx)
	})
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	u.Path = "/" + name
	db, err := postgres.Open(ctx, u.String())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(db.Close)
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// fakeFeed implements the session endpoints and /v1/status.
type fakeFeed struct {
	mu       sync.Mutex
	key      *instancekey.PrivateKey
	sessions map[string]server.Session
	hellos   []handshake.Hello
	clients  []string
	beats    int
	revision int64
	interval int // heartbeat seconds handed out
}

func (f *fakeFeed) Session(_ context.Context, id string) (server.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sessions[id]
	if !ok {
		return server.Session{}, server.ErrUnknownSession
	}
	return s, nil
}

func (f *fakeFeed) setKey(k *instancekey.PrivateKey) {
	f.mu.Lock()
	f.key = k
	f.mu.Unlock()
}

func (f *fakeFeed) handler(t *testing.T) http.Handler {
	v := &server.Verifier{Sessions: f}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+feedprotocol.SessionPath, func(w http.ResponseWriter, r *http.Request) {
		ver, err := handshake.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			server.WriteError(w, http.StatusUnsupportedMediaType, feedprotocol.CodeUnsupportedProtocol, err.Error())
			return
		}
		msg, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		key := f.key
		f.mu.Unlock()
		resp, err := handshake.Read(ver, key, msg, nil)
		if err != nil {
			server.WriteError(w, http.StatusBadRequest, feedprotocol.CodeBadHandshake, err.Error())
			return
		}
		f.mu.Lock()
		interval := f.interval
		f.mu.Unlock()
		msg2, keys, err := resp.Accept(handshake.Welcome{SessionExpires: time.Now().Add(24 * time.Hour).Unix(), Heartbeat: interval, Grade: "anonymous"})
		if err != nil {
			t.Error(err)
			return
		}
		f.mu.Lock()
		f.hellos = append(f.hellos, resp.Hello())
		f.clients = append(f.clients, resp.Client().String())
		f.sessions[keys.SessionID] = server.Session{ID: keys.SessionID, InstanceID: resp.Client().String(),
			ClientToServer: keys.ClientToServer, ServerToClient: keys.ServerToClient}
		f.mu.Unlock()
		w.Header().Set("Content-Type", handshake.MediaType(resp.Version()))
		w.Write(msg2)
	})
	protected := http.NewServeMux()
	protected.HandleFunc("POST "+feedprotocol.HeartbeatPath, func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.beats++
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(feedprotocol.Heartbeat{SessionExpires: time.Now().Add(24 * time.Hour).Unix(), IdleTimeout: 900, Grade: "anonymous"})
	})
	protected.HandleFunc("DELETE "+feedprotocol.SessionPath, func(w http.ResponseWriter, r *http.Request) {
		s, _ := server.FromContext(r.Context())
		f.mu.Lock()
		delete(f.sessions, s.ID)
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	protected.HandleFunc("GET "+StatusPath, func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		rev := f.revision
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"revision":` + itoa(rev) + `,"rules":"64ae2f42c4d2b9f4","sources":[{"name":"osv/Debian","updated_at":"2026-11-24T05:17:00Z","healthy":true}]}`))
	})
	mux.Handle("/", v.Middleware(protected))
	return mux
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

type fixture struct {
	db   *postgres.DB
	feed *fakeFeed
	url  string
	box  *secret.Box
	svc  *Service
}

func setup(t *testing.T) *fixture {
	t.Helper()
	db := newTestDB(t)
	k, _ := instancekey.Generate(nil)
	feed := &fakeFeed{key: k, sessions: map[string]server.Session{}, revision: 4812, interval: 300}
	srv := httptest.NewServer(feed.handler(t))
	t.Cleanup(srv.Close)
	box, err := secret.New(bytes.Repeat([]byte{7}, secret.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(Config{Store: db, Box: box, Version: "1.2.3", Tick: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{db: db, feed: feed, url: srv.URL, box: box, svc: svc}
}

func (f *fixture) addServer(t *testing.T, telemetry bool) store.FeedServer {
	t.Helper()
	u, err := NormalizeURL(f.url)
	if err != nil {
		t.Fatal(err)
	}
	s, err := f.db.CreateFeedServer(context.Background(), store.FeedServerCreate{Name: "local", URL: u, Telemetry: telemetry})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestInstanceKey(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a, err := f.svc.Instance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := instancekey.ParsePublicKey(a.PublicKey); err != nil {
		t.Fatalf("public key %q: %v", a.PublicKey, err)
	}
	if bytes.Contains(a.EncryptedKey, []byte("PRIVATE KEY")) {
		t.Fatal("instance key stored in the clear")
	}
	// Another replica with the same master key uses the same key.
	other, _ := New(Config{Store: f.db, Box: f.box})
	b, err := other.Instance(ctx)
	if err != nil || b.PublicKey != a.PublicKey {
		t.Fatalf("other replica: %+v %v", b, err)
	}
	if _, key, err := other.instance(ctx); err != nil || key.Public().String() != a.PublicKey {
		t.Fatalf("decrypt: %v", err)
	}
	// A wrong master key does not open it.
	wrong, _ := secret.New(bytes.Repeat([]byte{8}, secret.KeySize))
	bad, _ := New(Config{Store: f.db, Box: wrong})
	if _, _, err := bad.instance(ctx); err == nil {
		t.Fatal("opened with a wrong master key")
	}
}

func TestTestTrustsFirstKey(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	s := f.addServer(t, false)

	got, err := f.svc.Test(ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != store.FeedServerConnected || got.ServerKey != f.feed.key.Public().String() || got.Grade != "anonymous" ||
		got.SessionExpiresAt == nil || got.Revision == nil || *got.Revision != 4812 || len(got.Sources) != 1 {
		t.Fatalf("after test: %+v", got)
	}
	in, _ := f.svc.Instance(ctx)
	f.feed.mu.Lock()
	defer f.feed.mu.Unlock()
	if len(f.feed.clients) != 1 || f.feed.clients[0] != in.PublicKey {
		t.Fatalf("clients %v, instance %s", f.feed.clients, in.PublicKey)
	}
	if h := f.feed.hellos[0]; h.Client != ClientName || h.Version != "1.2.3" || h.Telemetry {
		t.Fatalf("hello %+v", h)
	}
	if len(f.feed.sessions) != 0 {
		t.Fatal("test session was not ended")
	}
}

func TestKeyChange(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	s := f.addServer(t, true)
	if _, err := f.svc.Test(ctx, s.ID); err != nil {
		t.Fatal(err)
	}
	first := f.feed.key.Public().String()

	k2, _ := instancekey.Generate(nil)
	f.feed.setKey(k2)
	got, err := f.svc.Test(ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != store.FeedServerKeyChanged || got.ServerKey != first || got.PresentedKey != k2.Public().String() || got.PresentedAt == nil {
		t.Fatalf("after key change: %+v", got)
	}
	f.feed.mu.Lock()
	beats := f.feed.beats
	f.feed.mu.Unlock()
	if beats != 1 {
		t.Fatalf("a session with the changed key was used: %d heartbeats", beats)
	}

	other, _ := instancekey.Generate(nil)
	if _, err := f.svc.TrustKey(ctx, s.ID, other.Public().String()); !errors.Is(err, store.ErrInvalidState) {
		t.Fatalf("trust another key: %v", err)
	}
	if _, err := f.svc.TrustKey(ctx, s.ID, "not a key"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("trust garbage: %v", err)
	}
	if got, err = f.svc.TrustKey(ctx, s.ID, k2.Public().String()); err != nil || got.ServerKey != k2.Public().String() {
		t.Fatalf("trust: %+v %v", got, err)
	}
	if got, _ = f.svc.Test(ctx, s.ID); got.Status != store.FeedServerConnected {
		t.Fatalf("after trust: %+v", got)
	}
}

func TestTestError(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	s, err := f.db.CreateFeedServer(ctx, store.FeedServerCreate{Name: "down", URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.svc.Test(ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != store.FeedServerError || got.LastError == "" || got.ServerKey != "" {
		t.Fatalf("unreachable: %+v", got)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRun(t *testing.T) {
	f := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	// Without an interval from the server, heartbeats go every tick.
	f.feed.interval = 0
	s := f.addServer(t, true)
	if _, err := f.db.ActivateFeedServer(ctx, s.ID); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- f.svc.Run(ctx) }()

	waitFor(t, "connected", func() bool {
		got, _ := f.db.GetFeedServer(ctx, s.ID)
		return got.Status == store.FeedServerConnected && got.ServerKey != ""
	})
	f.feed.mu.Lock()
	if len(f.feed.hellos) != 1 || !f.feed.hellos[0].Telemetry {
		t.Errorf("hellos %+v", f.feed.hellos)
	}
	f.feed.mu.Unlock()

	// Turning telemetry off replaces the session.
	off := false
	if _, err := f.db.UpdateFeedServer(ctx, s.ID, store.FeedServerUpdate{Telemetry: &off}); err != nil {
		t.Fatal(err)
	}
	f.svc.Kick()
	waitFor(t, "new session", func() bool {
		f.feed.mu.Lock()
		defer f.feed.mu.Unlock()
		return len(f.feed.hellos) == 2 && !f.feed.hellos[1].Telemetry && len(f.feed.sessions) == 1
	})

	// A changed key stops the session.
	k2, _ := instancekey.Generate(nil)
	f.feed.setKey(k2)
	f.feed.mu.Lock()
	f.feed.sessions = map[string]server.Session{}
	f.feed.mu.Unlock()
	waitFor(t, "key change", func() bool {
		got, _ := f.db.GetFeedServer(ctx, s.ID)
		return got.Status == store.FeedServerKeyChanged
	})
	f.feed.mu.Lock()
	n := len(f.feed.hellos)
	f.feed.mu.Unlock()
	time.Sleep(100 * time.Millisecond)
	f.feed.mu.Lock()
	if len(f.feed.hellos) != n {
		t.Errorf("handshakes continued after the key change: %d -> %d", n, len(f.feed.hellos))
	}
	f.feed.mu.Unlock()

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("run: %v", err)
	}
}

func TestNormalizeURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://Feed.Example.com/":      "https://feed.example.com",
		" https://feed.example.com/x/ ":  "https://feed.example.com/x",
		"http://127.0.0.1:8080":          "http://127.0.0.1:8080",
		"http://localhost:8080/":         "http://localhost:8080",
		"https://feed.example.com:8443":  "https://feed.example.com:8443",
		"http://feed.example.com":        "",
		"ftp://feed.example.com":         "",
		"https://user@feed.example.com":  "",
		"https://feed.example.com/?a=1":  "",
		"https://feed.example.com/#frag": "",
		"feed.example.com":               "",
		"":                               "",
	} {
		got, err := NormalizeURL(in)
		if want == "" {
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("%q: %q, %v", in, got, err)
			}
			continue
		}
		if err != nil || got != want {
			t.Errorf("%q: %q, %v; want %q", in, got, err, want)
		}
	}
}
