// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

func TestFeedInstance(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if _, err := db.GetFeedInstance(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("get before create: %v", err)
	}
	a, err := db.CreateFeedInstance(ctx, store.FeedInstance{PublicKey: "x25519 a", EncryptedKey: []byte{1}})
	if err != nil || a.PublicKey != "x25519 a" {
		t.Fatalf("create: %+v %v", a, err)
	}
	// A second create keeps the first key.
	b, err := db.CreateFeedInstance(ctx, store.FeedInstance{PublicKey: "x25519 b", EncryptedKey: []byte{2}})
	if err != nil || b.PublicKey != "x25519 a" || b.EncryptedKey[0] != 1 {
		t.Fatalf("second create: %+v %v", b, err)
	}
}

func TestFeedServers(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	builtin, err := db.GetActiveFeedServer(ctx)
	if err != nil || !builtin.Builtin || builtin.URL != "https://feed.bomcensus.com" || !builtin.Telemetry ||
		builtin.ServerKey != "" || builtin.Status != store.FeedServerNever || len(builtin.Sources) != 0 {
		t.Fatalf("built-in: %+v %v", builtin, err)
	}

	mirror, err := db.CreateFeedServer(ctx, store.FeedServerCreate{Name: "mirror", URL: "https://feed.corp.example"})
	if err != nil || mirror.Active || mirror.Telemetry || !mirror.Enabled {
		t.Fatalf("create: %+v %v", mirror, err)
	}
	if _, err := db.CreateFeedServer(ctx, store.FeedServerCreate{Name: "dup", URL: mirror.URL}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate url: %v", err)
	}
	list, err := db.ListFeedServers(ctx)
	if err != nil || len(list) != 2 || list[0].ID != builtin.ID {
		t.Fatalf("list: %+v %v", list, err)
	}

	// Only one server is active.
	if _, err := db.ActivateFeedServer(ctx, mirror.ID); err != nil {
		t.Fatal(err)
	}
	if a, _ := db.GetActiveFeedServer(ctx); a.ID != mirror.ID {
		t.Fatalf("active %s", a.ID)
	}
	if s, _ := db.GetFeedServer(ctx, builtin.ID); s.Active {
		t.Fatal("built-in still active")
	}
	off := false
	if _, err := db.UpdateFeedServer(ctx, mirror.ID, store.FeedServerUpdate{Enabled: &off}); !errors.Is(err, store.ErrInvalidState) {
		t.Fatalf("disable active: %v", err)
	}
	if err := db.DeleteFeedServer(ctx, mirror.ID); !errors.Is(err, store.ErrInvalidState) {
		t.Fatalf("delete active: %v", err)
	}
	if _, err := db.ActivateFeedServer(ctx, builtin.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteFeedServer(ctx, builtin.ID); !errors.Is(err, store.ErrInvalidState) {
		t.Fatalf("delete built-in: %v", err)
	}
	name, on := "corp", true
	u, err := db.UpdateFeedServer(ctx, mirror.ID, store.FeedServerUpdate{Name: &name, Enabled: &off, Telemetry: &on})
	if err != nil || u.Name != "corp" || u.Enabled || !u.Telemetry {
		t.Fatalf("update: %+v %v", u, err)
	}
	if _, err := db.ActivateFeedServer(ctx, mirror.ID); !errors.Is(err, store.ErrInvalidState) {
		t.Fatalf("activate disabled: %v", err)
	}
	if err := db.DeleteFeedServer(ctx, mirror.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetFeedServer(ctx, mirror.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("get deleted: %v", err)
	}
}

func TestFeedServerKey(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	s, _ := db.GetActiveFeedServer(ctx)

	// Trust on first use: the first key stays.
	if k, err := db.TrustFeedServerKey(ctx, s.ID, "x25519 one"); err != nil || k != "x25519 one" {
		t.Fatalf("first: %q %v", k, err)
	}
	if k, err := db.TrustFeedServerKey(ctx, s.ID, "x25519 two"); err != nil || k != "x25519 one" {
		t.Fatalf("second: %q %v", k, err)
	}
	exp := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	if err := db.RecordFeedServerOK(ctx, s.ID, store.FeedSession{Grade: "anonymous", ExpiresAt: exp}); err != nil {
		t.Fatal(err)
	}
	got, _ := db.GetFeedServer(ctx, s.ID)
	if got.Status != store.FeedServerConnected || got.Grade != "anonymous" || !got.SessionExpiresAt.Equal(exp) || got.KeyTrustedAt == nil {
		t.Fatalf("connected: %+v", got)
	}

	// A changed key stops the server until the presented key is accepted;
	// errors and successes do not leave that state.
	if err := db.RecordFeedServerKeyChange(ctx, s.ID, "x25519 two"); err != nil {
		t.Fatal(err)
	}
	_ = db.RecordFeedServerError(ctx, s.ID, "boom")
	_ = db.RecordFeedServerOK(ctx, s.ID, store.FeedSession{Grade: "anonymous", ExpiresAt: exp})
	got, _ = db.GetFeedServer(ctx, s.ID)
	if got.Status != store.FeedServerKeyChanged || got.PresentedKey != "x25519 two" || got.ServerKey != "x25519 one" || got.SessionExpiresAt != nil {
		t.Fatalf("key changed: %+v", got)
	}
	if _, err := db.AcceptFeedServerKey(ctx, s.ID, "x25519 three"); !errors.Is(err, store.ErrInvalidState) {
		t.Fatalf("accept other key: %v", err)
	}
	got, err := db.AcceptFeedServerKey(ctx, s.ID, "x25519 two")
	if err != nil || got.ServerKey != "x25519 two" || got.PresentedKey != "" || got.Status != store.FeedServerNever {
		t.Fatalf("accept: %+v %v", got, err)
	}

	if err := db.RecordFeedServerError(ctx, s.ID, "dial tcp: refused"); err != nil {
		t.Fatal(err)
	}
	got, _ = db.GetFeedServer(ctx, s.ID)
	if got.Status != store.FeedServerError || got.LastError != "dial tcp: refused" || got.LastErrorAt == nil {
		t.Fatalf("error: %+v", got)
	}

	healthy := true
	at := time.Date(2026, 11, 24, 5, 0, 0, 0, time.UTC)
	if err := db.RecordFeedData(ctx, s.ID, store.FeedData{Revision: 4812, RulesDigest: "64ae",
		Sources: []store.FeedSource{{Name: "osv/Debian", UpdatedAt: &at, Healthy: &healthy}}}); err != nil {
		t.Fatal(err)
	}
	got, _ = db.GetFeedServer(ctx, s.ID)
	if *got.Revision != 4812 || *got.RulesDigest != "64ae" || len(got.Sources) != 1 || !got.Sources[0].UpdatedAt.Equal(at) || got.StatusCheckedAt == nil {
		t.Fatalf("data: %+v", got)
	}
}
