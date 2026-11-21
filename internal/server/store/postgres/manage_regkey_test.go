// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

var mgT0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func mgTestKey(t *testing.T, db *DB, id string, mutate func(*store.RegisterKey)) store.RegisterKey {
	t.Helper()
	k := store.RegisterKey{
		ID:        id,
		Name:      "key " + id,
		PublicKey: []byte("pub-" + id),
		Target:    store.AgentKindAgent,
		Approval:  store.ApprovalAuto,
		CreatedAt: mgT0,
	}
	if mutate != nil {
		mutate(&k)
	}
	out, err := db.CreateRegisterKey(context.Background(), k)
	if err != nil {
		t.Fatalf("create register key: %v", err)
	}
	return out
}

func TestManageRegisterKeyRoundTrip(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	exp := mgT0.Add(24 * time.Hour)
	k := mgTestKey(t, db, "AAAAAAAAAAA", func(k *store.RegisterKey) {
		k.ExpiresAt = &exp
		k.AllowedCIDRs = []netip.Prefix{netip.MustParsePrefix("10.1.2.3/16"), netip.MustParsePrefix("fd00::/8")}
		k.MaxUses = 3
		k.Approval = store.ApprovalManual
		k.AllowRelaxedTLS = true
		k.DefaultGroup = "prod"
		k.DefaultTags = []string{"a", "b"}
		k.CreatedBy = "admin"
	})
	got, err := db.GetRegisterKey(ctx, k.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.AllowedCIDRs[0] != netip.MustParsePrefix("10.1.0.0/16") || len(got.AllowedCIDRs) != 2 {
		t.Fatalf("cidrs %v", got.AllowedCIDRs)
	}
	if !got.AllowsAddr(netip.MustParseAddr("10.1.9.9")) || got.AllowsAddr(netip.MustParseAddr("10.2.0.1")) {
		t.Fatal("AllowsAddr")
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(exp) || got.Approval != store.ApprovalManual ||
		!got.AllowRelaxedTLS || got.DefaultGroup != "prod" || len(got.DefaultTags) != 2 || got.CreatedBy != "admin" {
		t.Fatalf("got %+v", got)
	}
	if _, err := db.CreateRegisterKey(ctx, k); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := db.CreateRegisterKey(ctx, store.RegisterKey{ID: "short"}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("short id: %v", err)
	}
	if _, err := db.GetRegisterKey(ctx, "missingmiss"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}

	mgTestKey(t, db, "BBBBBBBBBBB", func(k *store.RegisterKey) { k.Target = store.AgentKindScanner; k.Name = "scanners" })
	list, total, err := db.ListRegisterKeys(ctx, store.RegisterKeyFilter{Target: store.AgentKindScanner}, store.Page{})
	if err != nil || total != 1 || len(list) != 1 || list[0].ID != "BBBBBBBBBBB" {
		t.Fatalf("list by target: %v %d %v", list, total, err)
	}
	list, total, err = db.ListRegisterKeys(ctx, store.RegisterKeyFilter{Q: "SCANNER"}, store.Page{})
	if err != nil || total != 1 || len(list) != 1 {
		t.Fatalf("list by q: %v %d %v", list, total, err)
	}
	_, total, err = db.ListRegisterKeys(ctx, store.RegisterKeyFilter{}, store.Page{Limit: 1, Offset: 5})
	if err != nil || total != 2 {
		t.Fatalf("total past end: %d %v", total, err)
	}

	if err := db.RevokeRegisterKey(ctx, k.ID, mgT0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := db.RevokeRegisterKey(ctx, k.ID, mgT0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, _ = db.GetRegisterKey(ctx, k.ID)
	if got.RevokedAt == nil || !got.RevokedAt.Equal(mgT0.Add(time.Hour)) {
		t.Fatalf("revoked at %v", got.RevokedAt)
	}
	if err := db.RevokeRegisterKey(ctx, "missingmiss", mgT0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("revoke missing: %v", err)
	}
}

func TestManageRegisterKeyConsumeReasons(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	exp := mgT0.Add(time.Hour)
	mgTestKey(t, db, "expired0000", func(k *store.RegisterKey) { k.ExpiresAt = &exp })
	mgTestKey(t, db, "revoked0000", nil)
	mgTestKey(t, db, "unlimited00", nil)
	if err := db.RevokeRegisterKey(ctx, "revoked0000", mgT0); err != nil {
		t.Fatal(err)
	}

	if _, err := db.ConsumeRegisterKey(ctx, "expired0000", mgT0); err != nil {
		t.Fatalf("before expiry: %v", err)
	}
	if _, err := db.ConsumeRegisterKey(ctx, "expired0000", exp); !errors.Is(err, store.ErrRegisterKeyExpired) {
		t.Fatalf("at expiry: %v", err)
	}
	if _, err := db.ConsumeRegisterKey(ctx, "revoked0000", mgT0); !errors.Is(err, store.ErrRegisterKeyRevoked) {
		t.Fatalf("revoked: %v", err)
	}
	if _, err := db.ConsumeRegisterKey(ctx, "nonexistent", mgT0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	for i := 0; i < 10; i++ {
		k, err := db.ConsumeRegisterKey(ctx, "unlimited00", mgT0)
		if err != nil || k.UsedCount != i+1 {
			t.Fatalf("unlimited %d: %v %d", i, err, k.UsedCount)
		}
	}
	k, _ := db.GetRegisterKey(ctx, "revoked0000")
	if k.UsedCount != 0 {
		t.Fatalf("refused consume counted: %d", k.UsedCount)
	}
}

func TestManageRegisterKeyConsumeConcurrent(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	const workers, maxUses = 40, 7
	mgTestKey(t, db, "concurrent0", func(k *store.RegisterKey) { k.MaxUses = maxUses })

	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, exhausted := 0, 0
	var other []error
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := db.ConsumeRegisterKey(ctx, "concurrent0", mgT0)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, store.ErrRegisterKeyExhausted):
				exhausted++
			default:
				other = append(other, err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if len(other) > 0 {
		t.Fatalf("unexpected errors: %v", other)
	}
	if ok != maxUses || exhausted != workers-maxUses {
		t.Fatalf("ok %d exhausted %d", ok, exhausted)
	}
	k, err := db.GetRegisterKey(ctx, "concurrent0")
	if err != nil || k.UsedCount != maxUses {
		t.Fatalf("used count %d %v", k.UsedCount, err)
	}
}

func TestManageRegisterKeyConsumeRollsBack(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	mgTestKey(t, db, "rollback000", func(k *store.RegisterKey) { k.MaxUses = 1 })
	failed := fmt.Errorf("enrollment failed")
	err := db.mgInTx(ctx, func(tx *DB) error {
		if _, err := tx.ConsumeRegisterKey(ctx, "rollback000", mgT0); err != nil {
			return err
		}
		return failed
	})
	if !errors.Is(err, failed) {
		t.Fatal(err)
	}
	if _, err := db.ConsumeRegisterKey(ctx, "rollback000", mgT0); err != nil {
		t.Fatalf("use after rollback: %v", err)
	}
}

func TestManageEnrollSessionTakeOnce(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	s, err := db.CreateEnrollSession(ctx, store.EnrollSession{State: []byte("state"), ExpiresAt: mgT0.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	taken := 0
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := db.TakeEnrollSession(ctx, s.ID, mgT0)
			if err == nil {
				mu.Lock()
				taken++
				mu.Unlock()
				if string(got.State) != "state" {
					t.Errorf("state %q", got.State)
				}
			} else if !errors.Is(err, store.ErrNotFound) {
				t.Errorf("take: %v", err)
			}
		}()
	}
	wg.Wait()
	if taken != 1 {
		t.Fatalf("taken %d times", taken)
	}

	exp, err := db.CreateEnrollSession(ctx, store.EnrollSession{State: []byte("x"), ExpiresAt: mgT0})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.TakeEnrollSession(ctx, exp.ID, mgT0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired take: %v", err)
	}
	if _, err := db.TakeEnrollSession(ctx, "not-a-uuid", mgT0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("malformed id: %v", err)
	}

	for i := 0; i < 3; i++ {
		if _, err := db.CreateEnrollSession(ctx, store.EnrollSession{ExpiresAt: mgT0.Add(time.Duration(i) * time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	n, err := db.DeleteExpiredEnrollSessions(ctx, mgT0.Add(time.Minute))
	if err != nil || n != 2 {
		t.Fatalf("delete expired: %d %v", n, err)
	}
}

func TestManageSessions(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	s, err := db.CreateSession(ctx, "admin", "Admin", mgT0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.ID) != 43 {
		t.Fatalf("id %q", s.ID)
	}
	got, err := db.GetSession(ctx, s.ID, mgT0)
	if err != nil || got.PrincipalID != "admin" || got.PrincipalName != "Admin" || !got.ExpiresAt.Equal(s.ExpiresAt) {
		t.Fatalf("get: %+v %v", got, err)
	}
	if _, err := db.GetSession(ctx, s.ID, mgT0.Add(time.Hour)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired: %v", err)
	}
	if _, err := db.CreateSession(ctx, "admin", "Admin", mgT0); err != nil {
		t.Fatal(err)
	}
	n, err := db.DeleteExpiredSessions(ctx, mgT0)
	if err != nil || n != 1 {
		t.Fatalf("delete expired: %d %v", n, err)
	}
	if err := db.DeleteSession(ctx, s.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetSession(ctx, s.ID, mgT0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted: %v", err)
	}
}
