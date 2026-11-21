// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

func TestManageScanLeases(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	t0 := mgT0
	acquire := func(key, owner string, ttl time.Duration, now time.Time) bool {
		t.Helper()
		ok, err := db.AcquireScanLease(ctx, key, owner, ttl, now)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if _, err := db.GetScanLease(ctx, "ssh:a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing lease: %v", err)
	}
	if !acquire("ssh:a", "job1", time.Minute, t0) {
		t.Fatal("free key not acquired")
	}
	if acquire("ssh:a", "job2", time.Minute, t0.Add(time.Second)) {
		t.Fatal("held key acquired by another owner")
	}
	// The owner extends its lease; the acquisition time is kept.
	if !acquire("ssh:a", "job1", time.Hour, t0.Add(30*time.Second)) {
		t.Fatal("owner could not extend")
	}
	l, err := db.GetScanLease(ctx, "ssh:a")
	if err != nil || l.Owner != "job1" || !l.AcquiredAt.Equal(t0) || !l.ExpiresAt.Equal(t0.Add(30*time.Second+time.Hour)) {
		t.Fatalf("lease %+v %v", l, err)
	}
	if ok, err := db.RenewScanLease(ctx, "ssh:a", "job2", time.Hour, t0.Add(time.Minute)); err != nil || ok {
		t.Fatalf("renew by another owner: %v %v", ok, err)
	}
	if ok, err := db.RenewScanLease(ctx, "ssh:a", "job1", 2*time.Hour, t0.Add(time.Minute)); err != nil || !ok {
		t.Fatalf("renew: %v %v", ok, err)
	}
	// Release by another owner keeps the lease.
	if err := db.ReleaseScanLease(ctx, "ssh:a", "job2", t0.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if acquire("ssh:a", "job2", time.Minute, t0.Add(2*time.Minute)) {
		t.Fatal("released by the wrong owner")
	}
	rel := t0.Add(3 * time.Minute)
	if err := db.ReleaseScanLease(ctx, "ssh:a", "job1", rel); err != nil {
		t.Fatal(err)
	}
	l, _ = db.GetScanLease(ctx, "ssh:a")
	if !l.ExpiresAt.Equal(rel) || !l.AcquiredAt.Equal(t0) {
		t.Fatalf("released lease %+v", l)
	}
	if ok, _ := db.RenewScanLease(ctx, "ssh:a", "job1", time.Hour, rel); ok {
		t.Fatal("renewed a released lease")
	}
	if !acquire("ssh:a", "job2", time.Minute, rel) {
		t.Fatal("released key not acquired")
	}
	// An expired lease is free.
	if !acquire("ssh:b", "job3", time.Minute, t0) || !acquire("ssh:b", "job4", time.Minute, t0.Add(time.Minute)) {
		t.Fatal("expired lease not taken over")
	}
	if l, _ := db.GetScanLease(ctx, "ssh:b"); l.Owner != "job4" || !l.AcquiredAt.Equal(t0.Add(time.Minute)) {
		t.Fatalf("taken over lease %+v", l)
	}
	if _, err := db.AcquireScanLease(ctx, "", "x", time.Minute, t0); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("empty key: %v", err)
	}
	if _, err := db.AcquireScanLease(ctx, "k", "x", 0, t0); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("zero ttl: %v", err)
	}
	// Cleanup removes leases that ended at or before t.
	n, err := db.DeleteExpiredScanLeases(ctx, t0.Add(2*time.Minute))
	if err != nil || n != 1 {
		t.Fatalf("cleanup: %d %v", n, err)
	}
	if _, err := db.GetScanLease(ctx, "ssh:a"); err != nil {
		t.Fatal("held lease deleted")
	}
}

func TestManageScanLeaseRace(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	var wins atomic.Int64
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := db.AcquireScanLease(ctx, "sync:c", fmt.Sprintf("job%d", i), time.Minute, mgT0)
			if err != nil {
				t.Error(err)
			}
			if ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d owners hold the lease", wins.Load())
	}
}
