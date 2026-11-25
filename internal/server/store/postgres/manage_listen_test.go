// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/server/scope"
)

func TestManageListenLeases(t *testing.T) {
	db := newTestDB(t)
	ctx := scope.System(context.Background())
	const ttl = 30 * time.Second
	var ids []string
	for i := 0; i < 3; i++ {
		lt, err := db.CreateListenTarget(ctx, store.ListenTarget{Address: fmt.Sprintf("10.0.0.%d:7443", i)})
		if err != nil {
			t.Fatal(err)
		}
		if lt.State != store.ListenNew || lt.LeaseOwner != "" {
			t.Fatalf("created %+v", lt)
		}
		ids = append(ids, lt.ID)
	}
	if _, err := db.CreateListenTarget(ctx, store.ListenTarget{Address: "10.0.0.0:7443"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate address: %v", err)
	}

	a, err := db.AcquireListenLeases(ctx, "replica-a", ttl, mgT0, 2)
	if err != nil || len(a) != 2 {
		t.Fatalf("a: %d %v", len(a), err)
	}
	b, err := db.AcquireListenLeases(ctx, "replica-b", ttl, mgT0, 0)
	if err != nil || len(b) != 1 || b[0].LeaseOwner != "replica-b" {
		t.Fatalf("b: %+v %v", b, err)
	}
	if b2, _ := db.AcquireListenLeases(ctx, "replica-b", ttl, mgT0.Add(time.Second), 0); len(b2) != 1 {
		t.Fatalf("b renew took %d", len(b2))
	}

	// a keeps renewing one target and lets the other lapse.
	kept := a[0].ID
	if ok, err := db.RenewListenLease(ctx, kept, "replica-a", ttl, mgT0.Add(20*time.Second)); err != nil || !ok {
		t.Fatalf("renew: %v %v", ok, err)
	}
	if err := db.RecordListenState(ctx, kept, "replica-a", store.ListenConnected, "", mgT0.Add(20*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordListenState(ctx, kept, "replica-b", store.ListenFailed, "x", mgT0); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("state by non-holder: %v", err)
	}

	// After the lease of a[1] expires, b takes it over.
	later := mgT0.Add(ttl + time.Second)
	b, err = db.AcquireListenLeases(ctx, "replica-b", ttl, later, 0)
	if err != nil || len(b) != 2 {
		t.Fatalf("takeover: %d %v", len(b), err)
	}
	for _, lt := range b {
		if lt.ID == kept {
			t.Fatal("b took a lease that was renewed")
		}
	}
	if ok, err := db.RenewListenLease(ctx, a[1].ID, "replica-a", ttl, later); err != nil || ok {
		t.Fatalf("renew lost lease: %v %v", ok, err)
	}
	if err := db.RecordListenState(ctx, a[1].ID, "replica-a", store.ListenConnected, "", later); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("state after takeover: %v", err)
	}

	if err := db.ReleaseListenLease(ctx, kept, "replica-b"); err != nil {
		t.Fatal(err)
	}
	got, _ := db.GetListenTarget(ctx, kept)
	if got.LeaseOwner != "replica-a" || got.State != store.ListenConnected || got.LastConnectedAt == nil {
		t.Fatalf("release by non-holder changed the lease: %+v", got)
	}
	if err := db.ReleaseListenLease(ctx, kept, "replica-a"); err != nil {
		t.Fatal(err)
	}
	if b, _ = db.AcquireListenLeases(ctx, "replica-b", ttl, later, 0); len(b) != 3 {
		t.Fatalf("after release b holds %d", len(b))
	}
	if ok, err := db.RenewListenLease(ctx, ids[0], "replica-b", ttl, later); err != nil || !ok {
		t.Fatalf("renew held: %v %v", ok, err)
	}
	if _, err := db.RenewListenLease(ctx, "00000000-0000-0000-0000-000000000000", "replica-b", ttl, later); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("renew missing: %v", err)
	}
}

func TestManageListenLeasesConcurrent(t *testing.T) {
	db := newTestDB(t)
	ctx := scope.System(context.Background())
	const targets, replicas = 40, 4
	for i := 0; i < targets; i++ {
		if _, err := db.CreateListenTarget(ctx, store.ListenTarget{Address: fmt.Sprintf("h%d:7443", i)}); err != nil {
			t.Fatal(err)
		}
	}
	held := map[string]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for r := 0; r < replicas; r++ {
		wg.Add(1)
		go func(owner string) {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				got, err := db.AcquireListenLeases(ctx, owner, time.Minute, mgT0, 3)
				if err != nil {
					t.Errorf("acquire: %v", err)
					return
				}
				mu.Lock()
				for _, lt := range got {
					if prev, ok := held[lt.ID]; ok && prev != owner {
						t.Errorf("target %s held by %s and %s", lt.ID, prev, owner)
					}
					held[lt.ID] = owner
				}
				mu.Unlock()
			}
		}(fmt.Sprintf("replica-%d", r))
	}
	wg.Wait()
	all, err := db.ListListenTargets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, lt := range all {
		if owner, ok := held[lt.ID]; ok && owner != lt.LeaseOwner {
			t.Fatalf("target %s: stored owner %s, acquired by %s", lt.ID, lt.LeaseOwner, owner)
		}
	}

	// Every lease has expired: each replica renews its own rows while the
	// others try to take them over. This must neither deadlock nor hand a
	// target to two replicas in the same round.
	for round := 1; round <= 5; round++ {
		now := mgT0.Add(time.Duration(round) * 2 * time.Minute)
		results := make([][]store.ListenTarget, replicas)
		for r := 0; r < replicas; r++ {
			wg.Add(1)
			go func(r int) {
				defer wg.Done()
				got, err := db.AcquireListenLeases(ctx, fmt.Sprintf("replica-%d", r), time.Minute, now, 7)
				if err != nil {
					t.Errorf("round %d acquire: %v", round, err)
				}
				results[r] = got
			}(r)
		}
		wg.Wait()
		owners := map[string]int{}
		for r, got := range results {
			for _, lt := range got {
				if prev, ok := owners[lt.ID]; ok {
					t.Fatalf("round %d: target %s returned to replicas %d and %d", round, lt.ID, prev, r)
				}
				owners[lt.ID] = r
			}
		}
	}
}

func TestManageListenTargetBind(t *testing.T) {
	db := newTestDB(t)
	ctx := scope.System(context.Background())
	mgTestKey(t, db, "listenkey00", nil)
	lt, err := db.CreateListenTarget(ctx, store.ListenTarget{Address: "edge:7443", RegisterKeyID: "listenkey00"})
	if err != nil || lt.RegisterKeyID != "listenkey00" {
		t.Fatalf("create %+v %v", lt, err)
	}
	a1 := mgTestAgent(t, db, nil)
	a2 := mgTestAgent(t, db, nil)
	if err := db.BindListenTargetAgent(ctx, lt.ID, a1.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.BindListenTargetAgent(ctx, lt.ID, a1.ID); err != nil {
		t.Fatalf("rebind same: %v", err)
	}
	if err := db.BindListenTargetAgent(ctx, lt.ID, a2.ID); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("bind other: %v", err)
	}
	if err := db.DeleteListenTarget(ctx, lt.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetListenTarget(ctx, lt.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted: %v", err)
	}
}
