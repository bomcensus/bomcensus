// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

func TestManagePKICompareAndSet(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	// Replicas starting together each try to create the CA.
	const replicas = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	won, lost := 0, 0
	for i := 0; i < replicas; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := db.PutPKIObject(ctx, store.PKIObject{
				Name:         store.PKIAgentTLSCA,
				CertChainPEM: []byte(fmt.Sprintf("cert-%d", i)),
				EncryptedKey: []byte(fmt.Sprintf("key-%d", i)),
				State:        store.PKIStateActive,
			}, 0)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				won++
			case errors.Is(err, store.ErrConflict):
				lost++
			default:
				t.Errorf("put: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if won != 1 || lost != replicas-1 {
		t.Fatalf("won %d lost %d", won, lost)
	}

	cur, err := db.GetPKIObject(ctx, store.PKIAgentTLSCA)
	if err != nil || cur.Version != 1 || cur.State != store.PKIStateActive {
		t.Fatalf("current %+v %v", cur, err)
	}
	next, err := db.PutPKIObject(ctx, store.PKIObject{Name: cur.Name, CertChainPEM: []byte("renewed"),
		EncryptedKey: cur.EncryptedKey, State: cur.State}, cur.Version)
	if err != nil || next.Version != 2 || string(next.CertChainPEM) != "renewed" || !next.CreatedAt.Equal(cur.CreatedAt) {
		t.Fatalf("update %+v %v", next, err)
	}
	if _, err := db.PutPKIObject(ctx, store.PKIObject{Name: cur.Name, CertChainPEM: []byte("stale")}, cur.Version); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale update: %v", err)
	}
	if _, err := db.PutPKIObject(ctx, store.PKIObject{Name: "absent", CertChainPEM: []byte("x")}, 3); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("update of absent object: %v", err)
	}

	if _, err := db.PutPKIObject(ctx, store.PKIObject{Name: store.PKIAgentTLSAnchorPending, CertChainPEM: []byte("anchor")}, 0); err != nil {
		t.Fatal(err)
	}
	list, err := db.ListPKIObjects(ctx)
	if err != nil || len(list) != 2 || list[0].Name != store.PKIAgentTLSAnchorPending || list[0].EncryptedKey != nil {
		t.Fatalf("list %+v %v", list, err)
	}
	if err := db.DeletePKIObject(ctx, store.PKIAgentTLSAnchorPending, 2); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("delete wrong version: %v", err)
	}
	if err := db.DeletePKIObject(ctx, store.PKIAgentTLSAnchorPending, 1); err != nil {
		t.Fatal(err)
	}
	if err := db.DeletePKIObject(ctx, store.PKIAgentTLSAnchorPending, 1); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
}

func TestManageTLSSettingsAndTrustBundle(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	s, err := db.GetTLSSetting(ctx, store.TLSEndpointWeb)
	if err != nil || s.Mode != store.TLSModeAuto || !s.UpdatedAt.IsZero() {
		t.Fatalf("default %+v %v", s, err)
	}
	if err := db.PutTLSSetting(ctx, store.TLSSetting{Endpoint: store.TLSEndpointWeb, Mode: store.TLSModeManual}); err != nil {
		t.Fatal(err)
	}
	if s, _ := db.GetTLSSetting(ctx, store.TLSEndpointWeb); s.Mode != store.TLSModeManual {
		t.Fatalf("after put %+v", s)
	}
	if s, _ := db.GetTLSSetting(ctx, store.TLSEndpointAgent); s.Mode != store.TLSModeAuto {
		t.Fatalf("agent %+v", s)
	}
	if err := db.PutTLSSetting(ctx, store.TLSSetting{Endpoint: "other", Mode: store.TLSModeAuto}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("bad endpoint: %v", err)
	}

	if v, err := db.TrustBundleVersion(ctx); err != nil || v != 0 {
		t.Fatalf("initial %d %v", v, err)
	}
	for want := int64(1); want <= 3; want++ {
		if v, err := db.BumpTrustBundleVersion(ctx); err != nil || v != want {
			t.Fatalf("bump %d %v", v, err)
		}
	}
	if v, _ := db.TrustBundleVersion(ctx); v != 3 {
		t.Fatalf("after bumps %d", v)
	}
}

func TestManageSettings(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if _, err := db.GetSetting(ctx, "x"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if err := db.PutSetting(ctx, "x", json.RawMessage(`{"a": 1}`)); err != nil {
		t.Fatal(err)
	}
	if err := db.PutSetting(ctx, "x", json.RawMessage(`{"a":2}`)); err != nil {
		t.Fatal(err)
	}
	v, err := db.GetSetting(ctx, "x")
	if err != nil || string(v) != `{"a": 2}` {
		t.Fatalf("get %s %v", v, err)
	}
	if err := db.PutSetting(ctx, "x", json.RawMessage(`{`)); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("invalid json: %v", err)
	}
}
