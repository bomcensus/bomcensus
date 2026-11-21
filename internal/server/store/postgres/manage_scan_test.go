// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

func TestManageCredentialDeleteRefusedWhileReferenced(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	c, err := db.CreateCredential(ctx, store.Credential{Name: "root key", Kind: store.CredentialSSHKey,
		Username: "root", Secret: []byte("sealed"), CreatedBy: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateCredential(ctx, store.Credential{Name: "root key", Kind: store.CredentialSSHKey,
		Secret: []byte("x")}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate name: %v", err)
	}
	if _, err := db.CreateCredential(ctx, store.Credential{Name: "k", Kind: "winrm", Secret: []byte("x")}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("bad kind: %v", err)
	}
	tg, err := db.CreateScanTarget(ctx, store.ScanTarget{Name: "web", Address: "10.0.0.5", Port: 22, CredentialID: c.ID})
	if err != nil {
		t.Fatal(err)
	}

	list, err := db.ListCredentials(ctx)
	if err != nil || len(list) != 1 || list[0].UsedBy != 1 || list[0].Secret != nil {
		t.Fatalf("list %+v %v", list, err)
	}
	if got, err := db.GetCredential(ctx, c.ID); err != nil || got.Secret != nil || got.Username != "root" {
		t.Fatalf("get %+v %v", got, err)
	}
	if got, err := db.GetCredentialWithSecret(ctx, c.ID); err != nil || string(got.Secret) != "sealed" {
		t.Fatalf("get with secret %+v %v", got, err)
	}

	if err := db.DeleteCredential(ctx, c.ID); !errors.Is(err, store.ErrInUse) {
		t.Fatalf("delete referenced: %v", err)
	}
	if err := db.DeleteScanTarget(ctx, tg.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteCredential(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteCredential(ctx, c.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
}

func TestManageScanTargets(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	c, err := db.CreateCredential(ctx, store.Credential{Name: "pw", Kind: store.CredentialSSHPassword, Secret: []byte("s")})
	if err != nil {
		t.Fatal(err)
	}
	scanner := mgTestAgent(t, db, func(a *store.Agent) { a.Kind = store.AgentKindScanner })

	if _, err := db.CreateScanTarget(ctx, store.ScanTarget{Name: "x", Address: "h", Port: 22,
		CredentialID: uuid.NewString()}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown credential: %v", err)
	}
	if _, err := db.CreateScanTarget(ctx, store.ScanTarget{Name: "x", Address: "h", Port: 0,
		CredentialID: c.ID}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("port 0: %v", err)
	}

	mk := func(name, scannerID string, interval int) store.ScanTarget {
		t.Helper()
		tg, err := db.CreateScanTarget(ctx, store.ScanTarget{Name: name, Address: name + ".lan", Port: 22,
			CredentialID: c.ID, ScannerID: scannerID, IntervalMinutes: interval, Sudo: true, CreatedAt: mgT0})
		if err != nil {
			t.Fatal(err)
		}
		return tg
	}
	embedded := mk("alpha", "", 60)
	remote := mk("beta", scanner.ID, 60)
	manual := mk("gamma", "", 0)
	if embedded.LastRun != nil || embedded.HostKey != nil || !embedded.Sudo || remote.ScannerID != scanner.ID {
		t.Fatalf("created %+v %+v", embedded, remote)
	}

	due := func(scannerID string, now time.Time) []string {
		t.Helper()
		list, err := db.ListDueScanTargets(ctx, scannerID, now, 0)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, tg := range list {
			names = append(names, tg.Name)
		}
		return names
	}
	if got := due("", mgT0); len(got) != 1 || got[0] != "alpha" {
		t.Fatalf("embedded due %v", got)
	}
	if got := due(scanner.ID, mgT0); len(got) != 1 || got[0] != "beta" {
		t.Fatalf("scanner due %v", got)
	}
	if err := db.RecordScanRun(ctx, embedded.ID, store.ScanRun{At: mgT0, Result: store.ScanPartial,
		Message: "no sudo", Duration: 1500 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	if got := due("", mgT0.Add(59*time.Minute)); len(got) != 0 {
		t.Fatalf("due too early %v", got)
	}
	if got := due("", mgT0.Add(60*time.Minute)); len(got) != 1 {
		t.Fatalf("due after interval %v", got)
	}
	got, err := db.GetScanTarget(ctx, embedded.ID)
	if err != nil || got.LastRun == nil || got.LastRun.Result != store.ScanPartial ||
		got.LastRun.Duration != 1500*time.Millisecond || !got.LastRun.At.Equal(mgT0) {
		t.Fatalf("last run %+v %v", got.LastRun, err)
	}

	if err := db.SetScanTargetHostKey(ctx, manual.ID, []byte("key-1")); err != nil {
		t.Fatal(err)
	}
	if err := db.SetScanTargetHostKey(ctx, manual.ID, []byte("key-1")); err != nil {
		t.Fatalf("same key: %v", err)
	}
	if err := db.SetScanTargetHostKey(ctx, manual.ID, []byte("key-2")); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("changed key: %v", err)
	}

	manual.Name, manual.Port, manual.IntervalMinutes = "gamma2", 2222, 15
	if err := db.UpdateScanTarget(ctx, manual); err != nil {
		t.Fatal(err)
	}
	asset := uuid.NewString()
	if err := db.SetScanTargetAsset(ctx, manual.ID, asset); err != nil {
		t.Fatal(err)
	}
	got, _ = db.GetScanTarget(ctx, manual.ID)
	if got.Name != "gamma2" || got.Port != 2222 || got.IntervalMinutes != 15 || string(got.HostKey) != "key-1" || got.AssetID != asset {
		t.Fatalf("updated %+v", got)
	}

	list, total, err := db.ListScanTargets(ctx, store.ScanTargetFilter{Q: "BETA.lan"}, store.Page{})
	if err != nil || total != 1 || list[0].ID != remote.ID {
		t.Fatalf("list %v %d %v", list, total, err)
	}
	if err := db.UpdateScanTarget(ctx, store.ScanTarget{ID: uuid.NewString(), Name: "n", Address: "a", Port: 22,
		CredentialID: c.ID}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}
}
