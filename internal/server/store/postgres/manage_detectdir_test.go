// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/server/scope"
)

func TestManageDetectDirs(t *testing.T) {
	db := newTestDB(t)
	ctx := scope.System(context.Background())

	opt, err := db.CreateDetectDir(ctx, store.DetectDir{Path: "/opt", Description: "applications"})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := db.CreateDetectDir(ctx, store.DetectDir{Path: "/srv"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateDetectDir(ctx, store.DetectDir{Path: "/opt"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate path: %v", err)
	}
	if _, err := db.CreateDetectDir(ctx, store.DetectDir{Path: "relative"}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("relative path: %v", err)
	}

	a := mgTestAgent(t, db, nil)
	c, err := db.CreateCredential(ctx, store.Credential{Name: "pw", Kind: store.CredentialSSHPassword, Secret: []byte("s")})
	if err != nil {
		t.Fatal(err)
	}
	tg, err := db.CreateScanTarget(ctx, store.ScanTarget{Name: "web", Address: "h", Port: 22, CredentialID: c.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(tg.DetectDirIDs) != 0 || len(tg.DetectPaths) != 0 {
		t.Fatalf("new target has dirs: %+v", tg)
	}

	// Duplicates collapse; results are ordered by path.
	if err := db.SetAgentDetectDirs(ctx, a.ID, []string{srv.ID, opt.ID, srv.ID}); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetAgent(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.DetectDirIDs, []string{opt.ID, srv.ID}) || !slices.Equal(got.DetectPaths, []string{"/opt", "/srv"}) {
		t.Fatalf("agent dirs %v %v", got.DetectDirIDs, got.DetectPaths)
	}
	if err := db.SetScanTargetDetectDirs(ctx, tg.ID, []string{srv.ID}); err != nil {
		t.Fatal(err)
	}
	if got, err := db.GetScanTarget(ctx, tg.ID); err != nil || !slices.Equal(got.DetectPaths, []string{"/srv"}) {
		t.Fatalf("target dirs %+v %v", got, err)
	}
	if list, _, err := db.ListScanTargets(ctx, store.ScanTargetFilter{}, store.Page{}); err != nil ||
		len(list) != 1 || !slices.Equal(list[0].DetectDirIDs, []string{srv.ID}) {
		t.Fatalf("list targets %+v %v", list, err)
	}

	// An unknown directory or owner changes nothing.
	if err := db.SetAgentDetectDirs(ctx, a.ID, []string{uuid.NewString()}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown dir: %v", err)
	}
	if err := db.SetAgentDetectDirs(ctx, uuid.NewString(), nil); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown agent: %v", err)
	}
	if err := db.SetScanTargetDetectDirs(ctx, uuid.NewString(), nil); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown target: %v", err)
	}
	if got, _ := db.GetAgent(ctx, a.ID); len(got.DetectDirIDs) != 2 {
		t.Fatalf("failed set changed the dirs: %v", got.DetectDirIDs)
	}

	list, err := db.ListDetectDirs(ctx)
	if err != nil || len(list) != 2 || list[0].Path != "/opt" || list[0].Agents != 1 || list[0].ScanTargets != 0 ||
		list[1].Agents != 1 || list[1].ScanTargets != 1 || list[0].Description != "applications" {
		t.Fatalf("list %+v %v", list, err)
	}

	// A renamed directory changes the paths sent to its hosts.
	if _, err := db.UpdateDetectDir(ctx, store.DetectDir{ID: srv.ID, Path: "/opt"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("rename onto another path: %v", err)
	}
	if _, err := db.UpdateDetectDir(ctx, store.DetectDir{ID: srv.ID, Path: "/data", Description: "d"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.GetAgent(ctx, a.ID); !slices.Equal(got.DetectPaths, []string{"/data", "/opt"}) {
		t.Fatalf("after rename %v", got.DetectPaths)
	}
	if _, err := db.UpdateDetectDir(ctx, store.DetectDir{ID: uuid.NewString(), Path: "/x"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("update unknown: %v", err)
	}

	// Deleting a directory removes its assignments.
	if err := db.DeleteDetectDir(ctx, srv.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteDetectDir(ctx, srv.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	if got, _ := db.GetAgent(ctx, a.ID); !slices.Equal(got.DetectPaths, []string{"/opt"}) {
		t.Fatalf("after delete %v", got.DetectPaths)
	}
	if got, _ := db.GetScanTarget(ctx, tg.ID); len(got.DetectPaths) != 0 {
		t.Fatalf("target after delete %v", got.DetectPaths)
	}

	// Clearing works with an empty list.
	if err := db.SetAgentDetectDirs(ctx, a.ID, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.GetAgent(ctx, a.ID); len(got.DetectDirIDs) != 0 {
		t.Fatalf("cleared %v", got.DetectDirIDs)
	}
}
