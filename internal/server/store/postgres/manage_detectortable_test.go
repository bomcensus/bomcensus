// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/server/scope"
)

func TestDetectorTables(t *testing.T) {
	db := newTestDB(t)
	ctx := scope.System(context.Background())
	if _, err := db.LatestDetectorTable(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("latest of none: %v", err)
	}
	d1 := strings.Repeat("a", 64)
	r1, err := db.AddDetectorTable(ctx, store.DetectorTableRevision{YAML: "schema_version: 1\n", Digest: d1, CreatedBy: "admin", CreatedAt: mgT0})
	if err != nil || r1.ID == 0 || !r1.CreatedAt.Equal(mgT0) {
		t.Fatalf("add: %+v %v", r1, err)
	}
	r2, err := db.AddDetectorTable(ctx, store.DetectorTableRevision{Reset: true, CreatedBy: "ops", CreatedAt: mgT0.Add(time.Hour)})
	if err != nil || r2.ID <= r1.ID {
		t.Fatalf("reset: %+v %v", r2, err)
	}
	for _, bad := range []store.DetectorTableRevision{{Reset: true, YAML: "x", Digest: d1}, {YAML: "x"}, {Digest: d1}} {
		if _, err := db.AddDetectorTable(ctx, bad); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	latest, err := db.LatestDetectorTable(ctx)
	if err != nil || latest.ID != r2.ID || !latest.Reset {
		t.Fatalf("latest: %+v %v", latest, err)
	}
	got, err := db.GetDetectorTable(ctx, r1.ID)
	if err != nil || got.YAML != "schema_version: 1\n" || got.Digest != d1 || got.CreatedBy != "admin" {
		t.Fatalf("get: %+v %v", got, err)
	}
	if _, err := db.GetDetectorTable(ctx, 999); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("get missing: %v", err)
	}
	list, err := db.ListDetectorTables(ctx, 10)
	if err != nil || len(list) != 2 || list[0].ID != r2.ID || list[1].YAML != "" || list[1].Digest != d1 {
		t.Fatalf("list: %+v %v", list, err)
	}

	// Usage follows the digest of each poll.
	a1 := mgTestAgent(t, db, nil)
	a2 := mgTestAgent(t, db, nil)
	mgTestAgent(t, db, nil) // never polled with a digest
	sc := mgTestAgent(t, db, func(a *store.Agent) { a.Kind = store.AgentKindScanner })
	mgTestAgent(t, db, func(a *store.Agent) { a.State = store.AgentPending })
	empty := ""
	poll := func(id string, digest *string) {
		t.Helper()
		if err := db.UpdateAgentPoll(ctx, id, store.AgentPollStatus{Hostname: "h", ConnectMode: store.ConnectModeConnect,
			TLSMode: store.TLSVerifyPinned, Privilege: store.PrivilegeNonRoot, UpdateState: store.UpdateUpToDate,
			SeenAt: mgT0, DetectorsDigest: digest}); err != nil {
			t.Fatal(err)
		}
	}
	poll(a1.ID, &d1)
	poll(a2.ID, &d1)
	poll(sc.ID, &empty)
	usage, err := db.DetectorTableUsage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := map[store.DetectorTableUsage]bool{
		{Kind: store.AgentKindAgent, Reported: true, Digest: d1, Count: 2}: true,
		{Kind: store.AgentKindAgent, Reported: false, Count: 1}:            true,
		{Kind: store.AgentKindScanner, Reported: true, Count: 1}:           true,
	}
	if len(usage) != len(want) {
		t.Fatalf("usage %+v", usage)
	}
	for _, u := range usage {
		if !want[u] {
			t.Errorf("usage %+v", u)
		}
	}
	a, err := db.GetAgent(ctx, a1.ID)
	if err != nil || a.DetectorsDigest == nil || *a.DetectorsDigest != d1 {
		t.Fatalf("agent digest %v %v", a.DetectorsDigest, err)
	}
	// An agent that stops reporting a digest (downgraded) is counted as
	// not reporting.
	poll(a2.ID, nil)
	if a, _ := db.GetAgent(ctx, a2.ID); a.DetectorsDigest != nil {
		t.Fatalf("digest kept: %v", *a.DetectorsDigest)
	}
	if _, err := db.DetectorTableUsage(context.Background()); err == nil {
		t.Fatal("usage without a scope")
	}
}
