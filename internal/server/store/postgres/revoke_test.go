// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/internal/server/vulnsvc"
	"github.com/bomcensus/bomcensus/server/scope"
)

func TestRevokedAgentAssetIsGone(t *testing.T) {
	db := newTestDB(t)
	ctx := scope.System(context.Background())
	srv, err := db.GetActiveFeedServer(ctx)
	ivMust(t, err)
	epoch := store.MatchEpoch{ServerID: srv.ID, Revision: 1}

	// Two agents, each with its host and openssl on it.
	host := func(name string) (store.Agent, string) {
		a := mgTestAgent(t, db, func(a *store.Agent) { a.Hostname = name })
		ref, err := db.UpsertHostAsset(ctx, store.HostIdentity{AgentID: a.ID},
			store.AssetInit{Name: name, Method: store.CollectAgent, SeenAt: ivT0})
		ivMust(t, err)
		_, err = db.ReplaceAssetComponents(ctx, store.ComponentScope{AssetID: ref.ID, Source: store.SourcePackages},
			ivPkgObs(ivDeb("openssl", "3.0.13-0ubuntu3"), ivDeb(name+"-tool", "1.0")), store.ReplaceOptions{At: ivT0})
		ivMust(t, err)
		return a, ref.ID
	}
	gone, goneAsset := host("old")
	_, keptAsset := host("web")

	pending, err := db.PendingMatches(ctx, epoch, 10)
	ivMust(t, err)
	var batch []store.ComponentMatch
	for _, c := range pending {
		m := store.ComponentMatch{ComponentID: c.ID, Status: store.MatchChecked}
		if c.Name == "openssl" {
			m.Vulns = []store.ComponentVuln{{VulnID: "CVE-1", Method: "package", FixState: "fixed"}}
		}
		batch = append(batch, m)
	}
	ivMust(t, db.SaveMatches(ctx, store.MatchBatch{Epoch: epoch, Components: batch, Vulns: []store.VulnMeta{{ID: "CVE-1"}}}))
	refresh := func() {
		t.Helper()
		r, err := vulnsvc.NewRefresher(db, nil, nil)
		ivMust(t, err)
		ivMust(t, r.Run(ctx))
	}
	refresh()
	openOn := func(asset string) int {
		return ivCount(t, db, `SELECT count(*) FROM findings WHERE asset_id = $1 AND resolved_at IS NULL`, asset)
	}
	if openOn(goneAsset) != 1 || openOn(keptAsset) != 1 {
		t.Fatalf("findings before: %d, %d", openOn(goneAsset), openOn(keptAsset))
	}

	// Revoking marks only that agent's asset gone.
	at := ivT0.Add(time.Hour).UTC().Truncate(time.Microsecond)
	ivMust(t, db.RevokeAgent(ctx, gone.ID, at))
	var goneAt *time.Time
	ivMust(t, db.q.QueryRow(ctx, `SELECT gone_at FROM assets WHERE id = $1`, goneAsset).Scan(&goneAt))
	if goneAt == nil || !goneAt.Equal(at) {
		t.Fatalf("gone_at %v, want %v", goneAt, at)
	}
	if n := ivCount(t, db, `SELECT count(*) FROM assets WHERE id = $1 AND gone_at IS NULL`, keptAsset); n != 1 {
		t.Fatal("the other agent's asset is gone")
	}
	rows, _, err := db.ListAssets(ctx, store.AssetFilter{}, store.Page{})
	ivMust(t, err)
	if len(rows) != 1 || rows[0].ID != keptAsset {
		t.Fatalf("assets %+v", rows)
	}

	// Its findings resolve and its own components are no longer matched.
	refresh()
	if openOn(goneAsset) != 0 || openOn(keptAsset) != 1 {
		t.Fatalf("findings after: %d, %d", openOn(goneAsset), openOn(keptAsset))
	}
	ivMust(t, db.ResetMatches(ctx, srv.ID))
	pending, err = db.PendingMatches(ctx, epoch, 10)
	ivMust(t, err)
	var names []string
	for _, c := range pending {
		names = append(names, c.Name)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"openssl", "web-tool"}) {
		t.Fatalf("live components %v", names)
	}

	// A report the revoked agent sent can no longer be accepted for it.
	locked, err := db.LockAgent(ctx, gone.ID)
	ivMust(t, err)
	if locked.State != store.AgentRevoked {
		t.Fatalf("lock agent %+v", locked)
	}

	// The migration marks assets of agents revoked before the change.
	if _, err := db.q.Exec(ctx, `UPDATE assets SET gone_at = NULL WHERE id = $1`, goneAsset); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile("migrations/0094_revoked_agent_assets.sql")
	ivMust(t, err)
	up := strings.SplitN(strings.SplitN(string(src), "-- +goose Up", 2)[1], "-- +goose Down", 2)[0]
	if _, err := db.q.Exec(ctx, up); err != nil {
		t.Fatal(err)
	}
	ivMust(t, db.q.QueryRow(ctx, `SELECT gone_at FROM assets WHERE id = $1`, goneAsset).Scan(&goneAt))
	if goneAt == nil || !goneAt.Equal(at) {
		t.Fatalf("migrated gone_at %v, want %v", goneAt, at)
	}
}
