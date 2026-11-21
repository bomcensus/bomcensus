// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

func TestUpsertHostAssetIdentity(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	scanner := uuid.NewString()
	init := store.AssetInit{Name: "db-01", Group: "prod", Tags: []string{"b", "a", "a"}, Method: store.CollectSSH, SeenAt: ivT0}

	// Scanner first, without machine id.
	r1, err := db.UpsertHostAsset(ctx, store.HostIdentity{ScannerID: scanner, Address: "10.0.0.5"}, init)
	ivMust(t, err)
	if !r1.Created {
		t.Fatal("not created")
	}
	r2, err := db.UpsertHostAsset(ctx, store.HostIdentity{ScannerID: scanner, Address: "10.0.0.5", MachineID: "m-1"}, init)
	ivMust(t, err)
	if r2.Created || r2.ID != r1.ID {
		t.Fatalf("scan with machine id: %+v", r2)
	}
	// An agent on the same machine takes the asset over.
	agent := uuid.NewString()
	r3, err := db.UpsertHostAsset(ctx, store.HostIdentity{AgentID: agent, MachineID: "m-1"}, init)
	ivMust(t, err)
	if r3.Created || r3.ID != r1.ID || r3.DuplicateMachineID {
		t.Fatalf("agent takeover: %+v", r3)
	}
	r4, err := db.UpsertHostAsset(ctx, store.HostIdentity{AgentID: agent}, init)
	ivMust(t, err)
	if r4.ID != r1.ID {
		t.Fatalf("agent lookup: %+v", r4)
	}
	// A clone: same machine id, another agent.
	r5, err := db.UpsertHostAsset(ctx, store.HostIdentity{AgentID: uuid.NewString(), MachineID: "m-1"}, init)
	ivMust(t, err)
	if !r5.Created || !r5.DuplicateMachineID {
		t.Fatalf("clone: %+v", r5)
	}

	a, err := db.GetAsset(ctx, r1.ID)
	ivMust(t, err)
	if a.AgentID != agent || a.MachineID != "m-1" || a.ScannerID != scanner || a.Address != "10.0.0.5" ||
		!a.DuplicateMachineID || len(a.Tags) != 2 || a.Tags[0] != "a" || !a.FirstSeen.Equal(ivT0) {
		t.Fatalf("asset: %+v", a.Asset)
	}

	if _, err := db.UpsertHostAsset(ctx, store.HostIdentity{}, init); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("empty identity: %v", err)
	}
}

func TestAssetFactsSectionsAndList(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	web := ivHost(t, db, "web-01")
	db1 := ivHost(t, db, "db-01")
	ivHost(t, db, "cache-01")

	ivMust(t, db.UpdateAssetFacts(ctx, web, store.AssetFacts{
		Group: "prod", Tags: []string{"dmz"}, OS: store.OSInfo{Family: "linux", ID: "ubuntu", Name: "Ubuntu", Version: "24.04"},
		Kernel: "6.8.0", Arch: "amd64", Address: "10.0.0.1", Privilege: store.PrivilegeNonRoot,
		Coverage: store.CoveragePartial, CoverageReason: "non-root", SeenAt: ivT0.Add(time.Hour),
	}))
	ivMust(t, db.UpdateAssetFacts(ctx, db1, store.AssetFacts{Group: "prod", Coverage: store.CoverageFull}))
	// Empty facts leave everything alone.
	ivMust(t, db.UpdateAssetFacts(ctx, web, store.AssetFacts{}))
	if err := db.UpdateAssetFacts(ctx, uuid.NewString(), store.AssetFacts{}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing asset: %v", err)
	}

	ivMust(t, db.SetSectionStates(ctx, web, []store.SectionState{
		{Section: "packages", Coverage: store.CoverageFull, Digest: "d1", CollectedAt: ivT0},
		{Section: "processes", Coverage: store.CoveragePartial, Reason: "hidepid", CollectedAt: ivT0},
	}))
	ivMust(t, db.SetSectionStates(ctx, web, []store.SectionState{
		{Section: "packages", Coverage: store.CoverageFull, Digest: "d2", CollectedAt: ivT0.Add(time.Hour)},
	}))
	ivMust(t, db.ReplaceContainers(ctx, web, []store.ContainerObservation{
		{Name: "app", ImageRef: "registry/app:1.0", ImageDigest: "sha256:aa", Runtime: store.RuntimeDocker, Instances: 1},
	}, store.ReplaceOptions{At: ivT0}))

	a, err := db.GetAsset(ctx, web)
	ivMust(t, err)
	if a.Group != "prod" || a.OS.Name != "Ubuntu" || a.Coverage != store.CoveragePartial || a.CoverageReason != "non-root" ||
		a.Privilege != store.PrivilegeNonRoot || !a.LastSeen.Equal(ivT0.Add(time.Hour)) || a.Location() != "10.0.0.1" {
		t.Fatalf("facts: %+v", a.Asset)
	}
	if len(a.Sections) != 2 || a.Sections[0].Section != "packages" || a.Sections[0].Digest != "d2" {
		t.Fatalf("sections: %+v", a.Sections)
	}
	if len(a.Containers) != 1 || a.Containers[0].ImageDigest != "sha256:aa" {
		t.Fatalf("containers: %+v", a.Containers)
	}

	rows, total, err := db.ListAssets(ctx, store.AssetFilter{Group: "prod", Sort: "name"}, store.Page{})
	ivMust(t, err)
	if total != 2 || rows[0].Name != "db-01" || rows[1].Name != "web-01" || rows[1].Containers != 1 {
		t.Fatalf("group filter: %+v", rows)
	}
	rows, total, err = db.ListAssets(ctx, store.AssetFilter{Coverage: store.CoverageLimited, Sort: "-name"}, store.Page{Limit: 1})
	ivMust(t, err)
	if total != 2 || len(rows) != 1 || rows[0].Name != "web-01" {
		t.Fatalf("limited: %d %+v", total, rows)
	}
	rows, total, err = db.ListAssets(ctx, store.AssetFilter{Q: "REGISTRY/app"}, store.Page{})
	ivMust(t, err)
	if total != 1 || rows[0].ID != web {
		t.Fatalf("image search: %+v", rows)
	}
	rows, total, err = db.ListAssets(ctx, store.AssetFilter{Q: "dmz"}, store.Page{})
	ivMust(t, err)
	if total != 1 {
		t.Fatalf("tag search: %d", total)
	}
	_, total, err = db.ListAssets(ctx, store.AssetFilter{Q: "%"}, store.Page{})
	ivMust(t, err)
	if total != 0 {
		t.Fatalf("escaped wildcard matched %d", total)
	}
	_, total, err = db.ListAssets(ctx, store.AssetFilter{Kind: store.AssetHost}, store.Page{Offset: 10})
	ivMust(t, err)
	if total != 3 {
		t.Fatalf("total beyond last page: %d", total)
	}

	counts, err := db.Dashboard(ctx)
	ivMust(t, err)
	if counts.Assets != 3 || counts.AssetsByCoverage[store.CoverageFull] != 1 || counts.LimitedCoverage != 2 || counts.Images != 1 {
		t.Fatalf("dashboard: %+v", counts)
	}
}

func TestReports(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	asset := ivHost(t, db, "h")
	id, err := db.StoreReport(ctx, store.RawReport{
		SourceID: "agent-1", SubjectKind: "self", Subject: []byte(`{"kind":"self"}`),
		ReceivedAt: ivT0, Body: []byte{0x28, 0xb5, 0x2f, 0xfd},
	})
	ivMust(t, err)
	ivMust(t, db.SetReportAsset(ctx, id, asset))
	r, err := db.GetReport(ctx, id)
	ivMust(t, err)
	if r.AssetID != asset || !bytes.Equal(r.Body, []byte{0x28, 0xb5, 0x2f, 0xfd}) || !r.ReceivedAt.Equal(ivT0) || string(r.Subject) != `{"kind": "self"}` {
		t.Fatalf("report: %+v", r)
	}
	n, err := db.DeleteReportsBefore(ctx, ivT0)
	ivMust(t, err)
	if n != 0 {
		t.Fatalf("deleted %d", n)
	}
	n, err = db.DeleteReportsBefore(ctx, ivT0.Add(time.Second))
	ivMust(t, err)
	if n != 1 {
		t.Fatalf("deleted %d", n)
	}
	if _, err := db.GetReport(ctx, id); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
}

func TestWithTxJoinsInventoryWrites(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	boom := errors.New("boom")
	err := db.WithTx(ctx, func(s store.Store) error {
		ref, err := s.UpsertHostAsset(ctx, store.HostIdentity{MachineID: "m-tx"}, store.AssetInit{Name: "tx"})
		if err != nil {
			return err
		}
		if _, err := s.ReplaceAssetComponents(ctx, store.ComponentScope{AssetID: ref.ID, Source: store.SourcePackages},
			ivPkgObs(ivDeb("zlib1g", "1.3")), store.ReplaceOptions{}); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("tx: %v", err)
	}
	if n := ivCount(t, db, `SELECT count(*) FROM assets`) + ivCount(t, db, `SELECT count(*) FROM components`); n != 0 {
		t.Fatalf("rolled back rows remain: %d", n)
	}
}
