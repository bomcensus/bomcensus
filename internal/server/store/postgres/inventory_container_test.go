// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

func TestContainersGoneAndReturn(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	asset := ivHost(t, db, "docker-01")
	t1, t2, t3 := ivT0, ivT0.Add(time.Hour), ivT0.Add(2*time.Hour)
	app := store.ContainerObservation{Name: "app", RuntimeID: "c1", ImageRef: "app:1", ImageDigest: "sha256:a1",
		Runtime: store.RuntimeDocker, Instances: 1, StartedAt: t1}
	db1 := store.ContainerObservation{Name: "db", RuntimeID: "c2", ImageRef: "postgres:16", ImageDigest: "sha256:d1",
		Runtime: store.RuntimeDocker, Instances: 1}

	ivMust(t, db.ReplaceContainers(ctx, asset, []store.ContainerObservation{app, db1}, store.ReplaceOptions{At: t1}))
	ivMust(t, db.SetContainerCoverage(ctx, asset, "app", store.CoverageFull, ""))

	// db disappears; app gets a new image.
	app2 := app
	app2.ImageRef, app2.ImageDigest = "app:2", "sha256:a2"
	ivMust(t, db.ReplaceContainers(ctx, asset, []store.ContainerObservation{app2}, store.ReplaceOptions{At: t2}))
	a, err := db.GetAsset(ctx, asset)
	ivMust(t, err)
	if len(a.Containers) != 2 {
		t.Fatalf("containers: %+v", a.Containers)
	}
	c := a.Containers[0]
	if c.Name != "app" || c.PreviousDigest != "sha256:a1" || !c.DigestSince.Equal(t2) || c.Coverage != store.CoverageInventoryOnly || c.GoneAt != nil {
		t.Fatalf("image change: %+v", c)
	}
	g := a.Containers[1]
	if g.Name != "db" || g.GoneAt == nil || !g.GoneAt.Equal(t2) || g.Instances != 0 {
		t.Fatalf("gone: %+v", g)
	}

	// Reduced coverage keeps it gone-free state as is.
	ivMust(t, db.ReplaceContainers(ctx, asset, nil, store.ReplaceOptions{At: t3, KeepMissing: true}))
	a, err = db.GetAsset(ctx, asset)
	ivMust(t, err)
	if a.Containers[0].GoneAt != nil {
		t.Fatalf("kept container marked gone: %+v", a.Containers[0])
	}

	// db comes back.
	ivMust(t, db.ReplaceContainers(ctx, asset, []store.ContainerObservation{app2, db1}, store.ReplaceOptions{At: t3}))
	a, err = db.GetAsset(ctx, asset)
	ivMust(t, err)
	for _, c := range a.Containers {
		if c.GoneAt != nil {
			t.Fatalf("still gone: %+v", c)
		}
		if c.Name == "db" && (!c.FirstSeen.Equal(t1) || c.Instances != 1) {
			t.Fatalf("returned: %+v", c)
		}
	}
	rows, _, err := db.ListAssets(ctx, store.AssetFilter{}, store.Page{})
	ivMust(t, err)
	if rows[0].Containers != 2 {
		t.Fatalf("container count: %d", rows[0].Containers)
	}

	// Image usage counts current containers only.
	ivMust(t, db.UpsertImages(ctx, []store.ImageObservation{
		{Digest: "sha256:a1", RepoTags: []string{"app:1", "app:latest"}, OS: "linux", Arch: "amd64", Size: 100},
	}, t1))
	imgs, total, err := db.ListImages(ctx, store.ImageFilter{InUseOnly: true, Sort: "digest"}, store.Page{})
	ivMust(t, err)
	if total != 2 || imgs[0].Digest != "sha256:a2" || imgs[1].Digest != "sha256:d1" {
		t.Fatalf("in use: %+v", imgs)
	}
	all, total, err := db.ListImages(ctx, store.ImageFilter{Q: "latest"}, store.Page{})
	ivMust(t, err)
	if total != 1 || all[0].Size != 100 || len(all[0].RepoTags) != 2 || all[0].Containers != 0 {
		t.Fatalf("unused image: %+v", all)
	}
}
