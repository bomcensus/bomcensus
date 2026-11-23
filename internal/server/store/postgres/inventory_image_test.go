// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

func ivImg(digest string, tags ...string) store.ImageObservation {
	return store.ImageObservation{Digest: digest, RepoTags: tags}
}

func ivCheckTags(t *testing.T, db *DB, what, digest string, cur []string, prev []store.PreviousTag) {
	t.Helper()
	im, err := db.GetImage(ivCtx(t), digest)
	ivMust(t, err)
	if prev == nil {
		prev = []store.PreviousTag{}
	}
	if cur == nil {
		cur = []string{}
	}
	if !reflect.DeepEqual(im.Tags, cur) || !reflect.DeepEqual(im.PreviousTags, prev) {
		t.Fatalf("%s: %s tags %v previous %+v, want %v %+v", what, digest, im.Tags, im.PreviousTags, cur, prev)
	}
}

func TestImageTagsPerSource(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	h1, h2 := ivHost(t, db, "h1"), ivHost(t, db, "h2")
	t1, t2, t3, t4 := ivT0, ivT0.Add(time.Hour), ivT0.Add(2*time.Hour), ivT0.Add(3*time.Hour)
	const d0, d1, d2 = "sha256:d0", "sha256:d1", "sha256:d2"
	host := func(id string, at time.Time, keep bool, obs ...store.ImageObservation) {
		t.Helper()
		ivMust(t, db.UpsertImages(ctx, store.ImageSource{Kind: store.ImageSourceAsset, ID: id}, obs,
			store.ReplaceOptions{At: at, KeepMissing: keep}))
	}

	host(h1, t1, false, ivImg(d0, "app:0"), ivImg(d1, "app:1", "app:latest"))
	host(h2, t1, false, ivImg(d1, "app:latest"))
	ivCheckTags(t, db, "first", d1, []string{"app:1", "app:latest"}, nil)

	// app:latest moves to d2 on h1; h2 still has it on d1.
	host(h1, t2, false, ivImg(d1, "app:1"), ivImg(d2, "app:latest"))
	ivCheckTags(t, db, "moved on h1", d1, []string{"app:1", "app:latest"}, nil)
	ivCheckTags(t, db, "moved on h1", d2, []string{"app:latest"}, nil)
	ivCheckTags(t, db, "dropped on h1", d0, nil, []store.PreviousTag{{Tag: "app:0", LastSeen: t1}})

	// A reduced listing of h2 keeps the tags it does not list.
	host(h2, t3, true, ivImg(d2, "app:latest"))
	ivCheckTags(t, db, "reduced", d1, []string{"app:1", "app:latest"}, nil)

	// A full listing replaces the tag set of h2.
	host(h2, t4, false, ivImg(d2, "app:latest"))
	ivCheckTags(t, db, "full", d1, []string{"app:1"}, []store.PreviousTag{{Tag: "app:latest", LastSeen: t1}})
	ivCheckTags(t, db, "full", d2, []string{"app:latest"}, nil)

	// Search matches previous tags; sorting by tag falls back to them.
	rows, total, err := db.ListImages(ctx, store.ImageFilter{Q: "app:0"}, store.Page{})
	ivMust(t, err)
	if total != 1 || rows[0].Digest != d0 {
		t.Fatalf("q on previous tag: %+v", rows)
	}
	rows, _, err = db.ListImages(ctx, store.ImageFilter{Sort: "tag"}, store.Page{})
	ivMust(t, err)
	if len(rows) != 3 || rows[0].Digest != d0 || rows[1].Digest != d1 || rows[2].Digest != d2 {
		t.Fatalf("sort by tag: %+v", rows)
	}

	// The tags of a gone host are not current.
	_, err = db.q.Exec(ctx, `UPDATE assets SET gone_at = $2 WHERE id = $1`, h1, t4)
	ivMust(t, err)
	ivCheckTags(t, db, "gone host", d1, nil, []store.PreviousTag{{Tag: "app:1", LastSeen: t2}, {Tag: "app:latest", LastSeen: t1}})
	ivCheckTags(t, db, "gone host", d2, []string{"app:latest"}, nil)

	// An empty full listing clears the tag set; a tag that comes back is
	// current again.
	host(h2, t4.Add(time.Hour), false)
	ivCheckTags(t, db, "empty", d2, nil, []store.PreviousTag{{Tag: "app:latest", LastSeen: t4}})
	host(h2, t4.Add(2*time.Hour), false, ivImg(d1, "app:latest"))
	ivCheckTags(t, db, "back", d1, []string{"app:latest"}, []store.PreviousTag{{Tag: "app:1", LastSeen: t2}})

	// A cluster is a source of its own until it is deleted.
	c, err := db.CreateCluster(ctx, store.K8sClusterConfig{Name: "prd", Connection: store.K8sInCluster})
	ivMust(t, err)
	ivMust(t, db.UpsertImages(ctx, store.ImageSource{Kind: store.ImageSourceCluster, ID: c.ID},
		[]store.ImageObservation{ivImg(d2, "app:latest")}, store.ReplaceOptions{At: t4}))
	ivCheckTags(t, db, "cluster", d2, []string{"app:latest"}, nil)
	ivMust(t, db.DeleteCluster(ctx, c.ID))
	ivCheckTags(t, db, "cluster deleted", d2, nil, []store.PreviousTag{{Tag: "app:latest", LastSeen: t4}})

	if err := db.UpsertImages(ctx, store.ImageSource{Kind: store.ImageSourceCluster, ID: c.ID}, nil, store.ReplaceOptions{}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted source: %v", err)
	}
	if err := db.UpsertImages(ctx, store.ImageSource{Kind: "registry", ID: h2}, nil, store.ReplaceOptions{}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("unknown source kind: %v", err)
	}
}

func TestPurgeUnusedImages(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	h := ivHost(t, db, "h")
	t0, t1, t2 := ivT0, ivT0.Add(time.Hour), ivT0.Add(2*time.Hour)
	const (
		dUsed   = "sha256:a1"
		dGone   = "sha256:a2"
		dPrev   = "sha256:a3"
		dWeb    = "sha256:a4"
		dPod    = "sha256:a5"
		dUnused = "sha256:a6"
		dRecent = "sha256:a7"
	)
	src := store.ImageSource{Kind: store.ImageSourceAsset, ID: h}
	ivMust(t, db.ReplaceContainers(ctx, h, []store.ContainerObservation{
		{Name: "app", ImageRef: "app:1", ImageDigest: dUsed, Instances: 1},
		{Name: "old", ImageRef: "old:1", ImageDigest: dGone, Instances: 1},
		{Name: "web", ImageRef: "web:1", ImageDigest: dPrev, Instances: 1},
	}, store.ReplaceOptions{At: t0}))
	ivMust(t, db.UpsertImages(ctx, src, []store.ImageObservation{ivImg(dUnused, "x:1")}, store.ReplaceOptions{At: t0}))
	_, err := db.PutImageContent(ctx, store.ImageContent{Digest: dUnused, Coverage: store.CoverageFull, CollectedAt: t0,
		Packages: ivPkgObs(ivDeb("libc6", "2.39"))})
	ivMust(t, err)
	c, err := db.CreateCluster(ctx, store.K8sClusterConfig{Name: "prd", Connection: store.K8sInCluster})
	ivMust(t, err)
	_, err = db.ReplaceClusterInventory(ctx, c.ID, store.K8sInventory{At: t0, Workloads: []store.K8sWorkloadObservation{
		{Namespace: "shop", Kind: "Deployment", Name: "api", Pods: []store.K8sPodObservation{{Name: "api-a", Phase: "Running",
			Containers: []store.K8sPodContainerObservation{{Name: "api", ImageRef: "api:1", ImageDigest: dPod}}}}},
	}})
	ivMust(t, err)

	// old goes away, web gets a new image.
	ivMust(t, db.ReplaceContainers(ctx, h, []store.ContainerObservation{
		{Name: "app", ImageRef: "app:1", ImageDigest: dUsed, Instances: 1},
		{Name: "web", ImageRef: "web:2", ImageDigest: dWeb, Instances: 1},
	}, store.ReplaceOptions{At: t1}))
	ivMust(t, db.UpsertImages(ctx, src, []store.ImageObservation{ivImg(dRecent, "y:1")}, store.ReplaceOptions{At: t2}))

	exists := func(d string) bool {
		return ivCount(t, db, `SELECT count(*) FROM images WHERE digest = $1`, d) == 1
	}
	pr, err := db.PurgeGone(ctx, t1)
	ivMust(t, err)
	if pr.Images != 1 || pr.Containers != 0 || exists(dUnused) {
		t.Fatalf("first purge: %+v", pr)
	}
	for _, d := range []string{dUsed, dGone, dPrev, dWeb, dPod, dRecent} {
		if !exists(d) {
			t.Fatalf("referenced or recent image %s purged", d)
		}
	}
	if n := ivCount(t, db, `SELECT count(*) FROM image_components WHERE digest = $1`, dUnused) +
		ivCount(t, db, `SELECT count(*) FROM image_tags WHERE digest = $1`, dUnused); n != 0 {
		t.Fatalf("rows of the purged image left: %d", n)
	}

	// Once the gone container is purged, its image goes in the same run.
	pr, err = db.PurgeGone(ctx, t1.Add(time.Second))
	ivMust(t, err)
	if pr.Containers != 1 || pr.Images != 1 || exists(dGone) || !exists(dPrev) {
		t.Fatalf("second purge: %+v", pr)
	}

	// A purged digest that is reported again starts over.
	ivMust(t, db.UpsertImages(ctx, src, []store.ImageObservation{ivImg(dUnused, "x:1")}, store.ReplaceOptions{At: t2}))
	im, err := db.GetImage(ctx, dUnused)
	ivMust(t, err)
	if !im.FirstSeen.Equal(t2) || im.ContentKnown() || !reflect.DeepEqual(im.Tags, []string{"x:1"}) {
		t.Fatalf("reported again: %+v", im)
	}
}
