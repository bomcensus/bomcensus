// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

func TestReplaceAssetComponentsHistory(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	asset := ivHost(t, db, "web-01")
	scope := store.ComponentScope{AssetID: asset, Source: store.SourcePackages}
	openssl, curl, bash := ivDeb("openssl", "3.0.13-0ubuntu3"), ivDeb("curl", "8.5.0-2ubuntu10"), ivDeb("bash", "5.2.21-2ubuntu4")

	t1, t2, t3, t4 := ivT0, ivT0.Add(time.Hour), ivT0.Add(2*time.Hour), ivT0.Add(3*time.Hour)

	res, err := db.ReplaceAssetComponents(ctx, scope, ivPkgObs(openssl, curl), store.ReplaceOptions{At: t1})
	ivMust(t, err)
	if res.Added != 2 || res.Removed != 0 || len(res.NewComponents) != 2 {
		t.Fatalf("first replace: %+v", res)
	}

	// Same set again: nothing changes.
	res, err = db.ReplaceAssetComponents(ctx, scope, ivPkgObs(openssl, curl), store.ReplaceOptions{At: t2})
	ivMust(t, err)
	if res.Added != 0 || res.Removed != 0 || res.Changed != 0 || len(res.NewComponents) != 0 {
		t.Fatalf("unchanged replace: %+v", res)
	}

	// curl removed, bash added.
	res, err = db.ReplaceAssetComponents(ctx, scope, ivPkgObs(openssl, bash), store.ReplaceOptions{At: t2})
	ivMust(t, err)
	if res.Added != 1 || res.Removed != 1 {
		t.Fatalf("remove replace: %+v", res)
	}

	// Reduced coverage: curl stays removed, openssl and bash are kept though
	// not observed.
	res, err = db.ReplaceAssetComponents(ctx, scope, nil, store.ReplaceOptions{At: t3, KeepMissing: true})
	ivMust(t, err)
	if res.Added != 0 || res.Removed != 0 {
		t.Fatalf("keep missing: %+v", res)
	}

	// curl comes back: a new interval.
	res, err = db.ReplaceAssetComponents(ctx, scope, ivPkgObs(openssl, bash, curl), store.ReplaceOptions{At: t4})
	ivMust(t, err)
	if res.Added != 1 || res.Removed != 0 {
		t.Fatalf("re-add: %+v", res)
	}

	rows, total, err := db.ListAssetComponents(ctx, asset, store.AssetComponentFilter{Q: "curl", IncludeRemoved: true, Sort: "first_seen"}, store.Page{})
	ivMust(t, err)
	if total != 2 || len(rows) != 2 {
		t.Fatalf("curl history: total %d rows %d", total, len(rows))
	}
	if !rows[0].FirstSeen.Equal(t1) || rows[0].RemovedAt == nil || !rows[0].RemovedAt.Equal(t2) {
		t.Fatalf("first interval: %+v", rows[0].Placement)
	}
	if !rows[1].FirstSeen.Equal(t4) || rows[1].RemovedAt != nil {
		t.Fatalf("second interval: %+v", rows[1].Placement)
	}

	cur, total, err := db.ListAssetComponents(ctx, asset, store.AssetComponentFilter{}, store.Page{})
	ivMust(t, err)
	if total != 3 {
		t.Fatalf("current: %d", total)
	}
	for _, r := range cur {
		if r.Component.Name == "openssl" && !r.FirstSeen.Equal(t1) {
			t.Fatalf("openssl first seen moved: %v", r.FirstSeen)
		}
	}

	// A changed location is an update, not a new interval.
	obs := ivPkgObs(openssl, bash, curl)
	obs[0].Locations = []string{"/var/lib/dpkg/status.d/openssl"}
	res, err = db.ReplaceAssetComponents(ctx, scope, obs, store.ReplaceOptions{At: t4})
	ivMust(t, err)
	if res.Changed != 1 || res.Added != 0 {
		t.Fatalf("change: %+v", res)
	}

	if _, err := db.ReplaceAssetComponents(ctx, store.ComponentScope{AssetID: "00000000-0000-7000-8000-000000000000", Source: store.SourcePackages},
		nil, store.ReplaceOptions{}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing asset: %v", err)
	}
}

func TestComponentsDeduplicatedAcrossAssets(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	a1, a2 := ivHost(t, db, "a1"), ivHost(t, db, "a2")
	openssl := ivDeb("openssl", "3.0.13-0ubuntu3")
	other := openssl
	other.Arch = "arm64"

	r1, err := db.ReplaceAssetComponents(ctx, store.ComponentScope{AssetID: a1, Source: store.SourcePackages},
		ivPkgObs(openssl), store.ReplaceOptions{At: ivT0})
	ivMust(t, err)
	r2, err := db.ReplaceAssetComponents(ctx, store.ComponentScope{AssetID: a2, Source: store.SourcePackages},
		ivPkgObs(openssl, other), store.ReplaceOptions{At: ivT0})
	ivMust(t, err)
	if len(r1.NewComponents) != 1 || len(r2.NewComponents) != 1 {
		t.Fatalf("new components: %v %v", r1.NewComponents, r2.NewComponents)
	}
	if n := ivCount(t, db, `SELECT count(*) FROM components`); n != 2 {
		t.Fatalf("components: %d", n)
	}

	// Duplicate observations in one call are merged.
	jar := store.Component{Type: "maven", Name: "log4j-core", Version: "2.17.1", PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"}
	_, err = db.ReplaceAssetComponents(ctx, store.ComponentScope{AssetID: a1, Source: store.SourceArtifacts}, []store.ComponentObservation{
		{Component: jar, Locations: []string{"/opt/b.jar"}, Method: store.DetectManifest},
		{Component: jar, Locations: []string{"/opt/a.jar"}, Method: store.DetectManifest, InUse: true},
	}, store.ReplaceOptions{At: ivT0})
	ivMust(t, err)

	comps, total, err := db.ListComponents(ctx, store.ComponentFilter{Q: "openssl", Sort: "-assets"}, store.Page{})
	ivMust(t, err)
	if total != 2 || comps[0].Assets != 2 || comps[0].Arch != "amd64" || comps[1].Assets != 1 {
		t.Fatalf("components: %+v", comps)
	}
	got, err := db.GetComponent(ctx, comps[0].ID)
	ivMust(t, err)
	if got.Assets != 2 || got.PURL != openssl.PURL {
		t.Fatalf("get component: %+v", got)
	}
	if _, err := db.GetComponent(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("get missing: %v", err)
	}

	where, total, err := db.ListComponentAssets(ctx, comps[0].ID, store.ComponentAssetFilter{Sort: "asset"}, store.Page{Limit: 1})
	ivMust(t, err)
	if total != 2 || len(where) != 1 || where[0].Asset.Name != "a1" {
		t.Fatalf("component assets: %d %+v", total, where)
	}
	where, _, err = db.ListComponentAssets(ctx, comps[0].ID, store.ComponentAssetFilter{Sort: "asset"}, store.Page{Limit: 1, Offset: 1})
	ivMust(t, err)
	if len(where) != 1 || where[0].Asset.Name != "a2" {
		t.Fatalf("component assets page 2: %+v", where)
	}

	mav, total, err := db.ListComponents(ctx, store.ComponentFilter{Type: "maven", Source: store.SourceArtifacts}, store.Page{})
	ivMust(t, err)
	if total != 1 {
		t.Fatalf("maven: %d", total)
	}
	placed, _, err := db.ListComponentAssets(ctx, mav[0].ID, store.ComponentAssetFilter{}, store.Page{})
	ivMust(t, err)
	if len(placed) != 1 || !placed[0].InUse || len(placed[0].Locations) != 2 || placed[0].Locations[0] != "/opt/a.jar" {
		t.Fatalf("merged observation: %+v", placed)
	}

	if _, _, err := db.ListComponents(ctx, store.ComponentFilter{Sort: "bogus"}, store.Page{}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("bad sort: %v", err)
	}

	// File hashes resolve to components.
	ivMust(t, db.RecordFileHashes(ctx, []store.FileHash{{SHA256: "abc", ComponentID: mav[0].ID, Path: "/opt/a.jar"}}, ivT0))
	m, err := db.ComponentsByFileHash(ctx, []string{"abc", "def"})
	ivMust(t, err)
	if len(m) != 1 || m["abc"] != mav[0].ID {
		t.Fatalf("file hashes: %v", m)
	}
}

func TestImageContentSharedByDigest(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	h1, h2 := ivHost(t, db, "h1"), ivHost(t, db, "h2")
	const digest = "sha256:1111"
	musl := store.Component{Type: "apk", Name: "musl", Version: "1.2.4-r2", Distro: "alpine-3.19", PURL: "pkg:apk/alpine/musl@1.2.4-r2"}
	busybox := store.Component{Type: "apk", Name: "busybox", Version: "1.36.1-r15", Distro: "alpine-3.19", PURL: "pkg:apk/alpine/busybox@1.36.1-r15"}

	for _, h := range []string{h1, h2} {
		ivMust(t, db.ReplaceContainers(ctx, h, []store.ContainerObservation{{
			Name: "nginx", ImageRef: "nginx:1.25-alpine", ImageDigest: digest, Runtime: store.RuntimeDocker, Instances: 1,
		}}, store.ReplaceOptions{At: ivT0}))
	}
	known, err := db.KnownImageContent(ctx, []string{digest})
	ivMust(t, err)
	if len(known) != 0 {
		t.Fatalf("known before: %v", known)
	}
	imgs, _, err := db.ListImages(ctx, store.ImageFilter{}, store.Page{})
	ivMust(t, err)
	if len(imgs) != 1 || imgs[0].ContentKnown() || imgs[0].Assets != 2 || imgs[0].Instances != 2 ||
		len(imgs[0].RepoTags) != 1 || imgs[0].RepoTags[0] != "nginx:1.25-alpine" {
		t.Fatalf("image before content: %+v", imgs)
	}

	written, err := db.PutImageContent(ctx, store.ImageContent{
		Digest: digest, Coverage: store.CoveragePartial, CollectedAt: ivT0,
		Packages: ivPkgObs(musl, busybox),
	})
	ivMust(t, err)
	if !written {
		t.Fatal("first content not written")
	}
	// Second write with the same coverage is skipped.
	written, err = db.PutImageContent(ctx, store.ImageContent{Digest: digest, Coverage: store.CoveragePartial, Packages: ivPkgObs(musl)})
	ivMust(t, err)
	if written {
		t.Fatal("content written twice")
	}

	for _, h := range []string{h1, h2} {
		rows, total, err := db.ListAssetComponents(ctx, h, store.AssetComponentFilter{}, store.Page{})
		ivMust(t, err)
		if total != 2 || rows[0].Container != "nginx" || rows[0].Layer != store.LayerImage {
			t.Fatalf("asset %s image components: %d %+v", h, total, rows)
		}
	}
	host := ""
	rows, _, err := db.ListAssetComponents(ctx, h1, store.AssetComponentFilter{Container: &host}, store.Page{})
	ivMust(t, err)
	if len(rows) != 0 {
		t.Fatalf("host-only filter: %+v", rows)
	}

	// Full coverage replaces partial content.
	written, err = db.PutImageContent(ctx, store.ImageContent{Digest: digest, Coverage: store.CoverageFull, Packages: ivPkgObs(musl)})
	ivMust(t, err)
	if !written {
		t.Fatal("full content not written")
	}
	ic, total, err := db.ListImageComponents(ctx, digest, store.ImageComponentFilter{}, store.Page{})
	ivMust(t, err)
	if total != 1 || ic[0].Component.Name != "musl" {
		t.Fatalf("image components: %+v", ic)
	}

	known, err = db.KnownImageContent(ctx, []string{digest, "sha256:2222"})
	ivMust(t, err)
	if len(known) != 1 {
		t.Fatalf("known after: %v", known)
	}
	musls, _, err := db.ListComponents(ctx, store.ComponentFilter{Q: "musl"}, store.Page{})
	ivMust(t, err)
	if len(musls) != 1 || musls[0].Assets != 2 {
		t.Fatalf("musl installs: %+v", musls)
	}
	where, _, err := db.ListComponentAssets(ctx, musls[0].ID, store.ComponentAssetFilter{}, store.Page{})
	ivMust(t, err)
	if len(where) != 2 || where[0].Layer != store.LayerImage {
		t.Fatalf("musl assets: %+v", where)
	}

	known2 := true
	kimgs, total, err := db.ListImages(ctx, store.ImageFilter{ContentKnown: &known2, Q: "1.25"}, store.Page{})
	ivMust(t, err)
	if total != 1 || !kimgs[0].ContentKnown() || kimgs[0].ContentCoverage != store.CoverageFull {
		t.Fatalf("known images: %+v", kimgs)
	}
	detail, err := db.GetImage(ctx, digest)
	ivMust(t, err)
	if len(detail.Uses) != 2 || detail.Uses[0].Container.Name != "nginx" {
		t.Fatalf("image uses: %+v", detail.Uses)
	}
	if _, err := db.GetImage(ctx, "sha256:none"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing image: %v", err)
	}
}

func TestReplaceAssetComponentsLarge(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	asset := ivHost(t, db, "big")
	var cs []store.Component
	for i := range 3000 {
		cs = append(cs, ivDeb(fmt.Sprintf("pkg%04d", i), "1.0"))
	}
	start := time.Now()
	res, err := db.ReplaceAssetComponents(ctx, store.ComponentScope{AssetID: asset, Source: store.SourcePackages},
		ivPkgObs(cs...), store.ReplaceOptions{At: ivT0})
	ivMust(t, err)
	if res.Added != 3000 {
		t.Fatalf("added %d", res.Added)
	}
	res, err = db.ReplaceAssetComponents(ctx, store.ComponentScope{AssetID: asset, Source: store.SourcePackages},
		ivPkgObs(cs[:2990]...), store.ReplaceOptions{At: ivT0.Add(time.Hour)})
	ivMust(t, err)
	if res.Removed != 10 || res.Added != 0 {
		t.Fatalf("second: %+v", res)
	}
	t.Logf("two replaces of 3000 packages: %v", time.Since(start))

	page, total, err := db.ListAssetComponents(ctx, asset, store.AssetComponentFilter{Sort: "-name"}, store.Page{Limit: 10, Offset: 10})
	ivMust(t, err)
	if total != 2990 || len(page) != 10 || page[0].Component.Name != "pkg2979" {
		t.Fatalf("page: %d %d %s", total, len(page), page[0].Component.Name)
	}
}
