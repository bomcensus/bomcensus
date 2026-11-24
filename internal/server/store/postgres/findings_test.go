// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"slices"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

func TestFindings(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	srv, err := db.GetActiveFeedServer(ctx)
	ivMust(t, err)
	epoch := store.MatchEpoch{ServerID: srv.ID, Revision: 1, Rules: ""}

	asset := ivHost(t, db, "web-01")
	openssl, curl := ivDeb("openssl", "3.0.13-0ubuntu3"), ivDeb("curl", "8.5.0-2ubuntu10")
	_, err = db.ReplaceAssetComponents(ctx, store.ComponentScope{AssetID: asset, Source: store.SourcePackages},
		ivPkgObs(openssl, curl), store.ReplaceOptions{At: ivT0})
	ivMust(t, err)
	// A container whose image contains musl.
	musl := store.Component{Type: "apk", Name: "musl", Version: "1.2.5-r0", Distro: "alpine-3.20",
		PURL: "pkg:apk/alpine/musl@1.2.5-r0?distro=alpine-3.20", Origin: store.OriginDistro}
	const digest = "sha256:aaaa"
	ivMust(t, db.UpsertImages(ctx, store.ImageSource{Kind: store.ImageSourceAsset, ID: asset},
		[]store.ImageObservation{{Digest: digest, RepoTags: []string{"web:1"}}}, store.ReplaceOptions{At: ivT0}))
	_, err = db.PutImageContent(ctx, store.ImageContent{Digest: digest, Coverage: store.CoverageFull, CollectedAt: ivT0,
		Packages: []store.ComponentObservation{{Component: musl, Locations: []string{"/lib/apk/db/installed"}, Method: store.DetectPackageDB}}})
	ivMust(t, err)
	ivMust(t, db.ReplaceContainers(ctx, asset, []store.ContainerObservation{{Name: "web", ImageDigest: digest, ImageRef: "web:1",
		Runtime: store.RuntimeDocker, Instances: 1, Coverage: store.CoverageFull}}, store.ReplaceOptions{At: ivT0}))

	// Before matching, the asset is computed once with nothing.
	dirty, err := db.DirtyFindingAssets(ctx, 10)
	ivMust(t, err)
	if !slices.Contains(dirty, asset) {
		t.Fatalf("dirty %v", dirty)
	}
	in, err := db.FindingInputs(ctx, asset)
	ivMust(t, err)
	if len(in.Sources) != 0 || in.Kind != store.AssetHost {
		t.Fatalf("inputs before matching %+v", in)
	}
	_, err = db.ApplyFindings(ctx, asset, nil, in.Stamp)
	ivMust(t, err)
	if d, _ := db.DirtyFindingAssets(ctx, 10); slices.Contains(d, asset) {
		t.Fatal("still dirty after refresh")
	}

	// Matching gives openssl and musl vulnerabilities: the asset is dirty.
	pending, err := db.PendingMatches(ctx, epoch, 10)
	ivMust(t, err)
	ids := map[string]string{}
	for _, c := range pending {
		ids[c.Name] = c.ID
	}
	ivMust(t, db.SaveMatches(ctx, store.MatchBatch{Epoch: epoch,
		Components: []store.ComponentMatch{
			{ComponentID: ids["openssl"], Status: store.MatchChecked, Vulns: []store.ComponentVuln{{VulnID: "CVE-1", Method: "package", FixState: "fixed"}}},
			{ComponentID: ids["curl"], Status: store.MatchChecked},
			{ComponentID: ids["musl"], Status: store.MatchChecked, Vulns: []store.ComponentVuln{{VulnID: "CVE-2", Method: "package", FixState: "not_fixed"}}},
		},
		Vulns: []store.VulnMeta{{ID: "CVE-1"}, {ID: "CVE-2"}}}))
	if d, _ := db.DirtyFindingAssets(ctx, 10); !slices.Contains(d, asset) {
		t.Fatal("not dirty after vulnerabilities changed")
	}

	ivMust(t, db.SetSectionStates(ctx, asset, []store.SectionState{{Section: "processes", Coverage: store.CoverageFull, CollectedAt: ivT0}}))
	_, err = db.ReplaceProcesses(ctx, store.ProcessScope{AssetID: asset}, store.ProcessSnapshot{At: ivT0, Processes: []store.ProcessObservation{
		{PID: 10, Exe: "/usr/sbin/nginx", StartedAt: ivT0, Packages: []string{"openssl", "nginx"},
			Listen: []store.ListenAddr{{Proto: "tcp", Address: "0.0.0.0", Port: 443}, {Proto: "tcp", Address: "127.0.0.1", Port: 8080}}},
		{PID: 20, Exe: "/bin/busybox", StartedAt: ivT0, Container: "web", Packages: []string{"busybox"}},
	}})
	ivMust(t, err)

	in, err = db.FindingInputs(ctx, asset)
	ivMust(t, err)
	if len(in.Sources) != 2 || in.ProcessCoverage[""] != store.CoverageFull || len(in.Processes) != 2 {
		t.Fatalf("inputs %+v", in)
	}
	var nginx store.FindingProcess
	for _, p := range in.Processes {
		if p.PID == 10 {
			nginx = p
		}
	}
	if !slices.Equal(nginx.Ports, []string{"tcp/443"}) || !slices.Equal(nginx.Packages, []string{"openssl", "nginx"}) {
		t.Fatalf("nginx %+v", nginx)
	}
	for _, s := range in.Sources {
		switch s.Component.Name {
		case "openssl":
			if s.Container != "" || s.Layer != "" || !slices.Equal(s.VulnIDs, []string{"CVE-1"}) {
				t.Fatalf("openssl source %+v", s)
			}
		case "musl":
			if s.Container != "web" || s.Layer != store.FindingLayerImage || s.ImageDigest != digest {
				t.Fatalf("musl source %+v", s)
			}
		default:
			t.Fatalf("source %+v", s)
		}
	}

	rows := []store.FindingRow{
		{ComponentID: ids["openssl"], VulnID: "CVE-1", Exposure: store.ExposureListening,
			Processes: []store.FindingProcessRef{{PID: 10, Exe: "/usr/sbin/nginx", Ports: []string{"tcp/443"}}}},
		{Container: "web", Layer: store.FindingLayerImage, ImageDigest: digest, ComponentID: ids["musl"], VulnID: "CVE-2", Exposure: store.ExposureInstalled},
	}
	ch, err := db.ApplyFindings(ctx, asset, rows, in.Stamp)
	ivMust(t, err)
	if ch != (store.FindingsChange{Opened: 2}) {
		t.Fatalf("first apply %+v", ch)
	}
	// Same rows again: nothing opens.
	if ch, _ = db.ApplyFindings(ctx, asset, rows, in.Stamp); ch != (store.FindingsChange{}) {
		t.Fatalf("second apply %+v", ch)
	}
	if n := ivCount(t, db, `SELECT count(*) FROM findings WHERE asset_id = $1 AND resolved_at IS NULL`, asset); n != 2 {
		t.Fatalf("open findings %d", n)
	}

	// A newer report makes the asset dirty; the container's image is gone
	// from the new set, so its finding resolves; the exposure of the kept
	// one changes in place.
	ivMust(t, func() error {
		_, err := db.q.Exec(ctx, `UPDATE assets SET last_seen = last_seen + interval '1 minute' WHERE id = $1`, asset)
		return err
	}())
	if d, _ := db.DirtyFindingAssets(ctx, 10); !slices.Contains(d, asset) {
		t.Fatal("not dirty after a new report")
	}
	in, err = db.FindingInputs(ctx, asset)
	ivMust(t, err)
	rows[0].Exposure, rows[0].Processes = store.ExposureRunning, nil
	ch, err = db.ApplyFindings(ctx, asset, rows[:1], in.Stamp)
	ivMust(t, err)
	if ch != (store.FindingsChange{Resolved: 1}) {
		t.Fatalf("third apply %+v", ch)
	}
	var exposure string
	var first time.Time
	ivMust(t, db.q.QueryRow(ctx, `SELECT exposure, first_seen FROM findings WHERE asset_id = $1 AND vuln_id = 'CVE-1' AND resolved_at IS NULL`, asset).Scan(&exposure, &first))
	if exposure != store.ExposureRunning {
		t.Fatalf("exposure %s", exposure)
	}

	// A gone asset is dirty and its findings resolve.
	ivMust(t, func() error {
		_, err := db.q.Exec(ctx, `UPDATE assets SET gone_at = now() WHERE id = $1`, asset)
		return err
	}())
	if d, _ := db.DirtyFindingAssets(ctx, 10); !slices.Contains(d, asset) {
		t.Fatal("gone asset not dirty")
	}
	in, err = db.FindingInputs(ctx, asset)
	ivMust(t, err)
	if !in.Gone || len(in.Sources) != 0 {
		t.Fatalf("gone inputs %+v", in)
	}
	if ch, _ = db.ApplyFindings(ctx, asset, nil, in.Stamp); ch.Resolved != 1 {
		t.Fatalf("gone apply %+v", ch)
	}
	if d, _ := db.DirtyFindingAssets(ctx, 10); slices.Contains(d, asset) {
		t.Fatal("gone asset still dirty")
	}
}
