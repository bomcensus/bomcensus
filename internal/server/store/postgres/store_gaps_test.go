// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

func TestSectionBaseline(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	a := ivHost(t, db, "h")
	baseline := func() store.Coverage {
		t.Helper()
		d, err := db.GetAsset(ctx, a)
		ivMust(t, err)
		return d.Sections[0].Baseline
	}
	set := func(c store.Coverage, at time.Duration) {
		t.Helper()
		ivMust(t, db.SetSectionStates(ctx, a, []store.SectionState{{Section: "packages", Coverage: c, CollectedAt: ivT0.Add(at)}}))
	}
	set(store.CoveragePartial, 0)
	if b := baseline(); b != store.CoveragePartial {
		t.Fatalf("first state: %s", b)
	}
	set(store.CoverageFull, time.Hour)
	set(store.CoveragePartial, 2*time.Hour)
	set(store.CoverageNone, 3*time.Hour)
	if b := baseline(); b != store.CoverageFull {
		t.Fatalf("reduced reports lowered the baseline: %s", b)
	}
	set(store.CoverageFull, 4*time.Hour)
	if b := baseline(); b != store.CoverageFull {
		t.Fatalf("full again: %s", b)
	}
}

func TestAssetQueries(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	web := ivHost(t, db, "web")
	ivMust(t, db.UpdateAssetFacts(ctx, web, store.AssetFacts{Group: "prod", Tags: []string{"dmz", "web"}}))
	dbh := ivHost(t, db, "db")
	ivMust(t, db.UpdateAssetFacts(ctx, dbh, store.AssetFacts{Group: "prod", Tags: []string{"dmz-old"}}))
	ivMust(t, db.UpdateAssetFacts(ctx, ivHost(t, db, "ci"), store.AssetFacts{Group: "build"}))
	ivMust(t, db.ReplaceContainers(ctx, web, []store.ContainerObservation{
		{Name: "a", ImageRef: "nginx:1", ImageDigest: "sha256:aa", Instances: 1},
		{Name: "b", ImageRef: "nginx:1", ImageDigest: "sha256:aa", Instances: 1},
		{Name: "c", ImageRef: "redis:7", ImageDigest: "sha256:bb", Instances: 1},
	}, store.ReplaceOptions{At: ivT0}))

	rows, n, err := db.ListAssets(ctx, store.AssetFilter{Tag: "dmz"}, store.Page{})
	ivMust(t, err)
	if n != 1 || rows[0].ID != web || !reflect.DeepEqual(rows[0].Images, []string{"nginx:1", "redis:7"}) || rows[0].Containers != 3 {
		t.Fatalf("tag filter: %d %+v", n, rows)
	}
	groups, n, err := db.ListAssetGroups(ctx, store.AssetGroupFilter{Sort: "-assets"}, store.Page{})
	ivMust(t, err)
	if n != 2 || !reflect.DeepEqual(groups, []store.AssetGroupRow{{Name: "prod", Assets: 2}, {Name: "build", Assets: 1}}) {
		t.Fatalf("groups: %+v", groups)
	}
	if _, _, err := db.ListAssetGroups(ctx, store.AssetGroupFilter{Sort: "size"}, store.Page{}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("bad sort: %v", err)
	}

	ivMust(t, db.MarkCollectRequested(ctx, web, ivT0.Add(time.Hour)))
	if d, _ := db.GetAsset(ctx, web); d.CollectRequestedAt == nil || !d.CollectRequestedAt.Equal(ivT0.Add(time.Hour)) {
		t.Fatalf("collect requested: %v", d.CollectRequestedAt)
	}
	ivMust(t, db.UpdateAssetFacts(ctx, web, store.AssetFacts{SeenAt: ivT0.Add(2 * time.Hour)}))
	if d, _ := db.GetAsset(ctx, web); d.CollectRequestedAt != nil {
		t.Fatal("newer report kept the request")
	}
	if err := db.MarkCollectRequested(ctx, uuid.NewString(), ivT0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown asset: %v", err)
	}

	inv, err := db.Dashboard(ctx)
	ivMust(t, err)
	if inv.Assets != 3 || inv.Hosts != 3 || inv.Workloads != 0 {
		t.Fatalf("dashboard: %+v", inv)
	}
}

func TestScanTargetHostIdentity(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	cred, err := db.CreateCredential(ctx, store.Credential{Name: "k", Kind: store.CredentialSSHPassword, Secret: []byte("x")})
	ivMust(t, err)
	tg, err := db.CreateScanTarget(ctx, store.ScanTarget{Name: "t", Address: "10.0.0.1", Port: 22, CredentialID: cred.ID})
	ivMust(t, err)
	id := store.HostIdentity{ScanTargetID: tg.ID, Address: tg.Address}
	r1, err := db.UpsertHostAsset(ctx, id, store.AssetInit{Name: "t", Method: store.CollectSSH})
	ivMust(t, err)
	r2, err := db.UpsertHostAsset(ctx, id, store.AssetInit{Name: "t", Method: store.CollectSSH})
	ivMust(t, err)
	if !r1.Created || r2.Created || r2.ID != r1.ID {
		t.Fatalf("refs %+v %+v", r1, r2)
	}
	tg, err = db.GetScanTarget(ctx, tg.ID)
	ivMust(t, err)
	d, err := db.GetAsset(ctx, r1.ID)
	ivMust(t, err)
	if tg.AssetID != r1.ID || d.ScanTargetID != tg.ID || d.ScannerID != "" || d.Address != "10.0.0.1" {
		t.Fatalf("link: target %+v asset %+v", tg, d.Asset)
	}
	if _, err := db.UpsertHostAsset(ctx, store.HostIdentity{ScanTargetID: uuid.NewString()}, store.AssetInit{}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown target: %v", err)
	}
}

func TestComponentLookups(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	a := ivHost(t, db, "h")
	tool := store.Component{Type: "binary", Name: "tool", Version: "1", PURL: "pkg:generic/tool@1"}
	obs := []store.ComponentObservation{
		{Component: ivDeb("bash", "5"), Locations: []string{"/usr/bin/bash"}},
		{Component: ivDeb("coreutils", "9"), Locations: []string{"/usr/bin/ls", "/usr/bin/cat"}},
		{Component: ivDeb("bash", "5"), Locations: []string{"/bin/bash"}},
	}
	res, err := db.ReplaceAssetComponents(ctx, store.ComponentScope{AssetID: a, Source: store.SourcePackages}, obs,
		store.ReplaceOptions{At: ivT0})
	ivMust(t, err)
	if len(res.ComponentIDs) != 3 || res.ComponentIDs[0] == "" || res.ComponentIDs[0] != res.ComponentIDs[2] ||
		res.ComponentIDs[1] == res.ComponentIDs[0] {
		t.Fatalf("component ids %v", res.ComponentIDs)
	}
	bash, coreutils := res.ComponentIDs[0], res.ComponentIDs[1]
	ivMust(t, db.ReplaceContainers(ctx, a, []store.ContainerObservation{{Name: "app", ImageDigest: "sha256:cc", Instances: 1}},
		store.ReplaceOptions{At: ivT0}))
	_, err = db.PutImageContent(ctx, store.ImageContent{Digest: "sha256:cc", CollectedAt: ivT0,
		Artifacts: []store.ComponentObservation{{Component: tool, Locations: []string{"/usr/bin/tool"}}}})
	ivMust(t, err)

	got, err := db.ComponentsAtLocations(ctx, a, []store.ComponentLocation{
		{Path: "/bin/bash"}, {Path: "/usr/bin/cat"}, {Path: "/usr/bin/tool"},
		{Container: "app", Path: "/usr/bin/tool"}, {Container: "app", Path: "/usr/bin/cat"}, {Container: "gone", Path: "/x"},
	})
	ivMust(t, err)
	ids, err := db.LookupComponentIDs(ctx, []store.Component{tool, ivDeb("missing", "0"), ivDeb("bash", "5")})
	ivMust(t, err)
	want := map[store.ComponentLocation]string{
		{Path: "/bin/bash"}:                       bash,
		{Path: "/usr/bin/cat"}:                    coreutils,
		{Container: "app", Path: "/usr/bin/tool"}: ids[0],
	}
	if !reflect.DeepEqual(got, want) || ids[0] == "" || ids[1] != "" || ids[2] != bash {
		t.Fatalf("locations %v, ids %v", got, ids)
	}

	// Layer and in-use filters of the asset's components.
	_, err = db.ReplaceAssetComponents(ctx, store.ComponentScope{AssetID: a, Container: "app", Source: store.SourceArtifacts,
		Layer: store.LayerRuntime}, []store.ComponentObservation{{Component: tool, InUse: true}}, store.ReplaceOptions{At: ivT0})
	ivMust(t, err)
	no := false
	for _, c := range []struct {
		f    store.AssetComponentFilter
		want int
	}{
		{store.AssetComponentFilter{Layer: store.LayerImage}, 1},
		{store.AssetComponentFilter{Layer: store.LayerRuntime}, 1},
		{store.AssetComponentFilter{InUse: &no}, 3},
	} {
		if _, n, err := db.ListAssetComponents(ctx, a, c.f, store.Page{}); err != nil || n != c.want {
			t.Fatalf("filter %+v: %d %v", c.f, n, err)
		}
	}

	img, _, err := db.ListImages(ctx, store.ImageFilter{}, store.Page{})
	ivMust(t, err)
	if len(img) != 1 || img[0].Components != 1 {
		t.Fatalf("image rows %+v", img)
	}

	// Installations with the full asset row and history.
	ca, n, err := db.ListComponentAssets(ctx, ids[0], store.ComponentAssetFilter{Method: ""}, store.Page{})
	ivMust(t, err)
	if n != 2 || ca[0].Asset.Name != "h" || ca[0].Asset.Containers != 1 || ca[0].Asset.Method != store.CollectAgent {
		t.Fatalf("component assets %d %+v", n, ca)
	}
	yes := true
	if _, n, _ := db.ListComponentAssets(ctx, ids[0], store.ComponentAssetFilter{InUse: &yes}, store.Page{}); n != 1 {
		t.Fatalf("in use: %d", n)
	}
	ivMust(t, db.ReplaceContainers(ctx, a, nil, store.ReplaceOptions{At: ivT0.Add(time.Hour)}))
	if _, n, _ := db.ListComponentAssets(ctx, ids[0], store.ComponentAssetFilter{}, store.Page{}); n != 1 {
		t.Fatalf("after container gone: %d", n)
	}
	hist, n, err := db.ListComponentAssets(ctx, ids[0], store.ComponentAssetFilter{IncludeRemoved: true}, store.Page{})
	ivMust(t, err)
	if n != 2 {
		t.Fatalf("history: %d %+v", n, hist)
	}
}

func TestClusterStatusAndLookups(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	c, err := db.CreateCluster(ctx, store.K8sClusterConfig{Name: "a", Connection: store.K8sInCluster, ExecEnabled: true})
	ivMust(t, err)
	if c.SyncStatus != store.K8sSyncNever || c.Workloads != 0 {
		t.Fatalf("new cluster %+v", c)
	}
	_, err = db.CreateCluster(ctx, store.K8sClusterConfig{Name: "b", Connection: store.K8sInCluster})
	ivMust(t, err)
	ivMust(t, db.RecordClusterSync(ctx, c.ID, store.K8sSyncFailed, "forbidden", ivT0))
	_, err = db.ReplaceClusterInventory(ctx, c.ID, store.K8sInventory{At: ivT0.Add(time.Minute), Workloads: []store.K8sWorkloadObservation{
		{Namespace: "ns", Kind: "Deployment", Name: "api", Replicas: 3,
			Pods: []store.K8sPodObservation{{Name: "api-1", Phase: "Running", StartedAt: ivT0}}},
		{Namespace: "ns", Kind: "DaemonSet", Name: "agent", Excluded: true, ExcludedBy: "label"},
	}})
	ivMust(t, err)
	c, err = db.GetCluster(ctx, c.ID)
	ivMust(t, err)
	if c.SyncStatus != store.K8sSyncOK || c.SyncMessage != "" || c.Workloads != 2 || c.Excluded != 1 {
		t.Fatalf("after inventory %+v", c)
	}
	ivMust(t, db.RecordClusterSync(ctx, c.ID, store.K8sSyncFailed, "stale", ivT0))
	ivMust(t, db.RecordClusterSync(ctx, c.ID, store.K8sSyncFailed, "timeout", ivT0.Add(time.Hour)))
	if c, _ = db.GetCluster(ctx, c.ID); c.SyncStatus != store.K8sSyncFailed || c.SyncMessage != "timeout" {
		t.Fatalf("failed sync %+v", c)
	}
	if err := db.RecordClusterSync(ctx, uuid.NewString(), store.K8sSyncOK, "", ivT0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown cluster: %v", err)
	}
	rows, _, err := db.ListClusters(ctx, store.ClusterFilter{Sort: "-exec_enabled"}, store.Page{})
	ivMust(t, err)
	if rows[0].Name != "a" || rows[0].Workloads != 2 {
		t.Fatalf("sorted %+v", rows)
	}

	pod, err := db.GetPod(ctx, c.ID, "ns", "api-1")
	ivMust(t, err)
	w, err := db.GetWorkload(ctx, pod.WorkloadID)
	ivMust(t, err)
	if w.Name != "api" || w.Replicas != 3 || w.AssetID == "" {
		t.Fatalf("workload %+v", w)
	}
	d, err := db.GetAsset(ctx, w.AssetID)
	ivMust(t, err)
	if d.WorkloadID != w.ID || d.Replicas != 3 {
		t.Fatalf("asset workload %q %d", d.WorkloadID, d.Replicas)
	}
	if _, err := db.GetPod(ctx, c.ID, "ns", "api-2"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing pod: %v", err)
	}
	if _, err := db.GetWorkload(ctx, uuid.NewString()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing workload: %v", err)
	}
}

func TestRawReportSender(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	id, err := db.StoreReport(ctx, store.RawReport{SourceID: "s", SenderKind: store.AgentKindScanner, RemoteAddr: "10.1.1.1:9",
		SubjectKind: "self", Body: []byte{1}})
	ivMust(t, err)
	r, err := db.GetReport(ctx, id)
	ivMust(t, err)
	if r.SenderKind != store.AgentKindScanner || r.RemoteAddr != "10.1.1.1:9" {
		t.Fatalf("report %+v", r)
	}
}

func TestManageStoreGaps(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)

	// Revoked certificates since a time, directly or through the agent.
	a1 := mgTestAgent(t, db, nil)
	a2 := mgTestAgent(t, db, func(a *store.Agent) { a.ObservedIssuer = "CN=proxy" })
	for i, a := range []store.Agent{a1, a1, a2} {
		ivMust(t, db.InsertAgentCert(ctx, store.AgentCert{Serial: string(rune('a' + i)), AgentID: a.ID,
			NotBefore: mgT0, NotAfter: mgT0.Add(24 * time.Hour)}))
	}
	if n, err := db.RevokeAgentCerts(ctx, a1.ID, mgT0.Add(time.Hour)); err != nil || n != 2 {
		t.Fatalf("revoke certs: %d %v", n, err)
	}
	ivMust(t, db.RevokeAgent(ctx, a2.ID, mgT0.Add(2*time.Hour)))
	serials := func(since time.Time) []string {
		t.Helper()
		cs, err := db.ListRevokedAgentCerts(ctx, since)
		ivMust(t, err)
		var out []string
		for _, c := range cs {
			if c.RevokedAt == nil {
				t.Fatalf("cert %s without revocation time", c.Serial)
			}
			out = append(out, c.Serial)
		}
		return out
	}
	if got := serials(time.Time{}); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("all: %v", got)
	}
	if got := serials(mgT0.Add(90 * time.Minute)); !reflect.DeepEqual(got, []string{"c"}) {
		t.Fatalf("since: %v", got)
	}
	counts, err := db.CountAgents(ctx, mgT0)
	ivMust(t, err)
	if counts.TLSIntercepted != 0 {
		t.Fatalf("revoked agent counted as intercepted: %+v", counts)
	}
	mgTestAgent(t, db, func(a *store.Agent) { a.ObservedIssuer = "CN=proxy" })
	if counts, _ = db.CountAgents(ctx, mgT0); counts.TLSIntercepted != 1 {
		t.Fatalf("intercepted: %+v", counts)
	}

	// Credential secret rotation keeps name and kind.
	c, err := db.CreateCredential(ctx, store.Credential{Name: "k", Kind: store.CredentialSSHKey, Username: "root",
		Secret: []byte("old"), PublicKeyFingerprint: "SHA256:old"})
	ivMust(t, err)
	if c.PublicKeyFingerprint != "SHA256:old" {
		t.Fatalf("created %+v", c)
	}
	u, err := db.UpdateCredentialSecret(ctx, store.Credential{ID: c.ID, Username: "admin", Secret: []byte("new"),
		PublicKeyFingerprint: "SHA256:new"})
	ivMust(t, err)
	full, err := db.GetCredentialWithSecret(ctx, c.ID)
	ivMust(t, err)
	if u.Name != "k" || u.Kind != store.CredentialSSHKey || u.Username != "admin" || u.PublicKeyFingerprint != "SHA256:new" ||
		string(full.Secret) != "new" {
		t.Fatalf("rotated %+v", full)
	}
	if _, err := db.UpdateCredentialSecret(ctx, store.Credential{ID: uuid.NewString(), Secret: []byte("x")}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rotate missing: %v", err)
	}

	// Host key reset.
	tg, err := db.CreateScanTarget(ctx, store.ScanTarget{Name: "t", Address: "h", Port: 22, CredentialID: c.ID, HostKey: []byte("key")})
	ivMust(t, err)
	ivMust(t, db.ClearScanTargetHostKey(ctx, tg.ID))
	ivMust(t, db.SetScanTargetHostKey(ctx, tg.ID, []byte("other")))
	if tg, _ = db.GetScanTarget(ctx, tg.ID); string(tg.HostKey) != "other" {
		t.Fatalf("host key %q", tg.HostKey)
	}
	if err := db.ClearScanTargetHostKey(ctx, uuid.NewString()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("clear missing: %v", err)
	}

	// Listen target update.
	lt, err := db.CreateListenTarget(ctx, store.ListenTarget{Address: "a:1"})
	ivMust(t, err)
	_, err = db.CreateListenTarget(ctx, store.ListenTarget{Address: "b:1"})
	ivMust(t, err)
	ivMust(t, db.BindListenTargetAgent(ctx, lt.ID, a1.ID))
	_, err = db.AcquireListenLeases(ctx, "r1", time.Minute, mgT0, 0)
	ivMust(t, err)
	ivMust(t, db.RecordListenState(ctx, lt.ID, "r1", store.ListenFailed, "refused", mgT0))
	if _, err := db.UpdateListenTarget(ctx, store.ListenTarget{ID: lt.ID, Address: "b:1"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate address: %v", err)
	}
	same, err := db.UpdateListenTarget(ctx, store.ListenTarget{ID: lt.ID, Address: "a:1"})
	ivMust(t, err)
	if same.State != store.ListenFailed || same.LastError != "refused" {
		t.Fatalf("unchanged address reset state: %+v", same)
	}
	moved, err := db.UpdateListenTarget(ctx, store.ListenTarget{ID: lt.ID, Address: "c:1"})
	ivMust(t, err)
	if moved.Address != "c:1" || moved.State != store.ListenNew || moved.LastError != "" || moved.AgentID != a1.ID ||
		moved.LeaseOwner != "r1" {
		t.Fatalf("moved %+v", moved)
	}
}
