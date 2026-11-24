// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package inventoryapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/oapi-codegen/nullable"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/apierr"
	"github.com/bomcensus/bomcensus/internal/server/auth"
	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/internal/server/store/postgres"
)

// newTestDB creates a fresh database from BOMCENSUS_TEST_DATABASE_URL,
// migrates it and drops it when the test ends.
func newTestDB(t *testing.T) *postgres.DB {
	t.Helper()
	base := os.Getenv("BOMCENSUS_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("BOMCENSUS_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	name := "bomcensus_test_" + hex.EncodeToString(b[:])
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		admin.Close(ctx)
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			t.Errorf("drop database: %v", err)
		}
		admin.Close(ctx)
	})
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	db, err := postgres.Open(ctx, u.String())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(db.Close)
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// wantStatus checks that err renders as status.
func wantStatus(t *testing.T, what string, err error, status int) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: no error, want %d", what, status)
	}
	if got, _ := apierr.From(err); got != status {
		t.Fatalf("%s: status %d (%v), want %d", what, got, err, status)
	}
}

var t0 = time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)

const (
	digestNginx = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	digestAPI   = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

func deb(name, version string) store.ComponentObservation {
	return store.ComponentObservation{
		Component: store.Component{Type: "deb", Name: name, Version: version, Arch: "amd64", Distro: "ubuntu-24.04",
			PURL: "pkg:deb/ubuntu/" + name + "@" + version, Origin: store.OriginDistro},
		Locations: []string{"/var/lib/dpkg/status"},
		Method:    store.DetectPackageDB,
	}
}

type fixture struct {
	db        *postgres.DB
	h         *Handlers
	ctx       context.Context
	web, db1  string
	cluster   string
	scanner   string
	kubecfg   string
	sshCred   string
	workload  string
	apiAsset  string
	collector *fakeCollector
}

type fakeCollector struct {
	err   error
	calls []string
}

func (f *fakeCollector) RequestCollect(_ context.Context, id string) error {
	f.calls = append(f.calls, id)
	return f.err
}

func (f *fakeCollector) RequestSync(_ context.Context, id string) error {
	f.calls = append(f.calls, id)
	return f.err
}

func host(t *testing.T, db *postgres.DB, name string, facts store.AssetFacts) string {
	t.Helper()
	ctx := context.Background()
	ref, err := db.UpsertHostAsset(ctx, store.HostIdentity{AgentID: uuid.NewString()},
		store.AssetInit{Name: name, Method: store.CollectAgent, SeenAt: t0})
	must(t, err)
	must(t, db.UpdateAssetFacts(ctx, ref.ID, facts))
	return ref.ID
}

func seed(t *testing.T) *fixture {
	db := newTestDB(t)
	ctx := auth.WithPrincipal(context.Background(), auth.Principal{ID: "env:admin", Name: "admin"})
	f := &fixture{db: db, ctx: ctx, collector: &fakeCollector{}}

	f.web = host(t, db, "web-1", store.AssetFacts{Group: "prod", Tags: []string{"dmz"}, Address: "10.0.0.1",
		OS: store.OSInfo{Family: "linux", ID: "ubuntu", Name: "Ubuntu", Version: "24.04"}, Arch: "amd64",
		Coverage: store.CoverageFull, Privilege: store.PrivilegePrivileged})
	f.db1 = host(t, db, "db-1", store.AssetFacts{Group: "prod", Coverage: store.CoveragePartial, CoverageReason: "non-root"})
	host(t, db, "build", store.AssetFacts{})

	must(t, db.SetSectionStates(ctx, f.web, []store.SectionState{
		{Section: "packages", Coverage: store.CoverageFull, CollectedAt: t0},
		{Section: "processes", Coverage: store.CoveragePartial, Reason: "hidepid", CollectedAt: t0},
		{Container: "nginx", Section: "packages", Coverage: store.CoverageFull, CollectedAt: t0},
	}))
	_, err := db.ReplaceAssetComponents(ctx, store.ComponentScope{AssetID: f.web, Source: store.SourcePackages},
		[]store.ComponentObservation{deb("openssl", "3.0.13"), deb("curl", "8.5.0")}, store.ReplaceOptions{At: t0})
	must(t, err)
	_, err = db.ReplaceAssetComponents(ctx, store.ComponentScope{AssetID: f.db1, Source: store.SourcePackages},
		[]store.ComponentObservation{deb("openssl", "3.0.13")}, store.ReplaceOptions{At: t0})
	must(t, err)
	must(t, db.ReplaceContainers(ctx, f.web, []store.ContainerObservation{
		{Name: "nginx", ImageRef: "nginx:1.27", ImageDigest: digestNginx, Runtime: store.RuntimeDocker, Instances: 1,
			Coverage: store.CoverageFull},
	}, store.ReplaceOptions{At: t0}))
	must(t, db.UpsertImages(ctx, store.ImageSource{Kind: store.ImageSourceAsset, ID: f.web},
		[]store.ImageObservation{{Digest: digestNginx, RepoTags: []string{"nginx:1.27", "nginx:latest"},
			OS: "linux", Arch: "amd64", Size: 1000}}, store.ReplaceOptions{At: t0}))
	_, err = db.PutImageContent(ctx, store.ImageContent{Digest: digestNginx, Coverage: store.CoverageFull, CollectedAt: t0,
		Packages: []store.ComponentObservation{deb("nginx", "1.27.0"), deb("libc6", "2.39")}})
	must(t, err)
	_, err = db.ReplaceProcesses(ctx, store.ProcessScope{AssetID: f.web}, store.ProcessSnapshot{At: t0,
		Processes: []store.ProcessObservation{
			{PID: 1, User: "root", Exe: "/sbin/init", ExeSource: "proc", ExeState: store.ExeNormal, StartedAt: t0},
			{PID: 200, User: "www-data", Exe: "/usr/sbin/nginx", ExeSource: "proc", ExeState: store.ExeReplaced,
				StartedAt: t0, Container: "nginx", Packages: []string{"libc6", "nginx"},
				Listen: []store.ListenAddr{{Proto: "tcp", Address: "0.0.0.0", Port: 443}}},
			{PID: 300, User: "app", Exe: "/usr/bin/app", ExeSource: "cmdline", ExeState: store.ExeNormal, StartedAt: t0,
				Libs: []store.MappedLib{{Path: "/usr/lib/libssl.so.3", State: store.ExeDeleted}}},
		},
		UnownedPorts: []store.UnownedPort{{ListenAddr: store.ListenAddr{Proto: "udp", Address: "0.0.0.0", Port: 53}, UID: 101}},
	})
	must(t, err)

	sc, err := db.CreateAgent(ctx, store.Agent{Kind: store.AgentKindScanner, Hostname: "scanner-1",
		IdentityKey: []byte(uuid.NewString()), State: store.AgentApproved, EnrolledAt: t0})
	must(t, err)
	f.scanner = sc.ID
	_, err = db.CreateAgent(ctx, store.Agent{Kind: store.AgentKindAgent, Hostname: "web-1",
		IdentityKey: []byte(uuid.NewString()), State: store.AgentPending, EnrolledAt: t0})
	must(t, err)
	kc, err := db.CreateCredential(ctx, store.Credential{Name: "prd-kubeconfig", Kind: store.CredentialKubeconfig, Secret: []byte("x")})
	must(t, err)
	f.kubecfg = kc.ID
	ssh, err := db.CreateCredential(ctx, store.Credential{Name: "ssh", Kind: store.CredentialSSHPassword, Username: "u", Secret: []byte("x")})
	must(t, err)
	f.sshCred = ssh.ID

	c, err := db.CreateCluster(ctx, store.K8sClusterConfig{Name: "prd", Connection: store.K8sInCluster, ScannerID: f.scanner})
	must(t, err)
	f.cluster = c.ID
	pod := func(name string) store.K8sPodObservation {
		return store.K8sPodObservation{Name: name, Node: "node-1", Phase: "Running", StartedAt: t0,
			Containers: []store.K8sPodContainerObservation{{Name: "api", ImageRef: "registry/api:1", ImageDigest: digestAPI}}}
	}
	res, err := db.ReplaceClusterInventory(ctx, c.ID, store.K8sInventory{Version: "v1.30.2", At: t0,
		Workloads: []store.K8sWorkloadObservation{
			{Namespace: "shop", Kind: "Deployment", Name: "api", Replicas: 2, Pods: []store.K8sPodObservation{pod("api-a"), pod("api-b")}},
			{Namespace: "kube-system", Kind: "DaemonSet", Name: "proxy", Replicas: 3, Excluded: true, ExcludedBy: "namespace kube-*"},
		}})
	must(t, err)
	for _, w := range res.Workloads {
		if w.Name == "api" {
			f.workload, f.apiAsset = w.ID, w.AssetID
		}
	}

	f.h = New(Config{
		Store:        db,
		Agents:       db,
		Collector:    f.collector,
		Syncer:       f.collector,
		Credentials:  StoreCredentials{Store: db},
		AgentAddress: "bomcensus.example:8443",
		Now:          func() time.Time { return t0 },
	})
	return f
}

func names[T any](items []T, name func(T) string) string {
	var out []string
	for _, it := range items {
		out = append(out, name(it))
	}
	return strings.Join(out, ",")
}

func TestAssets(t *testing.T) {
	f := seed(t)
	h, ctx := f.h, f.ctx
	assetName := func(a gen.AssetSummary) string { return a.Name }

	list := func(p gen.ListAssetsParams) gen.ListAssets200JSONResponse {
		t.Helper()
		r, err := h.ListAssets(ctx, gen.ListAssetsRequestObject{Params: p})
		must(t, err)
		return r.(gen.ListAssets200JSONResponse)
	}
	all := list(gen.ListAssetsParams{})
	if all.Total != 4 || names(all.Items, assetName) != "api,build,db-1,web-1" {
		t.Fatalf("all: %d %s", all.Total, names(all.Items, assetName))
	}
	kind := gen.AssetKindHost
	if r := list(gen.ListAssetsParams{Kind: &kind}); r.Total != 3 {
		t.Fatalf("hosts: %d", r.Total)
	}
	cov := gen.ListAssetsParamsCoverage("limited")
	if r := list(gen.ListAssetsParams{Coverage: &cov}); names(r.Items, assetName) != "api,build,db-1" {
		t.Fatalf("limited: %s", names(r.Items, assetName))
	}
	sort := gen.ListAssetsParamsSort("-name")
	limit, offset := 2, 1
	r := list(gen.ListAssetsParams{Group: ptr("prod"), Sort: &sort})
	if names(r.Items, assetName) != "web-1,db-1" {
		t.Fatalf("group sorted: %s", names(r.Items, assetName))
	}
	r = list(gen.ListAssetsParams{Sort: &sort, Limit: &limit, Offset: &offset})
	if r.Total != 4 || names(r.Items, assetName) != "db-1,build" {
		t.Fatalf("paged: %d %s", r.Total, names(r.Items, assetName))
	}
	r = list(gen.ListAssetsParams{Q: ptr("WEB")})
	if len(r.Items) != 1 {
		t.Fatalf("q: %s", names(r.Items, assetName))
	}
	web := r.Items[0]
	if web.Group != "prod" || len(web.Tags) != 1 || web.Os == nil || web.Os.Name != "Ubuntu" || web.ContainerCount != 1 ||
		web.Coverage != gen.CoverageFull || web.Privilege == nil || *web.Privilege != gen.Privileged ||
		web.Images == nil || strings.Join(*web.Images, ",") != "nginx:1.27" {
		t.Fatalf("summary: %+v", web)
	}
	if r := list(gen.ListAssetsParams{Q: ptr("nginx:1.27")}); names(r.Items, assetName) != "web-1" {
		t.Fatalf("q by image: %s", names(r.Items, assetName))
	}
	if r := list(gen.ListAssetsParams{Tag: ptr("dmz")}); names(r.Items, assetName) != "web-1" {
		t.Fatalf("tag: %s", names(r.Items, assetName))
	}
	if r := list(gen.ListAssetsParams{Tag: ptr("dm")}); r.Total != 0 {
		t.Fatalf("tag is not a substring match: %s", names(r.Items, assetName))
	}
	r = list(gen.ListAssetsParams{ClusterId: &f.cluster})
	if names(r.Items, assetName) != "api" || r.Items[0].ClusterName == nil || *r.Items[0].ClusterName != "prd" {
		t.Fatalf("cluster filter: %+v", r.Items)
	}

	bad := []gen.ListAssetsParams{
		{Sort: ptr(gen.ListAssetsParamsSort("containers"))},
		{Limit: ptr(0)},
		{Limit: ptr(1001)},
		{Offset: ptr(-1)},
		{Kind: ptr(gen.AssetKind("vm"))},
		{Q: ptr(strings.Repeat("x", 300))},
	}
	for i, p := range bad {
		_, err := h.ListAssets(ctx, gen.ListAssetsRequestObject{Params: p})
		wantStatus(t, "bad params "+string(rune('0'+i)), err, http.StatusBadRequest)
	}

	g, err := h.ListAssetGroups(ctx, gen.ListAssetGroupsRequestObject{})
	must(t, err)
	if gl := g.(gen.ListAssetGroups200JSONResponse); gl.Total != 1 || gl.Items[0] != (gen.AssetGroup{Name: "prod", AssetCount: 2}) {
		t.Fatalf("groups: %+v", gl)
	}
	host(t, f.db, "stage-1", store.AssetFacts{Group: "stage"})
	gs := gen.ListAssetGroupsParamsSort("-assetCount")
	g, err = h.ListAssetGroups(ctx, gen.ListAssetGroupsRequestObject{Params: gen.ListAssetGroupsParams{Sort: &gs}})
	must(t, err)
	if gl := g.(gen.ListAssetGroups200JSONResponse); gl.Total != 2 || gl.Items[0].Name != "prod" || gl.Items[1].AssetCount != 1 {
		t.Fatalf("groups by count: %+v", gl)
	}
	g, err = h.ListAssetGroups(ctx, gen.ListAssetGroupsRequestObject{Params: gen.ListAssetGroupsParams{Q: ptr("STA"), Limit: ptr(1)}})
	must(t, err)
	if gl := g.(gen.ListAssetGroups200JSONResponse); gl.Total != 1 || len(gl.Items) != 1 || gl.Items[0].Name != "stage" {
		t.Fatalf("groups q: %+v", gl)
	}

	d, err := h.GetAsset(ctx, gen.GetAssetRequestObject{Id: f.web})
	must(t, err)
	a := d.(gen.GetAsset200JSONResponse)
	if len(a.Sections) != 2 || len(a.Containers) != 1 || a.Containers[0].ImageDigest == nil || a.WorkloadId != nil {
		t.Fatalf("host detail: %+v", a)
	}
	d, err = h.GetAsset(ctx, gen.GetAssetRequestObject{Id: f.apiAsset})
	must(t, err)
	a = d.(gen.GetAsset200JSONResponse)
	if a.Kind != gen.AssetKindWorkload || a.WorkloadId == nil || *a.WorkloadId != f.workload || a.Replicas == nil ||
		*a.Replicas != 2 || a.WorkloadKind == nil || *a.WorkloadKind != "Deployment" {
		t.Fatalf("workload detail: %+v", a)
	}
	for _, id := range []string{uuid.NewString(), "not-a-uuid"} {
		_, err = h.GetAsset(ctx, gen.GetAssetRequestObject{Id: id})
		wantStatus(t, "missing asset", err, http.StatusNotFound)
	}

	inst, err := h.ListAssetInstances(ctx, gen.ListAssetInstancesRequestObject{Id: f.apiAsset})
	must(t, err)
	if il := inst.(gen.ListAssetInstances200JSONResponse); il.Total != 2 || il.Items[0].Phase != gen.K8sPodPhaseRunning {
		t.Fatalf("instances: %+v", il)
	}
	inst, err = h.ListAssetInstances(ctx, gen.ListAssetInstancesRequestObject{Id: f.web})
	must(t, err)
	if il := inst.(gen.ListAssetInstances200JSONResponse); il.Total != 0 || il.Items == nil {
		t.Fatalf("host instances: %+v", il)
	}
	_, err = h.ListAssetInstances(ctx, gen.ListAssetInstancesRequestObject{Id: uuid.NewString()})
	wantStatus(t, "instances of missing asset", err, http.StatusNotFound)

	cr, err := h.CollectAsset(ctx, gen.CollectAssetRequestObject{Id: f.web})
	must(t, err)
	if c := cr.(gen.CollectAsset202JSONResponse); !c.RequestedAt.Equal(t0) {
		t.Fatalf("collect: %+v", c)
	}
	d, err = h.GetAsset(ctx, gen.GetAssetRequestObject{Id: f.web})
	must(t, err)
	if a := d.(gen.GetAsset200JSONResponse); a.CollectRequestedAt == nil || !a.CollectRequestedAt.Equal(t0) {
		t.Fatalf("pending collect not shown: %+v", a.CollectRequestedAt)
	}
	// An older report keeps the request pending, a newer one answers it.
	must(t, f.db.UpdateAssetFacts(ctx, f.web, store.AssetFacts{SeenAt: t0.Add(-time.Minute)}))
	if a, _ := f.db.GetAsset(ctx, f.web); a.CollectRequestedAt == nil {
		t.Fatal("older report cleared the pending collect")
	}
	must(t, f.db.UpdateAssetFacts(ctx, f.web, store.AssetFacts{SeenAt: t0.Add(time.Minute)}))
	if a, _ := f.db.GetAsset(ctx, f.web); a.CollectRequestedAt != nil {
		t.Fatal("newer report did not clear the pending collect")
	}
	f.collector.err = store.ErrInvalidState
	_, err = h.CollectAsset(ctx, gen.CollectAssetRequestObject{Id: f.web})
	wantStatus(t, "collect revoked", err, http.StatusConflict)
	_, err = h.CollectAsset(ctx, gen.CollectAssetRequestObject{Id: uuid.NewString()})
	wantStatus(t, "collect missing", err, http.StatusNotFound)
	if len(f.collector.calls) != 2 {
		t.Fatalf("collector calls: %v", f.collector.calls)
	}
	_, err = New(Config{Store: f.db}).CollectAsset(ctx, gen.CollectAssetRequestObject{Id: f.web})
	wantStatus(t, "no collector", err, http.StatusServiceUnavailable)
}

func TestComponents(t *testing.T) {
	f := seed(t)
	h, ctx := f.h, f.ctx
	rowName := func(r gen.AssetComponentRow) string { return r.Component.Name }

	lc := func(p gen.ListAssetComponentsParams) gen.ListAssetComponents200JSONResponse {
		t.Helper()
		r, err := h.ListAssetComponents(ctx, gen.ListAssetComponentsRequestObject{Id: f.web, Params: p})
		must(t, err)
		return r.(gen.ListAssetComponents200JSONResponse)
	}
	all := lc(gen.ListAssetComponentsParams{})
	if all.Total != 4 || names(all.Items, rowName) != "curl,libc6,nginx,openssl" {
		t.Fatalf("asset components: %s", names(all.Items, rowName))
	}
	hostOnly := lc(gen.ListAssetComponentsParams{HostOnly: ptr(true)})
	if names(hostOnly.Items, rowName) != "curl,openssl" || hostOnly.Items[0].Container != nil || hostOnly.Items[0].Layer != nil {
		t.Fatalf("host only: %+v", hostOnly.Items)
	}
	inC := lc(gen.ListAssetComponentsParams{Container: ptr("nginx")})
	if names(inC.Items, rowName) != "libc6,nginx" || *inC.Items[0].Layer != gen.ComponentLayerImage || *inC.Items[0].Container != "nginx" {
		t.Fatalf("container: %+v", inC.Items)
	}
	srt := gen.ListAssetComponentsParamsSort("-name")
	if r := lc(gen.ListAssetComponentsParams{Q: ptr("ssl"), Sort: &srt}); names(r.Items, rowName) != "openssl" {
		t.Fatalf("q: %s", names(r.Items, rowName))
	}
	must(t, func() error {
		_, err := f.db.ReplaceAssetComponents(ctx, store.ComponentScope{AssetID: f.web, Container: "nginx",
			Source: store.SourceArtifacts, Layer: store.LayerRuntime}, []store.ComponentObservation{
			{Component: store.Component{Type: "binary", Name: "tool", Version: "1.0", PURL: "pkg:generic/tool@1.0"},
				Locations: []string{"/usr/local/bin/tool"}, InUse: true, Method: store.DetectStatic},
		}, store.ReplaceOptions{At: t0})
		return err
	}())
	if r := lc(gen.ListAssetComponentsParams{Layer: ptr(gen.ComponentLayerRuntime)}); names(r.Items, rowName) != "tool" {
		t.Fatalf("layer runtime: %s", names(r.Items, rowName))
	}
	if r := lc(gen.ListAssetComponentsParams{Layer: ptr(gen.ComponentLayerImage)}); names(r.Items, rowName) != "libc6,nginx" {
		t.Fatalf("layer image: %s", names(r.Items, rowName))
	}
	if r := lc(gen.ListAssetComponentsParams{InUse: ptr(false)}); names(r.Items, rowName) != "curl,libc6,nginx,openssl" {
		t.Fatalf("not in use: %s", names(r.Items, rowName))
	}
	if r := lc(gen.ListAssetComponentsParams{InUse: ptr(true)}); names(r.Items, rowName) != "tool" {
		t.Fatalf("in use: %s", names(r.Items, rowName))
	}
	for _, p := range []gen.ListAssetComponentsParams{
		{Layer: ptr(gen.ComponentLayer("lower"))},
		{HostOnly: ptr(true), Container: ptr("nginx")},
		{Type: ptr(gen.ComponentType("npm"))},
	} {
		_, err := h.ListAssetComponents(ctx, gen.ListAssetComponentsRequestObject{Id: f.web, Params: p})
		wantStatus(t, "bad component params", err, http.StatusBadRequest)
	}
	_, err := h.ListAssetComponents(ctx, gen.ListAssetComponentsRequestObject{Id: uuid.NewString()})
	wantStatus(t, "components of missing asset", err, http.StatusNotFound)

	srtC := gen.ListComponentsParamsSort("-assetCount")
	r, err := h.ListComponents(ctx, gen.ListComponentsRequestObject{Params: gen.ListComponentsParams{Sort: &srtC}})
	must(t, err)
	cl := r.(gen.ListComponentsResponseObject).(gen.ListComponents200JSONResponse)
	if cl.Total != 5 || cl.Items[0].Name != "openssl" || cl.Items[0].AssetCount != 2 || cl.Items[0].Origin != gen.Distro {
		t.Fatalf("components: %+v", cl.Items)
	}
	openssl := cl.Items[0].Id
	if cl.Items[0].RunningAssetCount != 0 {
		t.Fatalf("openssl running: %+v", cl.Items[0])
	}
	r, err = h.ListComponents(ctx, gen.ListComponentsRequestObject{Params: gen.ListComponentsParams{Running: ptr(true)}})
	must(t, err)
	if rl := r.(gen.ListComponents200JSONResponse); rl.Total != 1 || rl.Items[0].Name != "tool" || rl.Items[0].RunningAssetCount != 1 {
		t.Fatalf("running components: %+v", rl.Items)
	}
	r, err = h.ListComponents(ctx, gen.ListComponentsRequestObject{Params: gen.ListComponentsParams{Installed: ptr(true)}})
	must(t, err)
	if il := r.(gen.ListComponents200JSONResponse); il.Total != 5 {
		t.Fatalf("installed components: %+v", il.Items)
	}

	g, err := h.GetComponent(ctx, gen.GetComponentRequestObject{Id: openssl})
	must(t, err)
	if c := g.(gen.GetComponent200JSONResponse); c.Purl == "" || c.Distro == nil || *c.Distro != "ubuntu-24.04" {
		t.Fatalf("component: %+v", c)
	}
	_, err = h.GetComponent(ctx, gen.GetComponentRequestObject{Id: uuid.NewString()})
	wantStatus(t, "missing component", err, http.StatusNotFound)

	ca, err := h.ListComponentAssets(ctx, gen.ListComponentAssetsRequestObject{Id: openssl})
	must(t, err)
	cal := ca.(gen.ListComponentAssets200JSONResponse)
	if cal.Total != 2 || cal.Items[0].Asset.Name != "db-1" || cal.Items[0].AssetId != f.db1 || cal.Items[0].ComponentId != openssl {
		t.Fatalf("component assets: %+v", cal.Items)
	}
	// The embedded asset is the full summary.
	if w := cal.Items[1].Asset; w.Group != "prod" || len(w.Tags) != 1 || w.Method != gen.CollectMethodAgent ||
		w.Coverage != gen.CoverageFull || w.ContainerCount != 1 || w.FirstSeen.IsZero() {
		t.Fatalf("embedded asset: %+v", w)
	}
	_, err = h.ListComponentAssets(ctx, gen.ListComponentAssetsRequestObject{Id: uuid.NewString()})
	wantStatus(t, "assets of missing component", err, http.StatusNotFound)

	lca := func(id string, p gen.ListComponentAssetsParams) gen.ListComponentAssets200JSONResponse {
		t.Helper()
		r, err := h.ListComponentAssets(ctx, gen.ListComponentAssetsRequestObject{Id: id, Params: p})
		must(t, err)
		return r.(gen.ListComponentAssets200JSONResponse)
	}
	if r := lca(openssl, gen.ListComponentAssetsParams{InUse: ptr(true)}); r.Total != 0 {
		t.Fatalf("in use: %+v", r.Items)
	}
	if r := lca(openssl, gen.ListComponentAssetsParams{Method: ptr(gen.DetectMethod(store.DetectPackageDB))}); r.Total != 2 {
		t.Fatalf("method: %+v", r.Items)
	}
	if r := lca(openssl, gen.ListComponentAssetsParams{Method: ptr(gen.DetectMethod(store.DetectStatic))}); r.Total != 0 {
		t.Fatalf("method static: %+v", r.Items)
	}
	_, err = h.ListComponentAssets(ctx, gen.ListComponentAssetsRequestObject{Id: openssl,
		Params: gen.ListComponentAssetsParams{Method: ptr(gen.DetectMethod("guess"))}})
	wantStatus(t, "bad method", err, http.StatusBadRequest)

	// Removing openssl from db-1 leaves history that includeRemoved shows.
	_, err = f.db.ReplaceAssetComponents(ctx, store.ComponentScope{AssetID: f.db1, Source: store.SourcePackages},
		nil, store.ReplaceOptions{At: t0.Add(time.Hour)})
	must(t, err)
	if r := lca(openssl, gen.ListComponentAssetsParams{}); r.Total != 1 {
		t.Fatalf("current after removal: %+v", r.Items)
	}
	hist := lca(openssl, gen.ListComponentAssetsParams{IncludeRemoved: ptr(true)})
	if hist.Total != 2 || hist.Items[0].AssetId != f.db1 || hist.Items[0].RemovedAt == nil {
		t.Fatalf("history: %+v", hist.Items)
	}
}

func TestProcessesAndPorts(t *testing.T) {
	f := seed(t)
	h, ctx := f.h, f.ctx
	pid := func(p gen.ProcessInfo) string { return string(rune('0' + p.Pid/100)) }

	view := gen.ListProcessesParamsView("restart")
	r, err := h.ListProcesses(ctx, gen.ListProcessesRequestObject{Params: gen.ListProcessesParams{View: &view}})
	must(t, err)
	pl := r.(gen.ListProcesses200JSONResponse)
	if pl.Total != 1 || pl.Items[0].Pid != 200 || pl.Items[0].AssetName != "web-1" || *pl.Items[0].Container != "nginx" ||
		len(pl.Items[0].Listen) != 1 || pl.Items[0].ExeState != gen.ExeStateReplaced {
		t.Fatalf("restart: %+v", pl.Items)
	}
	view = "suspicious"
	r, err = h.ListProcesses(ctx, gen.ListProcessesRequestObject{Params: gen.ListProcessesParams{View: &view}})
	must(t, err)
	pl = r.(gen.ListProcesses200JSONResponse)
	if pl.Total != 1 || pl.Items[0].Pid != 300 || len(pl.Items[0].DeletedLibs) != 1 || pl.Items[0].ExeSource != gen.Cmdline {
		t.Fatalf("suspicious: %+v", pl.Items)
	}

	srt := gen.ListAssetProcessesParamsSort("-pid")
	ap, err := h.ListAssetProcesses(ctx, gen.ListAssetProcessesRequestObject{Id: f.web,
		Params: gen.ListAssetProcessesParams{Sort: &srt}})
	must(t, err)
	if apl := ap.(gen.ListAssetProcesses200JSONResponse); names(apl.Items, pid) != "3,2,0" {
		t.Fatalf("asset processes: %s", names(apl.Items, pid))
	}
	lv := gen.ListAssetProcessesParamsView("listen")
	ap, err = h.ListAssetProcesses(ctx, gen.ListAssetProcessesRequestObject{Id: f.web,
		Params: gen.ListAssetProcessesParams{View: &lv}})
	must(t, err)
	if apl := ap.(gen.ListAssetProcesses200JSONResponse); apl.Total != 1 {
		t.Fatalf("listen view: %+v", apl)
	}
	ap, err = h.ListAssetProcesses(ctx, gen.ListAssetProcessesRequestObject{Id: f.db1})
	must(t, err)
	if apl := ap.(gen.ListAssetProcesses200JSONResponse); apl.Total != 0 {
		t.Fatalf("db-1 processes: %+v", apl)
	}
	_, err = h.ListAssetProcesses(ctx, gen.ListAssetProcessesRequestObject{Id: uuid.NewString()})
	wantStatus(t, "processes of missing asset", err, http.StatusNotFound)

	lp, err := h.ListListenPorts(ctx, gen.ListListenPortsRequestObject{})
	must(t, err)
	ll := lp.(gen.ListListenPorts200JSONResponse)
	if ll.Total != 2 || ll.Items[0].Port != 53 || ll.Items[0].ProcessId != nil || ll.Items[0].Pid != nil ||
		ll.Items[1].Port != 443 || ll.Items[1].ProcessId == nil || *ll.Items[1].Pid != 200 {
		t.Fatalf("ports: %+v", ll.Items)
	}
	proto := gen.Tcp
	lp, err = h.ListListenPorts(ctx, gen.ListListenPortsRequestObject{Params: gen.ListListenPortsParams{Proto: &proto}})
	must(t, err)
	if ll := lp.(gen.ListListenPorts200JSONResponse); ll.Total != 1 {
		t.Fatalf("tcp: %+v", ll)
	}
	_, err = h.ListListenPorts(ctx, gen.ListListenPortsRequestObject{Params: gen.ListListenPortsParams{Port: ptr(70000)}})
	wantStatus(t, "bad port", err, http.StatusBadRequest)
}

func TestImages(t *testing.T) {
	f := seed(t)
	h, ctx := f.h, f.ctx
	r, err := h.ListImages(ctx, gen.ListImagesRequestObject{})
	must(t, err)
	il := r.(gen.ListImages200JSONResponse)
	if il.Total != 2 {
		t.Fatalf("images: %+v", il)
	}
	known := ptr(true)
	r, err = h.ListImages(ctx, gen.ListImagesRequestObject{Params: gen.ListImagesParams{ContentKnown: known}})
	must(t, err)
	il = r.(gen.ListImages200JSONResponse)
	if il.Total != 1 || il.Items[0].Digest != digestNginx || il.Items[0].ComponentCount != 2 || !il.Items[0].ContentKnown ||
		il.Items[0].Usage.Containers != 1 || *il.Items[0].SizeBytes != 1000 {
		t.Fatalf("known images: %+v", il.Items)
	}

	d, err := h.GetImage(ctx, gen.GetImageRequestObject{Digest: digestNginx})
	must(t, err)
	img := d.(gen.GetImage200JSONResponse)
	if len(img.Uses) != 1 || img.Uses[0].Asset.Name != "web-1" || img.Uses[0].Container.Name != "nginx" ||
		len(img.Components) != 2 || img.ComponentCount != 2 {
		t.Fatalf("image: %+v", img)
	}
	if u := img.Uses[0].Asset; u.Group != "prod" || u.ContainerCount != 1 || u.Images == nil || len(*u.Images) != 1 {
		t.Fatalf("image use asset: %+v", u)
	}
	if !reflect.DeepEqual(img.CurrentTags, gen.CurrentImageTags{"nginx:1.27", "nginx:latest"}) || len(img.PreviousTags) != 0 {
		t.Fatalf("tags: %+v %+v", img.CurrentTags, img.PreviousTags)
	}

	// nginx:latest moves away from the digest on the next full listing.
	t1 := t0.Add(time.Hour)
	must(t, f.db.UpsertImages(ctx, store.ImageSource{Kind: store.ImageSourceAsset, ID: f.web},
		[]store.ImageObservation{{Digest: digestNginx, RepoTags: []string{"nginx:1.27"}}}, store.ReplaceOptions{At: t1}))
	d, err = h.GetImage(ctx, gen.GetImageRequestObject{Digest: digestNginx})
	must(t, err)
	img = d.(gen.GetImage200JSONResponse)
	if !reflect.DeepEqual(img.CurrentTags, gen.CurrentImageTags{"nginx:1.27"}) ||
		!reflect.DeepEqual(img.PreviousTags, gen.PreviousImageTags{{Tag: "nginx:latest", LastSeen: t0}}) {
		t.Fatalf("tags after move: %+v %+v", img.CurrentTags, img.PreviousTags)
	}
	raw, err := json.Marshal(img)
	must(t, err)
	if !strings.Contains(string(raw), `"currentTags":["nginx:1.27"]`) ||
		!strings.Contains(string(raw), `"previousTags":[{"lastSeen":"`+t0.Format(time.RFC3339)+`","tag":"nginx:latest"}]`) {
		t.Fatalf("image json: %s", raw)
	}
	r, err = h.ListImages(ctx, gen.ListImagesRequestObject{Params: gen.ListImagesParams{Q: ptr("latest")}})
	must(t, err)
	il = r.(gen.ListImages200JSONResponse)
	if il.Total != 1 || il.Items[0].Digest != digestNginx || len(il.Items[0].PreviousTags) != 1 || il.Items[0].CurrentTags == nil {
		t.Fatalf("q on previous tag: %+v", il.Items)
	}
	// The cluster image has no tags; it sorts before nginx:1.27.
	r, err = h.ListImages(ctx, gen.ListImagesRequestObject{Params: gen.ListImagesParams{Sort: ptr(gen.ListImagesParamsSortTag)}})
	must(t, err)
	il = r.(gen.ListImages200JSONResponse)
	if il.Total != 2 || il.Items[1].Digest != digestNginx || len(il.Items[0].CurrentTags) != 0 || il.Items[0].PreviousTags == nil {
		t.Fatalf("sort by tag: %+v", il.Items)
	}
	_, err = h.GetImage(ctx, gen.GetImageRequestObject{Digest: "sha256:abc"})
	wantStatus(t, "bad digest", err, http.StatusBadRequest)
	_, err = h.GetImage(ctx, gen.GetImageRequestObject{Digest: "sha256:" + strings.Repeat("9", 64)})
	wantStatus(t, "unknown digest", err, http.StatusNotFound)
}

func TestKubernetes(t *testing.T) {
	f := seed(t)
	h, ctx := f.h, f.ctx

	r, err := h.ListK8sClusters(ctx, gen.ListK8sClustersRequestObject{})
	must(t, err)
	cl := r.(gen.ListK8sClusters200JSONResponse)
	if cl.Total != 1 || cl.Items[0].WorkloadCount != 2 || cl.Items[0].ExcludedCount != 1 ||
		cl.Items[0].SyncStatus != gen.K8sSyncStatusOk || *cl.Items[0].Version != "v1.30.2" {
		t.Fatalf("clusters: %+v", cl.Items)
	}
	_, err = h.ListK8sClusters(ctx, gen.ListK8sClustersRequestObject{Params: gen.ListK8sClustersParams{
		Sort: ptr(gen.ListK8sClustersParamsSort("-execEnabled"))}})
	must(t, err)

	g, err := h.GetK8sCluster(ctx, gen.GetK8sClusterRequestObject{Id: f.cluster})
	must(t, err)
	if c := g.(gen.GetK8sCluster200JSONResponse); c.WorkloadCount != 2 || c.ExcludedCount != 1 || *c.ScannerId != f.scanner ||
		c.SyncStatus != gen.K8sSyncStatusOk || c.SyncMessage != nil {
		t.Fatalf("cluster: %+v", c)
	}
	// A failed attempt after the last inventory is shown with its message;
	// an outcome older than the stored one is ignored.
	must(t, f.db.RecordClusterSync(ctx, f.cluster, store.K8sSyncFailed, "connection refused", t0.Add(time.Hour)))
	must(t, f.db.RecordClusterSync(ctx, f.cluster, store.K8sSyncOK, "", t0.Add(time.Minute)))
	g, err = h.GetK8sCluster(ctx, gen.GetK8sClusterRequestObject{Id: f.cluster})
	must(t, err)
	if c := g.(gen.GetK8sCluster200JSONResponse); c.SyncStatus != gen.K8sSyncStatusFailed || c.SyncMessage == nil ||
		*c.SyncMessage != "connection refused" || c.LastSync == nil || !c.LastSync.Equal(t0) {
		t.Fatalf("failed sync: %+v", c)
	}

	w, err := h.ListK8sWorkloads(ctx, gen.ListK8sWorkloadsRequestObject{Id: f.cluster,
		Params: gen.ListK8sWorkloadsParams{Excluded: ptr(false)}})
	must(t, err)
	wl := w.(gen.ListK8sWorkloads200JSONResponse)
	if wl.Total != 1 || wl.Items[0].Name != "api" || *wl.Items[0].AssetId != f.apiAsset || len(wl.Items[0].Coverages) != 1 {
		t.Fatalf("workloads: %+v", wl.Items)
	}
	w, err = h.ListK8sWorkloads(ctx, gen.ListK8sWorkloadsRequestObject{Id: f.cluster,
		Params: gen.ListK8sWorkloadsParams{Excluded: ptr(true)}})
	must(t, err)
	if wl := w.(gen.ListK8sWorkloads200JSONResponse); wl.Total != 1 || wl.Items[0].AssetId != nil || *wl.Items[0].ExcludedBy == "" {
		t.Fatalf("excluded workloads: %+v", wl.Items)
	}
	_, err = h.ListK8sWorkloads(ctx, gen.ListK8sWorkloadsRequestObject{Id: uuid.NewString()})
	wantStatus(t, "workloads of missing cluster", err, http.StatusNotFound)

	phase := gen.K8sPodPhaseRunning
	srt := gen.ListK8sWorkloadPodsParamsSort("-name")
	p, err := h.ListK8sWorkloadPods(ctx, gen.ListK8sWorkloadPodsRequestObject{Id: f.workload,
		Params: gen.ListK8sWorkloadPodsParams{Phase: &phase, Sort: &srt}})
	must(t, err)
	if pl := p.(gen.ListK8sWorkloadPods200JSONResponse); pl.Total != 2 || pl.Items[0].Name != "api-b" ||
		len(pl.Items[0].Containers) != 1 || *pl.Items[0].Containers[0].ImageDigest != digestAPI {
		t.Fatalf("pods: %+v", pl.Items)
	}
	for _, id := range []string{uuid.NewString(), "not-a-uuid"} {
		_, err = h.ListK8sWorkloadPods(ctx, gen.ListK8sWorkloadPodsRequestObject{Id: id})
		wantStatus(t, "pods of missing workload", err, http.StatusNotFound)
	}
	p, err = h.ListK8sWorkloadPods(ctx, gen.ListK8sWorkloadPodsRequestObject{Id: f.workload,
		Params: gen.ListK8sWorkloadPodsParams{Q: ptr("nothing")}})
	must(t, err)
	if pl := p.(gen.ListK8sWorkloadPods200JSONResponse); pl.Total != 0 {
		t.Fatalf("filtered pods: %+v", pl)
	}

	// Create: validation of connection, credential and scanner.
	create := func(b gen.K8sClusterCreate) (gen.CreateK8sClusterResponseObject, error) {
		return h.CreateK8sCluster(ctx, gen.CreateK8sClusterRequestObject{Body: &b})
	}
	for name, b := range map[string]gen.K8sClusterCreate{
		"no credential":      {Name: "a", Connection: gen.K8sConnectionKubeconfig},
		"unknown credential": {Name: "a", Connection: gen.K8sConnectionKubeconfig, CredentialId: ptr(uuid.NewString())},
		"ssh credential":     {Name: "a", Connection: gen.K8sConnectionKubeconfig, CredentialId: &f.sshCred},
		"no scanner":         {Name: "a", Connection: gen.K8sConnectionInCluster},
		"agent as scanner":   {Name: "a", Connection: gen.K8sConnectionInCluster, ScannerId: ptr(uuid.NewString())},
		"credential in":      {Name: "a", Connection: gen.K8sConnectionInCluster, ScannerId: &f.scanner, CredentialId: &f.kubecfg},
		"bad connection":     {Name: "a", Connection: "magic"},
		"blank name":         {Name: "  ", Connection: gen.K8sConnectionKubeconfig, CredentialId: &f.kubecfg},
		"bad glob": {Name: "a", Connection: gen.K8sConnectionKubeconfig, CredentialId: &f.kubecfg,
			Filter: &gen.K8sFilter{NsInclude: []string{"[x"}}},
	} {
		_, err := create(b)
		wantStatus(t, name, err, http.StatusBadRequest)
	}
	_, err = create(gen.K8sClusterCreate{Name: "prd", Connection: gen.K8sConnectionKubeconfig, CredentialId: &f.kubecfg})
	wantStatus(t, "duplicate", err, http.StatusConflict)
	cr, err := create(gen.K8sClusterCreate{Name: " stg ", Connection: gen.K8sConnectionKubeconfig, CredentialId: &f.kubecfg,
		ExecEnabled: ptr(true), Filter: &gen.K8sFilter{NsExclude: []string{"kube-*"}}})
	must(t, err)
	stg := cr.(gen.CreateK8sCluster201JSONResponse)
	if stg.Name != "stg" || !stg.ExecEnabled || stg.SyncStatus != gen.K8sSyncStatusNever || len(stg.Filter.NsExclude) != 1 ||
		stg.Filter.LabelInclude == nil {
		t.Fatalf("created: %+v", stg)
	}

	// Update: switching to in_cluster drops the credential.
	conn := gen.K8sConnectionInCluster
	up, err := h.UpdateK8sCluster(ctx, gen.UpdateK8sClusterRequestObject{Id: stg.Id,
		Body: &gen.K8sClusterUpdate{Connection: &conn, ScannerId: nullable.NewNullableWithValue(f.scanner)}})
	must(t, err)
	if u := up.(gen.UpdateK8sCluster200JSONResponse); u.CredentialId != nil || *u.ScannerId != f.scanner || !u.ExecEnabled {
		t.Fatalf("updated: %+v", u)
	}
	// Null clears: back to kubeconfig with the embedded scanner.
	kc := gen.K8sConnectionKubeconfig
	up, err = h.UpdateK8sCluster(ctx, gen.UpdateK8sClusterRequestObject{Id: stg.Id,
		Body: &gen.K8sClusterUpdate{Connection: &kc, CredentialId: nullable.NewNullableWithValue(f.kubecfg),
			ScannerId: nullable.NewNullNullable[string]()}})
	must(t, err)
	if u := up.(gen.UpdateK8sCluster200JSONResponse); u.ScannerId != nil || u.CredentialId == nil || *u.CredentialId != f.kubecfg {
		t.Fatalf("cleared scanner: %+v", u)
	}
	// Absent keeps the credential; null on in_cluster clears it.
	up, err = h.UpdateK8sCluster(ctx, gen.UpdateK8sClusterRequestObject{Id: stg.Id,
		Body: &gen.K8sClusterUpdate{ExecEnabled: ptr(false)}})
	must(t, err)
	if u := up.(gen.UpdateK8sCluster200JSONResponse); u.CredentialId == nil || u.ExecEnabled {
		t.Fatalf("absent fields changed: %+v", u)
	}
	_, err = h.UpdateK8sCluster(ctx, gen.UpdateK8sClusterRequestObject{Id: stg.Id,
		Body: &gen.K8sClusterUpdate{CredentialId: nullable.NewNullNullable[string]()}})
	wantStatus(t, "kubeconfig without credential", err, http.StatusBadRequest)
	up, err = h.UpdateK8sCluster(ctx, gen.UpdateK8sClusterRequestObject{Id: stg.Id,
		Body: &gen.K8sClusterUpdate{Connection: &conn, ScannerId: nullable.NewNullableWithValue(f.scanner),
			CredentialId: nullable.NewNullNullable[string]()}})
	must(t, err)
	if u := up.(gen.UpdateK8sCluster200JSONResponse); u.CredentialId != nil || u.ScannerId == nil {
		t.Fatalf("cleared credential: %+v", u)
	}
	_, err = h.UpdateK8sCluster(ctx, gen.UpdateK8sClusterRequestObject{Id: stg.Id, Body: &gen.K8sClusterUpdate{Name: ptr("prd")}})
	wantStatus(t, "rename to taken", err, http.StatusConflict)
	_, err = h.UpdateK8sCluster(ctx, gen.UpdateK8sClusterRequestObject{Id: uuid.NewString(), Body: &gen.K8sClusterUpdate{}})
	wantStatus(t, "update missing", err, http.StatusNotFound)

	_, err = h.SyncK8sCluster(ctx, gen.SyncK8sClusterRequestObject{Id: stg.Id})
	must(t, err)
	_, err = h.SyncK8sCluster(ctx, gen.SyncK8sClusterRequestObject{Id: uuid.NewString()})
	wantStatus(t, "sync missing", err, http.StatusNotFound)

	_, err = h.DeleteK8sCluster(ctx, gen.DeleteK8sClusterRequestObject{Id: stg.Id})
	must(t, err)
	_, err = h.DeleteK8sCluster(ctx, gen.DeleteK8sClusterRequestObject{Id: stg.Id})
	wantStatus(t, "delete twice", err, http.StatusNotFound)
}

func TestDashboardAndMeta(t *testing.T) {
	f := seed(t)
	r, err := f.h.GetDashboard(f.ctx, gen.GetDashboardRequestObject{})
	must(t, err)
	d := r.(gen.GetDashboard200JSONResponse)
	if d.Assets != (gen.DashboardAssets{Total: 4, Hosts: 3, Workloads: 1, Limited: 3}) {
		t.Fatalf("assets: %+v", d.Assets)
	}
	if len(d.Coverage) != 6 || d.Coverage[0] != (gen.CoverageCount{Coverage: gen.CoverageFull, Count: 1}) {
		t.Fatalf("coverage: %+v", d.Coverage)
	}
	if d.Processes != (gen.DashboardProcesses{RestartRequired: 1, Suspicious: 1}) {
		t.Fatalf("processes: %+v", d.Processes)
	}
	if d.Agents.PendingApproval != 1 || d.Agents.Offline != 1 || d.Agents.TlsIntercepted != 0 {
		t.Fatalf("agents: %+v", d.Agents)
	}
	must(t, f.db.UpdateAgentPoll(f.ctx, f.scanner, store.AgentPollStatus{ObservedIssuer: "CN=proxy", TLSMode: store.TLSVerifyPinned,
		ConnectMode: store.ConnectModeConnect, UpdateState: store.UpdateUpToDate, SeenAt: t0}))
	r, err = f.h.GetDashboard(f.ctx, gen.GetDashboardRequestObject{})
	must(t, err)
	if d := r.(gen.GetDashboard200JSONResponse); d.Agents.TlsIntercepted != 1 || d.Agents.Online != 1 {
		t.Fatalf("intercepted: %+v", d.Agents)
	}

	m, err := f.h.GetMeta(f.ctx, gen.GetMetaRequestObject{})
	must(t, err)
	if meta := m.(gen.GetMeta200JSONResponse); meta.Version == "" || !meta.Features.Vulnerabilities || meta.Features.SbomExport ||
		meta.AgentAddress == nil || *meta.AgentAddress != "bomcensus.example:8443" {
		t.Fatalf("meta: %+v", meta)
	}
	m, err = New(Config{Store: f.db}).GetMeta(f.ctx, gen.GetMetaRequestObject{})
	must(t, err)
	if meta := m.(gen.GetMeta200JSONResponse); meta.AgentAddress != nil {
		t.Fatalf("meta without agent address: %+v", meta)
	}

	me, err := f.h.GetCurrentUser(f.ctx, gen.GetCurrentUserRequestObject{})
	must(t, err)
	if p := me.(gen.GetCurrentUser200JSONResponse); p.Id != "env:admin" {
		t.Fatalf("me: %+v", p)
	}
	_, err = f.h.GetCurrentUser(context.Background(), gen.GetCurrentUserRequestObject{})
	wantStatus(t, "me without principal", err, http.StatusUnauthorized)
}

func TestStoreCredentials(t *testing.T) {
	f := seed(t)
	c := StoreCredentials{Store: f.db}
	if err := c.CheckKubeconfig(f.ctx, f.kubecfg); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckKubeconfig(f.ctx, f.sshCred); !errors.Is(err, ErrNotKubeconfig) {
		t.Fatalf("ssh: %v", err)
	}
	for _, id := range []string{uuid.NewString(), "nope"} {
		if err := c.CheckKubeconfig(f.ctx, id); !errors.Is(err, ErrCredentialNotFound) {
			t.Fatalf("%s: %v", id, err)
		}
	}
}

// The handlers compile against the generated interface when combined with
// the rest of the operations.
type stub struct{ gen.StrictServerInterface }

var _ gen.StrictServerInterface = struct {
	*Handlers
	stub
}{}
