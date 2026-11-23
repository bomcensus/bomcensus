// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package ingest

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/internal/server/store/postgres"
)

var t0 = time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)

const (
	img1      = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	img2      = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	web1ID    = "aaaaaaaaaaaa0000000000000000000000000000000000000000000000000001"
	web2ID    = "bbbbbbbbbbbb0000000000000000000000000000000000000000000000000002"
	appSHA    = "a11ce00000000000000000000000000000000000000000000000000000000000"
	ctrdSHA   = "c0ffee0000000000000000000000000000000000000000000000000000000000"
	sshdSHA   = "55dd000000000000000000000000000000000000000000000000000000000000"
	bashPURL  = "pkg:deb/ubuntu/bash@5.2.21-2ubuntu4?arch=amd64&distro=ubuntu-24.04"
	sslPURL   = "pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3?arch=amd64&distro=ubuntu-24.04"
	curlPURL  = "pkg:deb/ubuntu/curl@8.5.0-2ubuntu10?arch=amd64&distro=ubuntu-24.04"
	ctrdPURL  = "pkg:deb/ubuntu/containerd@1.7.12-0ubuntu4?arch=amd64&distro=ubuntu-24.04"
	sshPURL   = "pkg:deb/ubuntu/openssh-server@1:9.6p1-3ubuntu13?arch=amd64&distro=ubuntu-24.04"
	appPURL   = "pkg:golang/example.com/app@v1.0.0"
	log4jPURL = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
	muslPURL  = "pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64&distro=alpine-3.19.1"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func encode(t *testing.T, r *report.Report) []byte {
	t.Helper()
	var buf bytes.Buffer
	must(t, report.Encode(&buf, r))
	return buf.Bytes()
}

func meta(at time.Time, cov report.Coverage) report.SectionMeta {
	return report.SectionMeta{Coverage: cov, CollectedAt: at, Digest: at.Format(time.RFC3339)}
}

func pkg(name, version string) report.Package {
	return report.Package{Type: "deb", Name: name, Version: version, Arch: "amd64",
		Maintainer: "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>"}
}

func basePackages() []report.Package {
	return []report.Package{pkg("bash", "5.2.21-2ubuntu4"), pkg("openssl", "3.0.13-0ubuntu3"),
		pkg("containerd", "1.7.12-0ubuntu4"), pkg("openssh-server", "1:9.6p1-3ubuntu13")}
}

func baseArtifacts() []report.Artifact {
	return []report.Artifact{
		{Kind: "go_binary", Path: "/usr/bin/containerd", Module: "github.com/containerd/containerd",
			Version: "v1.7.12", GoVersion: "go1.21.6", SHA256: ctrdSHA, OwnerPackage: "containerd", InUse: true,
			Method: "buildinfo"},
		{Kind: "go_binary", Path: "/opt/app/app", Name: "app", Module: "example.com/app", Version: "v1.0.0",
			GoVersion: "go1.22.1", SHA256: appSHA, InUse: true, Method: "buildinfo"},
		{Kind: "go_module", Path: "/opt/app/app", Module: "golang.org/x/net", Version: "v0.20.0", Method: "buildinfo"},
		{Kind: "jar", Path: "/opt/svc/log4j-core.jar", GroupID: "org.apache.logging.log4j", ArtifactID: "log4j-core",
			Version: "2.14.1", Method: "manifest"},
		{Kind: "package_file", Path: "/usr/sbin/sshd", Name: "openssh-server", SHA256: sshdSHA,
			OwnerPackage: "openssh-server", InUse: true, Method: "pkgdb"},
	}
}

// hostReport is a full report of web-01 collected at at.
func hostReport(at time.Time) *report.Report {
	return &report.Report{
		SchemaVersion: report.SchemaVersion, ProbeVersion: "test", CollectedAt: at,
		Subject:   &report.Subject{Kind: report.SubjectSelf},
		Privilege: report.Privilege{Level: report.PrivilegePrivileged},
		Host: &report.HostSection{SectionMeta: meta(at, report.CoverageFull), Hostname: "web-01",
			MachineID: "machine-web-01", Kernel: "6.8.0", Arch: "x86_64",
			OS: report.OS{Family: "linux", ID: "ubuntu", IDLike: "debian", VersionID: "24.04", PrettyName: "Ubuntu 24.04 LTS"}},
		Packages:  &report.PackagesSection{SectionMeta: meta(at, report.CoverageFull), Packages: basePackages()},
		Artifacts: &report.ArtifactsSection{SectionMeta: meta(at, report.CoverageFull), Artifacts: baseArtifacts()},
		Processes: &report.ProcessesSection{SectionMeta: meta(at, report.CoverageFull), Processes: []report.Process{
			{PID: 100, User: "root", Exe: "/usr/bin/containerd", ExeSource: "proc", ExeState: "normal", StartedAt: t0},
			{PID: 200, User: "app", Exe: "/opt/app/app", ExeSource: "proc", ExeState: "normal", SHA256: appSHA, StartedAt: t0,
				Listen: []report.Listen{{Proto: "tcp", Address: "0.0.0.0", Port: 8080}}},
			{PID: 300, User: "root", Exe: "/usr/bin/bash", ExeSource: "proc", ExeState: "normal", StartedAt: t0},
			{PID: 500, User: "root", Exe: "/usr/sbin/sshd", ExeSource: "proc", ExeState: "normal", SHA256: sshdSHA,
				StartedAt: t0, Listen: []report.Listen{{Proto: "tcp", Address: "0.0.0.0", Port: 22}}},
			{PID: 400, User: "nginx", Exe: "/usr/sbin/nginx", ExeSource: "proc", ExeState: "normal", StartedAt: t0,
				ContainerID: web1ID},
		}},
		Containers: &report.ContainersSection{SectionMeta: meta(at, report.CoverageFull), Runtimes: []string{"docker"},
			Containers: []report.Container{
				{ID: web1ID, Name: "/web1", Runtime: "docker", ImageRef: "nginx:1.25-alpine", ImageDigest: img1, Running: true,
					Coverage: report.CoverageFull},
				{ID: web2ID, Name: "/web2", Runtime: "docker", ImageRef: "nginx:1.25-alpine", ImageDigest: img1, Running: true,
					Coverage: report.CoverageFull, RuntimeArtifacts: []report.Artifact{{Kind: "software", Path: "/usr/local/bin/tool",
						Name: "tool", Version: "1.0", Method: "static"}}},
			},
			Images: []report.Image{{Digest: img1, RepoTags: []string{"nginx:1.25-alpine"}, OS: "linux", Arch: "amd64"}},
			ImageScopes: []report.ImageScope{{Digest: img1, FromContainer: web1ID,
				OS:       &report.OS{ID: "alpine", VersionID: "3.19.1"},
				Packages: []report.Package{{Type: "apk", Name: "musl", Version: "1.2.4-r2", Arch: "x86_64"}}}},
		},
	}
}

type fixture struct {
	db    *postgres.DB
	svc   *Service
	agent store.Agent
	ctx   context.Context
}

func newFixture(t *testing.T) *fixture {
	db := newTestDB(t)
	ctx := context.Background()
	pub := make([]byte, 32)
	_, _ = rand.Read(pub)
	_, err := db.CreateRegisterKey(ctx, store.RegisterKey{ID: "regkey00001", Name: "prod", PublicKey: pub,
		Target: store.AgentKindAgent, Approval: store.ApprovalAuto, DefaultGroup: "prod", DefaultTags: []string{"web", "dmz"}})
	must(t, err)
	f := &fixture{db: db, ctx: ctx, svc: New(db, nil, func() time.Time { return t0.Add(24 * time.Hour) })}
	f.agent = f.newAgent(t, store.AgentKindAgent, "regkey00001")
	return f
}

func (f *fixture) newAgent(t *testing.T, kind store.AgentKind, regKey string) store.Agent {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	a, err := f.db.CreateAgent(f.ctx, store.Agent{Kind: kind, Hostname: "h", IdentityKey: key,
		State: store.AgentApproved, RegisterKeyID: regKey, EnrolledAt: t0})
	must(t, err)
	return a
}

func (f *fixture) ingest(t *testing.T, a store.Agent, r *report.Report) error {
	t.Helper()
	return f.svc.IngestReport(f.ctx, Sender{AgentID: a.ID, Kind: a.Kind, RemoteAddr: "10.0.0.5:51000"}, encode(t, r))
}

func (f *fixture) components(t *testing.T, assetID string, container *string, removed bool) map[string]store.AssetComponentRow {
	t.Helper()
	rows, _, err := f.db.ListAssetComponents(f.ctx, assetID, store.AssetComponentFilter{Container: container,
		IncludeRemoved: removed}, store.Page{Limit: 1000})
	must(t, err)
	out := map[string]store.AssetComponentRow{}
	for _, r := range rows {
		k := r.Container + "|" + r.Layer + "|" + r.Component.PURL
		if prev, ok := out[k]; ok && prev.RemovedAt == nil {
			continue
		}
		out[k] = r
	}
	return out
}

func ptr(s string) *string { return &s }

func TestHostReportLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := f.ctx
	must(t, f.ingest(t, f.agent, hostReport(t0)))

	a, err := f.db.GetAgent(ctx, f.agent.ID)
	must(t, err)
	if a.AssetID == "" {
		t.Fatal("agent not linked to an asset")
	}
	assetID := a.AssetID
	asset, err := f.db.GetAsset(ctx, assetID)
	must(t, err)
	if asset.Name != "web-01" || asset.Group != "prod" || !reflect.DeepEqual(asset.Tags, []string{"dmz", "web"}) ||
		asset.Method != store.CollectAgent || asset.OS.ID != "ubuntu" || asset.OS.Version != "24.04" ||
		asset.Address != "10.0.0.5" || asset.Coverage != store.CoverageFull || asset.Privilege != store.PrivilegePrivileged {
		t.Fatalf("asset %+v", asset.Asset)
	}

	self := f.components(t, assetID, ptr(""), false)
	for _, p := range []string{bashPURL, sslPURL, ctrdPURL} {
		if _, ok := self["||"+p]; !ok {
			t.Errorf("package %s missing", p)
		}
	}
	ctrd := self["||"+ctrdPURL]
	if !reflect.DeepEqual(ctrd.Locations, []string{"/usr/bin/containerd"}) || !ctrd.InUse ||
		ctrd.Component.Origin != store.OriginDistro {
		t.Errorf("owned artifact not linked to its package: %+v", ctrd)
	}
	for _, p := range []string{appPURL, "pkg:golang/stdlib@1.22.1", "pkg:golang/golang.org/x/net@v0.20.0", log4jPURL} {
		if r, ok := self["||"+p]; !ok || r.Source != store.SourceArtifacts || r.Component.Origin != store.OriginUpstream {
			t.Errorf("artifact %s: %+v", p, r)
		}
	}
	ssh := self["||"+sshPURL]
	if !reflect.DeepEqual(ssh.Locations, []string{"/usr/sbin/sshd"}) || !ssh.InUse {
		t.Errorf("running package file not linked to its package: %+v", ssh)
	}
	if _, ok := self["||pkg:golang/github.com/containerd/containerd@v1.7.12"]; ok {
		t.Error("package-owned go binary became a component")
	}

	// Two containers with the same digest share the image content.
	for _, c := range []string{"web1", "web2"} {
		rows := f.components(t, assetID, ptr(c), false)
		if r, ok := rows[c+"|image|"+muslPURL]; !ok || r.Source != store.SourcePackages {
			t.Errorf("container %s lacks image content: %v", c, rows)
		}
	}
	if _, ok := f.components(t, assetID, ptr("web2"), false)["web2|runtime|pkg:generic/tool@1.0"]; !ok {
		t.Error("runtime artifact of web2 missing")
	}
	img, err := f.db.GetImage(ctx, img1)
	must(t, err)
	if !img.ContentKnown() || img.ContentCoverage != store.CoverageFull || img.Containers != 2 {
		t.Errorf("image %+v", img.ImageRow)
	}

	// Processes: linked by path (package owner), by hash (artifact) and
	// attributed to their container.
	procs, _, err := f.db.ListProcesses(ctx, store.ProcessFilter{AssetID: assetID}, store.Page{Limit: 100})
	must(t, err)
	byPID := map[int]store.ProcessRow{}
	for _, p := range procs {
		byPID[p.PID] = p
	}
	if p := byPID[100]; p.ComponentID != ctrd.Component.ID {
		t.Errorf("containerd process component %q, want %q", p.ComponentID, ctrd.Component.ID)
	}
	if p := byPID[200]; p.ComponentID != self["||"+appPURL].Component.ID {
		t.Errorf("app process component %q, want %q", p.ComponentID, self["||"+appPURL].Component.ID)
	}
	if p := byPID[500]; p.ComponentID != ssh.Component.ID {
		t.Errorf("sshd process component %q, want %q", p.ComponentID, ssh.Component.ID)
	}
	if p := byPID[300]; p.ComponentID != "" {
		t.Errorf("bash process linked to %q", p.ComponentID)
	}
	if p := byPID[400]; p.Container != "web1" {
		t.Errorf("container process attributed to %q", p.Container)
	}
	hashes, err := f.db.ComponentsByFileHash(ctx, []string{ctrdSHA, appSHA})
	must(t, err)
	if hashes[ctrdSHA] != ctrd.Component.ID || hashes[appSHA] != self["||"+appPURL].Component.ID {
		t.Errorf("file hashes %v", hashes)
	}

	t.Run("removed package gets history", func(t *testing.T) {
		r := hostReport(t0.Add(time.Hour))
		r.Packages.Packages = []report.Package{pkg("bash", "5.2.21-2ubuntu4"), pkg("curl", "8.5.0-2ubuntu10"),
			pkg("containerd", "1.7.12-0ubuntu4")}
		must(t, f.ingest(t, f.agent, r))
		cur := f.components(t, assetID, ptr(""), false)
		if _, ok := cur["||"+sslPURL]; ok {
			t.Error("removed package still current")
		}
		if _, ok := cur["||"+curlPURL]; !ok {
			t.Error("new package missing")
		}
		hist := f.components(t, assetID, ptr(""), true)
		if h := hist["||"+sslPURL]; h.RemovedAt == nil || !h.RemovedAt.Equal(t0.Add(time.Hour)) {
			t.Errorf("history of removed package: %+v", h.Placement)
		}
		if got := cur["||"+ctrdPURL].Locations; !reflect.DeepEqual(got, []string{"/usr/bin/containerd"}) {
			t.Errorf("owned location lost: %v", got)
		}
	})

	t.Run("reduced coverage keeps items", func(t *testing.T) {
		r := hostReport(t0.Add(2 * time.Hour))
		r.Packages = nil
		r.Artifacts.Coverage = report.CoveragePartial
		r.Artifacts.Reason = "permission denied under /opt/svc"
		r.Artifacts.Artifacts = baseArtifacts()[:2]
		must(t, f.ingest(t, f.agent, r))
		cur := f.components(t, assetID, ptr(""), false)
		if l, ok := cur["||"+log4jPURL]; !ok || l.RemovedAt != nil {
			t.Error("item not seen under reduced coverage was removed")
		}
		if got := cur["||"+ctrdPURL].Locations; !reflect.DeepEqual(got, []string{"/usr/bin/containerd"}) {
			t.Errorf("owned location lost without packages section: %v", got)
		}
		asset, err := f.db.GetAsset(ctx, assetID)
		must(t, err)
		if asset.Coverage != store.CoveragePartial || asset.CoverageReason != "artifacts: permission denied under /opt/svc" {
			t.Errorf("asset coverage %s %q", asset.Coverage, asset.CoverageReason)
		}
	})

	t.Run("unchanged section refreshes state", func(t *testing.T) {
		at := t0.Add(3 * time.Hour)
		r := &report.Report{SchemaVersion: 1, CollectedAt: at, Subject: &report.Subject{Kind: report.SubjectSelf},
			Packages: &report.PackagesSection{SectionMeta: report.SectionMeta{Unchanged: true, Coverage: report.CoverageFull,
				CollectedAt: at, Digest: "same"}}}
		must(t, f.ingest(t, f.agent, r))
		cur := f.components(t, assetID, ptr(""), false)
		if _, ok := cur["||"+curlPURL]; !ok {
			t.Error("unchanged section changed components")
		}
		asset, err := f.db.GetAsset(ctx, assetID)
		must(t, err)
		for _, s := range asset.Sections {
			if s.Section == report.SectionPackages && (!s.CollectedAt.Equal(at) || s.Digest != "same") {
				t.Errorf("packages state %+v", s)
			}
		}
	})

	t.Run("older report is ignored", func(t *testing.T) {
		r := hostReport(t0.Add(30 * time.Minute))
		r.Packages.Packages = []report.Package{pkg("bash", "5.2.21-2ubuntu4")}
		must(t, f.ingest(t, f.agent, r))
		cur := f.components(t, assetID, ptr(""), false)
		if _, ok := cur["||"+curlPURL]; !ok {
			t.Error("older report removed a package")
		}
		if _, ok := cur["||"+sslPURL]; ok {
			t.Error("older report brought a package back")
		}
	})

	t.Run("second host shares image content", func(t *testing.T) {
		other := f.newAgent(t, store.AgentKindAgent, "")
		r := hostReport(t0)
		r.Host.Hostname, r.Host.MachineID = "web-02", "machine-web-02"
		r.Containers.ImageScopes = nil
		must(t, f.ingest(t, other, r))
		oa, err := f.db.GetAgent(ctx, other.ID)
		must(t, err)
		if oa.AssetID == assetID {
			t.Fatal("second agent joined the first asset")
		}
		if _, ok := f.components(t, oa.AssetID, ptr("web1"), false)["web1|image|"+muslPURL]; !ok {
			t.Error("image content not shared by digest")
		}
	})

	t.Run("agent sending a foreign subject is rejected", func(t *testing.T) {
		r := hostReport(t0.Add(5 * time.Hour))
		r.Subject = &report.Subject{Kind: report.SubjectScanTarget, ScanTargetID: "00000000-0000-0000-0000-000000000000"}
		if err := f.ingest(t, f.agent, r); !errors.Is(err, ErrForbidden) {
			t.Fatalf("got %v", err)
		}
		r.Subject = &report.Subject{Kind: report.SubjectK8sContainer}
		if _, err := f.svc.Accept(ctx, Sender{AgentID: f.agent.ID, Kind: store.AgentKindAgent}, encode(t, r)); !errors.Is(err, ErrForbidden) {
			t.Fatalf("accept: %v", err)
		}
		// A scanner may not send self.
		sc := f.newAgent(t, store.AgentKindScanner, "")
		r.Subject = nil
		if err := f.ingest(t, sc, r); !errors.Is(err, ErrForbidden) {
			t.Fatalf("scanner self: %v", err)
		}
	})
}

// snapshot captures what ingest writes for an asset.
func snapshot(t *testing.T, f *fixture, assetID string) any {
	t.Helper()
	d, err := f.db.GetAsset(f.ctx, assetID)
	must(t, err)
	comps, _, err := f.db.ListAssetComponents(f.ctx, assetID, store.AssetComponentFilter{IncludeRemoved: true}, store.Page{Limit: 1000})
	must(t, err)
	procs, _, err := f.db.ListProcesses(f.ctx, store.ProcessFilter{AssetID: assetID}, store.Page{Limit: 1000})
	must(t, err)
	ports, _, err := f.db.ListListenPorts(f.ctx, store.ListenPortFilter{AssetID: assetID}, store.Page{Limit: 1000})
	must(t, err)
	for i := range procs {
		procs[i].ID = ""
	}
	for i := range ports {
		ports[i].ProcessID = ""
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].PID < procs[j].PID })
	return []any{d, comps, procs, ports}
}

func TestIngestIsIdempotent(t *testing.T) {
	f := newFixture(t)
	raw := encode(t, hostReport(t0))
	sender := Sender{AgentID: f.agent.ID, Kind: store.AgentKindAgent}
	must(t, f.svc.IngestReport(f.ctx, sender, raw))
	a, err := f.db.GetAgent(f.ctx, f.agent.ID)
	must(t, err)
	before := snapshot(t, f, a.AssetID)
	id, err := f.svc.Accept(f.ctx, sender, raw)
	must(t, err)
	must(t, f.svc.IngestStored(f.ctx, id))
	after := snapshot(t, f, a.AssetID)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("second ingest changed the inventory:\nbefore %+v\nafter  %+v", before, after)
	}
}

func k8sReport(at time.Time, clusterID, ns, pod, container string, full bool) *report.Report {
	r := &report.Report{SchemaVersion: 1, CollectedAt: at, Privilege: report.Privilege{Level: report.PrivilegeNonRoot},
		Subject: &report.Subject{Kind: report.SubjectK8sContainer, K8s: &report.K8sSubject{ClusterID: clusterID,
			Namespace: ns, Pod: pod, Container: container}},
		Processes: &report.ProcessesSection{SectionMeta: meta(at, report.CoverageFull), Processes: []report.Process{
			{PID: 1, User: "app", Exe: "/app/server", ExeSource: "proc", ExeState: "normal", StartedAt: t0,
				Listen: []report.Listen{{Proto: "tcp", Address: "0.0.0.0", Port: 8080}}}}},
	}
	if full {
		r.Host = &report.HostSection{SectionMeta: meta(at, report.CoverageFull), Hostname: pod, Arch: "x86_64",
			OS: report.OS{ID: "alpine", VersionID: "3.19.1"}}
		r.Packages = &report.PackagesSection{SectionMeta: meta(at, report.CoverageFull),
			Packages: []report.Package{{Type: "apk", Name: "musl", Version: "1.2.4-r2", Arch: "x86_64"}}}
		r.Artifacts = &report.ArtifactsSection{SectionMeta: meta(at, report.CoverageFull), Artifacts: []report.Artifact{
			{Kind: "go_binary", Path: "/app/server", Module: "example.com/server", Version: "v2.0.0", GoVersion: "go1.23.0",
				Method: "buildinfo"},
			{Kind: "software", Path: "/tmp/added", Name: "added", Version: "0.1", Layer: report.LayerRuntime, Method: "static"},
		}}
	}
	return r
}

func strp(s string) *string { return &s }

func TestKubernetesInventoryAndContainerReports(t *testing.T) {
	f := newFixture(t)
	ctx := f.ctx
	cl, err := f.db.CreateCluster(ctx, store.K8sClusterConfig{Name: "prd", Connection: store.K8sInCluster, ExecEnabled: true})
	must(t, err)
	embedded := EmbeddedScanner()

	// Before the inventory the pod is unknown.
	early := encode(t, k8sReport(t0, cl.ID, "shop", "web-7d9f-abc12", "app", true))
	err = f.svc.IngestReport(ctx, embedded, early)
	var ie *Error
	if !errors.Is(err, ErrRetryLater) || !errors.As(err, &ie) || !ie.RetryLater() || ie.Permanent() {
		t.Fatalf("unknown pod: %v", err)
	}

	inv := agentapi.K8sInventory{ClusterId: cl.ID, CollectedAt: t0, ServerVersion: "v1.30.2",
		Workloads: []agentapi.K8sInventoryWorkload{
			{Namespace: "shop", Kind: "Deployment", Name: "web", Replicas: 2},
			{Namespace: "shop", Kind: "Deployment", Name: "api", Replicas: 1},
			{Namespace: "kube-system", Kind: "DaemonSet", Name: "proxy", ExcludedBy: strp("namespace kube-system")},
		},
		Pods: []agentapi.K8sInventoryPod{
			{Namespace: "shop", Name: "web-7d9f-abc12", Node: "n1", Phase: agentapi.K8sPodPhaseRunning, StartedAt: &t0,
				WorkloadKind: "Deployment", WorkloadName: "web",
				Containers: []agentapi.K8sInventoryContainer{{Name: "app", ImageRef: "shop/web:1", ImageDigest: strp("docker-pullable://shop/web@" + img1)}}},
			{Namespace: "shop", Name: "web-7d9f-def34", Node: "n2", Phase: agentapi.K8sPodPhaseRunning, StartedAt: &t0,
				WorkloadKind: "Deployment", WorkloadName: "web",
				Containers: []agentapi.K8sInventoryContainer{{Name: "app", ImageRef: "shop/web:1", ImageDigest: strp(img1)}}},
			{Namespace: "shop", Name: "api-5c4b-xyz99", Node: "n1", Phase: agentapi.K8sPodPhaseRunning, StartedAt: &t0,
				WorkloadKind: "Deployment", WorkloadName: "api",
				Containers: []agentapi.K8sInventoryContainer{{Name: "api", ImageRef: "shop/api:3", ImageDigest: strp(img2)}}},
		}}
	other := f.newAgent(t, store.AgentKindScanner, "")
	if err := f.svc.IngestK8sInventory(ctx, Sender{AgentID: other.ID, Kind: store.AgentKindScanner}, cl.ID, inv); !errors.Is(err, ErrForbidden) {
		t.Fatalf("foreign scanner: %v", err)
	}
	must(t, f.svc.IngestK8sInventory(ctx, embedded, cl.ID, inv))

	assets, _, err := f.db.ListAssets(ctx, store.AssetFilter{ClusterID: cl.ID}, store.Page{Limit: 10})
	must(t, err)
	byName := map[string]string{}
	for _, a := range assets {
		byName[a.Name] = a.ID
	}
	if len(byName) != 2 || byName["web"] == "" || byName["api"] == "" {
		t.Fatalf("workload assets %v", byName)
	}
	webID := byName["web"]

	// The stored early report succeeds now.
	must(t, f.svc.IngestReport(ctx, embedded, early))
	img, err := f.db.GetImage(ctx, img1)
	must(t, err)
	if !img.ContentKnown() || img.ContentCoverage != store.CoverageFull {
		t.Fatalf("image content %+v", img.ImageRow)
	}
	comps, _, err := f.db.ListImageComponents(ctx, img1, store.ImageComponentFilter{}, store.Page{Limit: 100})
	must(t, err)
	var purls []string
	for _, c := range comps {
		purls = append(purls, c.Component.PURL)
	}
	sort.Strings(purls)
	want := []string{muslPURL, "pkg:golang/example.com/server@v2.0.0", "pkg:golang/stdlib@1.23.0"}
	sort.Strings(want)
	if !reflect.DeepEqual(purls, want) {
		t.Errorf("image components %v", purls)
	}
	rows := f.components(t, webID, ptr("app"), false)
	if _, ok := rows["app|runtime|pkg:generic/added@0.1"]; !ok {
		t.Errorf("runtime layer missing: %v", rows)
	}
	if _, ok := rows["app|image|"+muslPURL]; !ok {
		t.Errorf("image layer missing: %v", rows)
	}

	// Second replica: processes only.
	must(t, f.svc.IngestReport(ctx, embedded, encode(t, k8sReport(t0.Add(time.Minute), cl.ID, "shop", "web-7d9f-def34", "app", false))))
	// api: processes only and no content known for its digest.
	must(t, f.svc.IngestReport(ctx, embedded, encode(t, k8sReport(t0.Add(time.Minute), cl.ID, "shop", "api-5c4b-xyz99", "api", false))))

	pods, _, err := f.db.ListAssetInstances(ctx, webID, store.PodFilter{}, store.Page{Limit: 10})
	must(t, err)
	podCov := map[string]store.Coverage{}
	for _, p := range pods {
		for _, c := range p.Containers {
			podCov[p.Name] = c.Coverage
		}
	}
	// The replica collected for processes only runs an image whose content
	// is known: full as well.
	if podCov["web-7d9f-abc12"] != store.CoverageFull || podCov["web-7d9f-def34"] != store.CoverageFull {
		t.Errorf("pod coverage %v", podCov)
	}
	web, err := f.db.GetAsset(ctx, webID)
	must(t, err)
	if len(web.Containers) != 1 || web.Containers[0].Coverage != store.CoverageFull || web.Coverage != store.CoverageFull ||
		web.Method != store.CollectK8sExec {
		t.Errorf("web asset %+v containers %+v", web.Asset, web.Containers)
	}
	api, err := f.db.GetAsset(ctx, byName["api"])
	must(t, err)
	if len(api.Containers) != 1 || api.Containers[0].Coverage != store.CoverageProcessOnly || api.Coverage != store.CoverageProcessOnly {
		t.Errorf("api asset %+v containers %+v", api.Asset, api.Containers)
	}
	procs, _, err := f.db.ListProcesses(ctx, store.ProcessFilter{AssetID: webID}, store.Page{Limit: 10})
	must(t, err)
	podsSeen := map[string]bool{}
	for _, p := range procs {
		podsSeen[p.Pod] = p.Container == "app"
	}
	if !podsSeen["web-7d9f-abc12"] || !podsSeen["web-7d9f-def34"] {
		t.Errorf("pod process scopes %v", podsSeen)
	}

	// An older inventory is ignored.
	stale := inv
	stale.CollectedAt = t0.Add(-time.Hour)
	stale.Pods = nil
	must(t, f.svc.IngestK8sInventory(ctx, embedded, cl.ID, stale))
	if _, err := f.db.GetAsset(ctx, webID); err != nil {
		t.Fatal(err)
	}
	pods, _, err = f.db.ListAssetInstances(ctx, webID, store.PodFilter{}, store.Page{Limit: 10})
	must(t, err)
	if len(pods) != 2 {
		t.Errorf("stale inventory applied: %d pods", len(pods))
	}

	// A scanner that is not the cluster's may not report its containers.
	if err := f.ingest(t, other, k8sReport(t0.Add(time.Hour), cl.ID, "shop", "web-7d9f-abc12", "app", false)); !errors.Is(err, ErrForbidden) {
		t.Fatalf("foreign scanner report: %v", err)
	}
}

func TestScanTargetReportAndResult(t *testing.T) {
	f := newFixture(t)
	ctx := f.ctx
	cred, err := f.db.CreateCredential(ctx, store.Credential{Name: "key", Kind: store.CredentialSSHKey, Username: "root",
		Secret: []byte("sealed")})
	must(t, err)
	tg, err := f.db.CreateScanTarget(ctx, store.ScanTarget{Name: "db-01", Address: "10.0.0.9", Port: 22, CredentialID: cred.ID})
	must(t, err)

	r := hostReport(t0)
	r.Subject = &report.Subject{Kind: report.SubjectScanTarget, ScanTargetID: tg.ID}
	r.Host.MachineID = "machine-db-01"
	must(t, f.svc.IngestReport(ctx, EmbeddedScanner(), encode(t, r)))
	tg, err = f.db.GetScanTarget(ctx, tg.ID)
	must(t, err)
	if tg.AssetID == "" {
		t.Fatal("scan target not linked")
	}
	asset, err := f.db.GetAsset(ctx, tg.AssetID)
	must(t, err)
	if asset.Name != "db-01" || asset.Method != store.CollectSSH || asset.Address != "10.0.0.9" {
		t.Errorf("asset %+v", asset.Asset)
	}

	sc := f.newAgent(t, store.AgentKindScanner, "")
	if err := f.svc.RecordScanResult(ctx, Sender{AgentID: sc.ID, Kind: store.AgentKindScanner}, tg.ID,
		ScanResult{Status: store.ScanFailed}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("foreign scanner: %v", err)
	}
	must(t, f.svc.RecordScanResult(ctx, EmbeddedScanner(), tg.ID, ScanResult{Status: store.ScanFailed,
		Message: "connection refused", StartedAt: t0, FinishedAt: t0.Add(2 * time.Second)}))
	tg, err = f.db.GetScanTarget(ctx, tg.ID)
	must(t, err)
	if tg.LastRun == nil || tg.LastRun.Result != store.ScanFailed || tg.LastRun.Duration != 2*time.Second {
		t.Errorf("last run %+v", tg.LastRun)
	}
	asset, err = f.db.GetAsset(ctx, tg.AssetID)
	must(t, err)
	if asset.Coverage != store.CoverageFailed || asset.CoverageReason != "connection refused" {
		t.Errorf("coverage %s %q", asset.Coverage, asset.CoverageReason)
	}
}

// TestReducedCoverageSequence: items that a reduced report cannot see are
// kept through any number of reduced reports and reconciled by the next
// full one (ARCH 3.6).
func TestReducedCoverageSequence(t *testing.T) {
	f := newFixture(t)
	ctx := f.ctx
	const xnetPURL = "pkg:golang/golang.org/x/net@v0.20.0"
	const toolPURL = "pkg:generic/tool@1.0"
	tool := report.Artifact{Kind: "software", Path: "/usr/local/bin/tool", Name: "tool", Version: "1.0", Method: "static"}

	r := hostReport(t0)
	must(t, f.ingest(t, f.agent, r))
	a, err := f.db.GetAgent(ctx, f.agent.ID)
	must(t, err)
	assetID := a.AssetID

	check := func(step string, current, gone []string, cov, baseline store.Coverage) {
		t.Helper()
		cur := f.components(t, assetID, ptr(""), false)
		for _, p := range current {
			if _, ok := cur["||"+p]; !ok {
				t.Errorf("%s: %s not current", step, p)
			}
		}
		for _, p := range gone {
			if _, ok := cur["||"+p]; ok {
				t.Errorf("%s: %s still current", step, p)
			}
		}
		d, err := f.db.GetAsset(ctx, assetID)
		must(t, err)
		for _, s := range d.Sections {
			if s.Container == "" && s.Section == report.SectionArtifacts && (s.Coverage != cov || s.Baseline != baseline) {
				t.Errorf("%s: artifacts state %s, baseline %s; want %s, %s", step, s.Coverage, s.Baseline, cov, baseline)
			}
		}
	}
	check("full", []string{log4jPURL, xnetPURL, appPURL}, []string{toolPURL}, store.CoverageFull, store.CoverageFull)

	// log4j is out of view (permission denied), x/net is really gone, the
	// tool is only seen under the reduced coverage.
	for i, at := range []time.Time{t0.Add(time.Hour), t0.Add(2 * time.Hour)} {
		r := hostReport(at)
		r.Artifacts.Coverage, r.Artifacts.Reason = report.CoveragePartial, "permission denied under /opt/svc"
		r.Artifacts.Artifacts = baseArtifacts()[:2]
		if i == 0 {
			r.Artifacts.Artifacts = append(r.Artifacts.Artifacts, tool)
		}
		must(t, f.ingest(t, f.agent, r))
		check(fmt.Sprintf("partial %d", i+1), []string{log4jPURL, xnetPURL, appPURL, toolPURL}, nil,
			store.CoveragePartial, store.CoverageFull)
	}

	r = hostReport(t0.Add(3 * time.Hour))
	r.Artifacts.Artifacts = append(baseArtifacts()[:2], baseArtifacts()[3])
	must(t, f.ingest(t, f.agent, r))
	check("full again", []string{log4jPURL, appPURL}, []string{xnetPURL, toolPURL}, store.CoverageFull, store.CoverageFull)
	hist := f.components(t, assetID, ptr(""), true)
	if h := hist["||"+xnetPURL]; h.RemovedAt == nil || !h.RemovedAt.Equal(t0.Add(3*time.Hour)) {
		t.Errorf("x/net removal: %+v", h.Placement)
	}

	// Partial with a partial baseline replaces the set: equal coverage.
	r = hostReport(t0.Add(4 * time.Hour))
	r.Artifacts.Coverage = report.CoveragePartial
	r.Artifacts.Artifacts = baseArtifacts()[:2]
	must(t, f.ingest(t, f.agent, r))
	check("partial after full", []string{log4jPURL}, nil, store.CoveragePartial, store.CoverageFull)
	r = hostReport(t0.Add(5 * time.Hour))
	r.Artifacts.Coverage = report.CoverageNone
	r.Artifacts.Artifacts = nil
	must(t, f.ingest(t, f.agent, r))
	check("none", []string{log4jPURL, appPURL}, nil, store.CoverageNone, store.CoverageFull)
}

// TestScanTargetIdentity: a scan target resolves its host through the
// target, independent of the scanner, also without a machine id.
func TestScanTargetIdentity(t *testing.T) {
	f := newFixture(t)
	ctx := f.ctx
	cred, err := f.db.CreateCredential(ctx, store.Credential{Name: "key", Kind: store.CredentialSSHKey, Username: "root",
		Secret: []byte("sealed")})
	must(t, err)
	tg, err := f.db.CreateScanTarget(ctx, store.ScanTarget{Name: "db-01", Address: "10.0.0.9", Port: 22, CredentialID: cred.ID})
	must(t, err)

	targetReport := func(id, machineID string, at time.Time) *report.Report {
		r := hostReport(at)
		r.Subject = &report.Subject{Kind: report.SubjectScanTarget, ScanTargetID: id}
		r.Host.MachineID = machineID
		r.Containers = nil
		return r
	}
	hosts := func() int {
		t.Helper()
		_, n, err := f.db.ListAssets(ctx, store.AssetFilter{Kind: store.AssetHost}, store.Page{Limit: 1})
		must(t, err)
		return n
	}

	// Embedded scanner, no machine id: the first report creates the asset.
	must(t, f.svc.IngestReport(ctx, EmbeddedScanner(), encode(t, targetReport(tg.ID, "", t0))))
	tg, err = f.db.GetScanTarget(ctx, tg.ID)
	must(t, err)
	if tg.AssetID == "" {
		t.Fatal("scan target not linked")
	}
	first := tg.AssetID
	asset, err := f.db.GetAsset(ctx, first)
	must(t, err)
	if asset.Name != "db-01" || asset.ScanTargetID != tg.ID || asset.Method != store.CollectSSH || asset.MachineID != "" {
		t.Fatalf("asset %+v", asset.Asset)
	}
	must(t, f.svc.IngestReport(ctx, EmbeddedScanner(), encode(t, targetReport(tg.ID, "", t0.Add(time.Hour)))))
	if n := hosts(); n != 1 {
		t.Fatalf("second report created an asset: %d hosts", n)
	}

	// Moving the target to a remote scanner keeps the asset; a machine id
	// reported later is added to it.
	sc := f.newAgent(t, store.AgentKindScanner, "")
	tg.ScannerID = sc.ID
	must(t, f.db.UpdateScanTarget(ctx, tg))
	must(t, f.ingest(t, sc, targetReport(tg.ID, "machine-db-01", t0.Add(2*time.Hour))))
	tg, err = f.db.GetScanTarget(ctx, tg.ID)
	must(t, err)
	asset, err = f.db.GetAsset(ctx, first)
	must(t, err)
	if tg.AssetID != first || hosts() != 1 || asset.MachineID != "machine-db-01" {
		t.Fatalf("after scanner change: target asset %s, %d hosts, machine id %q", tg.AssetID, hosts(), asset.MachineID)
	}

	// A new target of a machine already known by its machine id joins
	// that asset on its first report.
	known, err := f.db.UpsertHostAsset(ctx, store.HostIdentity{MachineID: "machine-db-02"}, store.AssetInit{Name: "db-02"})
	must(t, err)
	tg2, err := f.db.CreateScanTarget(ctx, store.ScanTarget{Name: "db-02 ssh", Address: "10.0.0.10", Port: 22, CredentialID: cred.ID})
	must(t, err)
	must(t, f.svc.IngestReport(ctx, EmbeddedScanner(), encode(t, targetReport(tg2.ID, "machine-db-02", t0))))
	tg2, err = f.db.GetScanTarget(ctx, tg2.ID)
	must(t, err)
	if tg2.AssetID != known.ID {
		t.Fatalf("target joined %s, want %s", tg2.AssetID, known.ID)
	}
}

// TestStoredReportKeepsSender: a queued report is applied with the sender
// recorded at upload, including its address.
func TestStoredReportKeepsSender(t *testing.T) {
	f := newFixture(t)
	ctx := f.ctx
	sender := Sender{AgentID: f.agent.ID, Kind: store.AgentKindAgent, RemoteAddr: "192.0.2.7:51000"}
	id, err := f.svc.Accept(ctx, sender, encode(t, hostReport(t0)))
	must(t, err)
	rr, err := f.db.GetReport(ctx, id)
	must(t, err)
	if rr.SenderKind != store.AgentKindAgent || rr.RemoteAddr != "192.0.2.7:51000" || rr.SourceID != f.agent.ID {
		t.Fatalf("raw report sender %q %q %q", rr.SenderKind, rr.RemoteAddr, rr.SourceID)
	}
	must(t, f.svc.IngestStored(ctx, id))
	a, err := f.db.GetAgent(ctx, f.agent.ID)
	must(t, err)
	asset, err := f.db.GetAsset(ctx, a.AssetID)
	must(t, err)
	if asset.Address != "192.0.2.7" {
		t.Fatalf("address %q", asset.Address)
	}

	cred, err := f.db.CreateCredential(ctx, store.Credential{Name: "key", Kind: store.CredentialSSHKey, Username: "root",
		Secret: []byte("sealed")})
	must(t, err)
	tg, err := f.db.CreateScanTarget(ctx, store.ScanTarget{Name: "db", Address: "10.0.0.9", Port: 22, CredentialID: cred.ID})
	must(t, err)
	r := hostReport(t0)
	r.Subject = &report.Subject{Kind: report.SubjectScanTarget, ScanTargetID: tg.ID}
	id, err = f.svc.Accept(ctx, EmbeddedScanner(), encode(t, r))
	must(t, err)
	must(t, f.svc.IngestStored(ctx, id))
	if tg, err = f.db.GetScanTarget(ctx, tg.ID); err != nil || tg.AssetID == "" {
		t.Fatalf("embedded scanner report not applied: %v %+v", err, tg)
	}
}

// TestKubernetesCoverageIsWhatIsKnown: coverage describes what is known
// about a container now. A re-sync that collects processes only keeps the
// coverage that the known image content gives.
func TestKubernetesCoverageIsWhatIsKnown(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content report.Coverage
		want    store.Coverage
	}{
		{"full content", report.CoverageFull, store.CoverageFull},
		{"partial content", report.CoveragePartial, store.CoveragePartial},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			ctx := f.ctx
			cl, err := f.db.CreateCluster(ctx, store.K8sClusterConfig{Name: "prd", Connection: store.K8sInCluster, ExecEnabled: true})
			must(t, err)
			embedded := EmbeddedScanner()
			pods := []string{"web-1", "web-2", "web-3"}
			sync := func(at time.Time) {
				t.Helper()
				inv := agentapi.K8sInventory{ClusterId: cl.ID, CollectedAt: at, ServerVersion: "v1.30.2",
					Workloads: []agentapi.K8sInventoryWorkload{{Namespace: "shop", Kind: "Deployment", Name: "web", Replicas: 3}}}
				for _, p := range pods {
					inv.Pods = append(inv.Pods, agentapi.K8sInventoryPod{Namespace: "shop", Name: p, Node: "n1",
						Phase: agentapi.K8sPodPhaseRunning, StartedAt: &t0, WorkloadKind: "Deployment", WorkloadName: "web",
						Containers: []agentapi.K8sInventoryContainer{{Name: "app", ImageRef: "shop/web:1", ImageDigest: strp(img1)}}})
				}
				must(t, f.svc.IngestK8sInventory(ctx, embedded, cl.ID, inv))
			}
			collect := func(at time.Time, pod string, full bool) {
				t.Helper()
				r := k8sReport(at, cl.ID, "shop", pod, "app", full)
				if full {
					r.Artifacts.Coverage, r.Artifacts.Reason = tc.content, "permission denied under /opt"
					if tc.content == report.CoverageFull {
						r.Artifacts.Reason = ""
					}
				}
				must(t, f.svc.IngestReport(ctx, embedded, encode(t, r)))
			}
			check := func(step string) {
				t.Helper()
				assets, _, err := f.db.ListAssets(ctx, store.AssetFilter{ClusterID: cl.ID}, store.Page{Limit: 10})
				must(t, err)
				if len(assets) != 1 {
					t.Fatalf("%s: %d assets", step, len(assets))
				}
				web, err := f.db.GetAsset(ctx, assets[0].ID)
				must(t, err)
				if len(web.Containers) != 1 || web.Containers[0].Coverage != tc.want || web.Coverage != tc.want {
					t.Errorf("%s: asset %s, containers %+v", step, web.Coverage, web.Containers)
				}
				insts, _, err := f.db.ListAssetInstances(ctx, web.ID, store.PodFilter{}, store.Page{Limit: 10})
				must(t, err)
				for _, p := range insts {
					if len(p.Containers) != 1 || p.Containers[0].Coverage != tc.want {
						t.Errorf("%s: pod %s containers %+v", step, p.Name, p.Containers)
					}
				}
				rows, _, err := f.db.ListWorkloads(ctx, cl.ID, store.WorkloadFilter{}, store.Page{Limit: 10})
				must(t, err)
				if len(rows) != 1 || !slices.Equal(rows[0].Coverages, []store.Coverage{tc.want}) {
					t.Errorf("%s: workload rows %+v", step, rows)
				}
			}

			// First run: one pod collected in full, the others for processes.
			sync(t0)
			collect(t0.Add(time.Minute), "web-1", true)
			collect(t0.Add(2*time.Minute), "web-2", false)
			collect(t0.Add(2*time.Minute), "web-3", false)
			check("first run")

			// Second run: the image content is known, every pod is
			// collected for processes only.
			sync(t0.Add(time.Hour))
			for _, p := range pods {
				collect(t0.Add(time.Hour+time.Minute), p, false)
			}
			check("second run")
			img, err := f.db.GetImage(ctx, img1)
			must(t, err)
			if img.ContentCoverage != tc.want {
				t.Errorf("image content coverage %s", img.ContentCoverage)
			}
		})
	}
}
