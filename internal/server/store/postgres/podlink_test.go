// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

// TestPodLinks: a host container that a node agent reports for a pod
// belongs to the pod's workload asset.
func TestPodLinks(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	srv, err := db.GetActiveFeedServer(ctx)
	ivMust(t, err)

	const digest = "sha256:bbbb"
	const podCtr = "default/web-abc/nginx"
	musl := store.Component{Type: "apk", Name: "musl", Version: "1.2.5-r0", Distro: "alpine-3.20",
		PURL: "pkg:apk/alpine/musl@1.2.5-r0?distro=alpine-3.20", Origin: store.OriginDistro}
	_, err = db.PutImageContent(ctx, store.ImageContent{Digest: digest, Coverage: store.CoverageFull, CollectedAt: ivT0,
		Packages: []store.ComponentObservation{{Component: musl, Locations: []string{"/lib/apk/db/installed"}, Method: store.DetectPackageDB}}})
	ivMust(t, err)

	c, err := db.CreateCluster(ctx, store.K8sClusterConfig{Name: "prod", Connection: store.K8sInCluster})
	ivMust(t, err)
	inv := store.K8sInventory{At: ivT0, Workloads: []store.K8sWorkloadObservation{{
		Namespace: "default", Kind: "Deployment", Name: "web", Replicas: 1,
		Pods: []store.K8sPodObservation{{UID: "uid-1", Name: "web-abc", Node: "worker-1", Phase: "Running", StartedAt: ivT0,
			Containers: []store.K8sPodContainerObservation{{Name: "nginx", ImageRef: "nginx:1", ImageDigest: digest}}}},
	}}}
	res, err := db.ReplaceClusterInventory(ctx, c.ID, inv)
	ivMust(t, err)
	wl := res.Workloads[0].AssetID
	pod, err := db.GetPod(ctx, c.ID, "default", "web-abc")
	ivMust(t, err)
	if pod.UID != "uid-1" {
		t.Fatalf("pod uid %q", pod.UID)
	}

	host := ivHost(t, db, "worker-1")
	ivMust(t, db.ReplaceContainers(ctx, host, []store.ContainerObservation{
		{Name: podCtr, RuntimeID: "rid-1", ImageRef: "nginx:1", ImageDigest: digest, Runtime: store.RuntimeContainerd,
			Instances: 1, Coverage: store.CoverageFull, PodUID: "uid-1", PodContainer: "nginx"},
		{Name: "standalone", RuntimeID: "rid-2", ImageRef: "nginx:1", ImageDigest: digest, Runtime: store.RuntimeContainerd,
			Instances: 1, Coverage: store.CoverageFull},
	}, store.ReplaceOptions{At: ivT0}))
	// A file added at run time in the pod container.
	openssl := ivDeb("openssl", "3.0.13-0ubuntu3")
	_, err = db.ReplaceAssetComponents(ctx, store.ComponentScope{AssetID: host, Container: podCtr,
		Source: store.SourceArtifacts, Layer: store.LayerRuntime}, ivPkgObs(openssl), store.ReplaceOptions{At: ivT0})
	ivMust(t, err)
	ivMust(t, db.SetSectionStates(ctx, host, []store.SectionState{{Section: "processes", Coverage: store.CoverageFull, CollectedAt: ivT0}}))
	_, err = db.ReplaceProcesses(ctx, store.ProcessScope{AssetID: host}, store.ProcessSnapshot{At: ivT0, Processes: []store.ProcessObservation{
		{PID: 70242, Exe: "/usr/sbin/nginx", StartedAt: ivT0, Container: podCtr, OtherNetNS: true,
			Listen: []store.ListenAddr{{Proto: "tcp", Address: "0.0.0.0", Port: 8080}}},
		{PID: 500, Exe: "/usr/sbin/nginx", StartedAt: ivT0, Container: "standalone", OtherNetNS: true,
			Listen: []store.ListenAddr{{Proto: "tcp", Address: "0.0.0.0", Port: 80}}},
		// In the host's network (a hostNetwork pod): a port of the host.
		{PID: 600, Exe: "/usr/bin/kube-proxy", StartedAt: ivT0, Container: podCtr,
			Listen: []store.ListenAddr{{Proto: "tcp", Address: "0.0.0.0", Port: 10256}}},
	}})
	ivMust(t, err)
	// The scanner collected the same pod through exec before.
	_, err = db.ReplaceProcesses(ctx, store.ProcessScope{AssetID: wl, Pod: "web-abc", Container: "nginx"},
		store.ProcessSnapshot{At: ivT0, Processes: []store.ProcessObservation{{PID: 9, Exe: "/usr/sbin/nginx", StartedAt: ivT0,
			Listen: []store.ListenAddr{{Proto: "tcp", Address: "0.0.0.0", Port: 8080}}}}})
	ivMust(t, err)

	pending, err := db.PendingMatches(ctx, store.MatchEpoch{ServerID: srv.ID, Revision: 1}, 10)
	ivMust(t, err)
	var cms []store.ComponentMatch
	for _, p := range pending {
		cms = append(cms, store.ComponentMatch{ComponentID: p.ID, Status: store.MatchChecked,
			Vulns: []store.ComponentVuln{{VulnID: "CVE-" + p.Name, Method: "package", FixState: "fixed"}}})
	}
	ivMust(t, db.SaveMatches(ctx, store.MatchBatch{Epoch: store.MatchEpoch{ServerID: srv.ID, Revision: 1}, Components: cms,
		Vulns: []store.VulnMeta{{ID: "CVE-musl"}, {ID: "CVE-openssl"}}}))

	setSeen := func(at time.Time) {
		t.Helper()
		_, err := db.q.Exec(ctx, `UPDATE assets SET last_seen = $2 WHERE id = $1`, host, at)
		ivMust(t, err)
	}
	setSeen(time.Now())

	// The host keeps its own container only.
	in, err := db.FindingInputs(ctx, host)
	ivMust(t, err)
	if len(in.Sources) != 1 || in.Sources[0].Container != "standalone" {
		t.Fatalf("host sources %+v", in.Sources)
	}
	if len(in.Processes) != 1 || in.Processes[0].PID != 500 {
		t.Fatalf("host processes %+v", in.Processes)
	}

	// The workload gets the runtime layer and the processes the host saw.
	in, err = db.FindingInputs(ctx, wl)
	ivMust(t, err)
	if len(in.NodeContainers) != 1 || !in.NodeContainers[0].Fresh || in.NodeContainers[0].RuntimeID != "rid-1" ||
		in.NodeContainers[0].HostID != host || in.NodeContainers[0].Container != "nginx" {
		t.Fatalf("node containers %+v", in.NodeContainers)
	}
	layers := map[string]string{}
	for _, s := range in.Sources {
		if s.Container != "nginx" {
			t.Fatalf("workload source %+v", s)
		}
		layers[s.Component.Name] = s.Layer
	}
	if layers["musl"] != store.FindingLayerImage || layers["openssl"] != store.FindingLayerRuntime {
		t.Fatalf("workload layers %v", layers)
	}
	if len(in.Processes) != 2 || in.Processes[0].PID != 600 {
		t.Fatalf("workload processes %+v", in.Processes)
	}
	p := in.Processes[1]
	if p.PID != 70242 || p.Node != "worker-1" || p.Pod != "web-abc" || p.Container != "nginx" || !slices.Equal(p.Ports, []string{"tcp/8080"}) {
		t.Fatalf("workload process %+v", p)
	}
	if in.ProcessCoverage["nginx"] != store.CoverageFull {
		t.Fatalf("process coverage %v", in.ProcessCoverage)
	}

	// The pod's socket is listed once, under the workload; the host keeps
	// the sockets of its own network and of the standalone container.
	ports := func(asset string) []string {
		t.Helper()
		rows, total, err := db.ListListenPorts(ctx, store.ListenPortFilter{AssetID: asset}, store.Page{Limit: 10})
		ivMust(t, err)
		if total != len(rows) {
			t.Fatalf("listen ports of %s: total %d, rows %+v", asset, total, rows)
		}
		var out []string
		for _, r := range rows {
			out = append(out, fmt.Sprintf("%s/%s %d %d %s", r.Pod, r.Container, r.Port, r.PID, r.Node))
		}
		slices.Sort(out)
		return out
	}
	if got := ports(host); !slices.Equal(got, []string{"/" + podCtr + " 10256 600 ", "/standalone 80 500 "}) {
		t.Fatalf("host ports %q", got)
	}
	if got := ports(wl); !slices.Equal(got, []string{"web-abc/nginx 8080 70242 worker-1"}) {
		t.Fatalf("workload ports %q", got)
	}

	detail, err := db.GetAsset(ctx, host)
	ivMust(t, err)
	for _, ct := range detail.Containers {
		switch {
		case ct.Name == podCtr && (ct.Workload == nil || ct.Workload.AssetID != wl || ct.Workload.Pod != "web-abc" ||
			ct.PodUID != "uid-1" || ct.PodContainer != "nginx"):
			t.Fatalf("pod container %+v / %+v", ct, ct.Workload)
		case ct.Name == "standalone" && ct.Workload != nil:
			t.Fatalf("standalone linked %+v", ct.Workload)
		}
	}

	// A host that stopped reporting: the exec processes count again; the
	// runtime layer stays.
	setSeen(time.Now().Add(-3 * time.Hour))
	in, err = db.FindingInputs(ctx, wl)
	ivMust(t, err)
	if len(in.Processes) != 1 || in.Processes[0].PID != 9 || in.Processes[0].Node != "" || in.NodeContainers[0].Fresh {
		t.Fatalf("stale host: processes %+v nodes %+v", in.Processes, in.NodeContainers)
	}
	if len(in.Sources) != 2 {
		t.Fatalf("stale host: sources %+v", in.Sources)
	}

	// An exec into the workload container after the node container started
	// collected the same file: its version (from the version command)
	// replaces the static one of the node agent.
	opensslExec := ivDeb("openssl", "3.0.13-0ubuntu3.4")
	_, err = db.ReplaceAssetComponents(ctx, store.ComponentScope{AssetID: wl, Container: "nginx",
		Source: store.SourceArtifacts, Layer: store.LayerRuntime}, ivPkgObs(opensslExec), store.ReplaceOptions{At: ivT0})
	ivMust(t, err)
	ivMust(t, db.SetSectionStates(ctx, wl, []store.SectionState{{Container: "nginx", Section: "artifacts",
		Coverage: store.CoverageFull, CollectedAt: ivT0.Add(time.Minute)}}))
	pending, err = db.PendingMatches(ctx, store.MatchEpoch{ServerID: srv.ID, Revision: 1}, 10)
	ivMust(t, err)
	cms = nil
	for _, p := range pending {
		cms = append(cms, store.ComponentMatch{ComponentID: p.ID, Status: store.MatchChecked,
			Vulns: []store.ComponentVuln{{VulnID: "CVE-" + p.Name, Method: "package", FixState: "fixed"}}})
	}
	ivMust(t, db.SaveMatches(ctx, store.MatchBatch{Epoch: store.MatchEpoch{ServerID: srv.ID, Revision: 1}, Components: cms,
		Vulns: []store.VulnMeta{{ID: "CVE-openssl"}}}))
	opensslVersions := func() []string {
		t.Helper()
		in, err := db.FindingInputs(ctx, wl)
		ivMust(t, err)
		var vs []string
		for _, s := range in.Sources {
			if s.Component.Name == "openssl" {
				vs = append(vs, s.Component.Version)
			}
		}
		slices.Sort(vs)
		return vs
	}
	if v := opensslVersions(); !slices.Equal(v, []string{"3.0.13-0ubuntu3.4"}) {
		t.Fatalf("exec after start: openssl %v", v)
	}
	// An exec from before the node container started does not count.
	_, err = db.q.Exec(ctx, `UPDATE asset_containers SET started_at = $3 WHERE asset_id = $1 AND name = $2`,
		host, podCtr, ivT0.Add(2*time.Minute))
	ivMust(t, err)
	if v := opensslVersions(); !slices.Equal(v, []string{"3.0.13-0ubuntu3", "3.0.13-0ubuntu3.4"}) {
		t.Fatalf("exec before start: openssl %v", v)
	}

	// A host report makes the workload dirty, a cluster sync the host.
	for _, id := range []string{host, wl} {
		in, err := db.FindingInputs(ctx, id)
		ivMust(t, err)
		_, err = db.ApplyFindings(ctx, id, nil, in.Stamp)
		ivMust(t, err)
	}
	ivMust(t, db.TouchPodLinks(ctx, host))
	dirty, err := db.DirtyFindingAssets(ctx, 10)
	ivMust(t, err)
	if !slices.Contains(dirty, wl) || slices.Contains(dirty, host) {
		t.Fatalf("dirty after host report %v", dirty)
	}
	inv.At = ivT0.Add(time.Minute)
	_, err = db.ReplaceClusterInventory(ctx, c.ID, inv)
	ivMust(t, err)
	if dirty, _ := db.DirtyFindingAssets(ctx, 10); !slices.Contains(dirty, host) {
		t.Fatalf("dirty after sync %v", dirty)
	}

	// The pod is gone: the host owns its container again.
	inv.At = ivT0.Add(2 * time.Minute)
	inv.Workloads[0].Pods = nil
	_, err = db.ReplaceClusterInventory(ctx, c.ID, inv)
	ivMust(t, err)
	in, err = db.FindingInputs(ctx, host)
	ivMust(t, err)
	if len(in.Sources) != 3 {
		t.Fatalf("host sources after pod gone %+v", in.Sources)
	}
}
