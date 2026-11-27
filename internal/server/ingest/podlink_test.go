// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package ingest

import (
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/agentproto/dto"
	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// TestNodeAgentPodContainer: a node agent's report links its pod container
// to the workload and gives the pod container the coverage the host read.
func TestNodeAgentPodContainer(t *testing.T) {
	f := newFixture(t)
	ctx := f.ctx
	cl, err := f.db.CreateCluster(ctx, store.K8sClusterConfig{Name: "prd", Connection: store.K8sInCluster, ExecEnabled: true})
	must(t, err)
	inv := dto.K8sInventory{ClusterId: cl.ID, CollectedAt: t0, ServerVersion: "v1.30.2",
		Workloads: []dto.K8sInventoryWorkload{{Namespace: "shop", Kind: "Deployment", Name: "web", Replicas: 2}},
		Pods: []dto.K8sInventoryPod{
			{Uid: strp("uid-a"), Namespace: "shop", Name: "web-a", Node: "web-01", Phase: dto.K8sPodPhaseRunning, StartedAt: &t0,
				WorkloadKind: "Deployment", WorkloadName: "web",
				Containers: []dto.K8sInventoryContainer{{Name: "app", ImageRef: "nginx:1.25-alpine", ImageDigest: strp(img1)}}},
			{Uid: strp("uid-b"), Namespace: "shop", Name: "web-b", Node: "web-02", Phase: dto.K8sPodPhaseRunning, StartedAt: &t0,
				WorkloadKind: "Deployment", WorkloadName: "web",
				Containers: []dto.K8sInventoryContainer{{Name: "app", ImageRef: "nginx:1.25-alpine", ImageDigest: strp(img1)}}},
		}}
	must(t, f.svc.IngestK8sInventory(ctx, EmbeddedScanner(), cl.ID, inv))

	r := hostReport(t0)
	const podID = "c0ffee0000000000000000000000000000000000000000000000000000000001"
	r.Containers.Runtimes = []string{"docker", "containerd"}
	r.Containers.Containers = append(r.Containers.Containers, report.Container{
		ID: podID, Name: "shop/web-a/app", Runtime: "containerd", ImageRef: "nginx:1.25-alpine", ImageDigest: img1,
		Running: true, Coverage: report.CoverageFull,
		Pod: &report.PodRef{UID: "uid-a", Namespace: "shop", Name: "web-a", Container: "app"},
	})
	must(t, f.ingest(t, f.agent, r))

	assets, _, err := f.db.ListAssets(ctx, store.AssetFilter{ClusterID: cl.ID}, store.Page{Limit: 10})
	must(t, err)
	if len(assets) != 1 {
		t.Fatalf("workload assets %+v", assets)
	}
	wl, err := f.db.GetAsset(ctx, assets[0].ID)
	must(t, err)
	pods, _, err := f.db.ListWorkloadPods(ctx, wl.WorkloadID, store.PodFilter{}, store.Page{Limit: 10})
	must(t, err)
	cov := map[string]store.Coverage{}
	for _, p := range pods {
		cov[p.Name] = p.Containers[0].Coverage
	}
	// web-b runs on a node without an agent and was not collected.
	if cov["web-a"] != store.CoverageFull || cov["web-b"] != store.CoverageInventoryOnly {
		t.Fatalf("pod coverage %v", cov)
	}
	if len(wl.Containers) != 1 || wl.Containers[0].Coverage != store.CoverageFull || wl.Coverage != store.CoverageFull {
		t.Fatalf("workload coverage %s, containers %+v", wl.Coverage, wl.Containers)
	}

	var host store.AssetDetail
	all, _, err := f.db.ListAssets(ctx, store.AssetFilter{Kind: store.AssetHost}, store.Page{Limit: 10})
	must(t, err)
	host, err = f.db.GetAsset(ctx, all[0].ID)
	must(t, err)
	for _, c := range host.Containers {
		linked := c.Workload != nil && c.Workload.AssetID == wl.ID && c.Workload.Pod == "web-a"
		if (c.Name == "shop/web-a/app") != linked {
			t.Errorf("container %s linked %+v", c.Name, c.Workload)
		}
	}

	// A lower coverage from the node does not replace a higher one (from
	// an exec into the pod).
	must(t, f.db.SetPodContainerCoverage(ctx, cl.ID, "shop", "web-a", "app", store.CoverageFull, ""))
	t1 := t0.Add(time.Minute)
	r = hostReport(t1)
	r.Containers.Runtimes = []string{"docker", "containerd"}
	r.Containers.Containers = append(r.Containers.Containers, report.Container{
		ID: podID, Name: "shop/web-a/app", Runtime: "containerd", ImageRef: "nginx:1.25-alpine", ImageDigest: img1,
		Running: true, Coverage: report.CoveragePartial,
		Pod: &report.PodRef{UID: "uid-a", Namespace: "shop", Name: "web-a", Container: "app"},
	})
	must(t, f.ingest(t, f.agent, r))
	pod, err := f.db.GetPod(ctx, cl.ID, "shop", "web-a")
	must(t, err)
	if pod.Containers[0].Coverage != store.CoverageFull {
		t.Fatalf("pod coverage after a partial node report %+v", pod.Containers[0])
	}
}
