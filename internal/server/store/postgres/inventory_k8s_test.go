// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

func TestClusterCRUD(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	cfg := store.K8sClusterConfig{Name: "prd", Connection: store.K8sKubeconfig, CredentialID: uuid.NewString(),
		ScannerID: uuid.NewString(), ExecEnabled: true, Filter: store.K8sFilter{NSExclude: []string{"kube-*"}}}
	c, err := db.CreateCluster(ctx, cfg)
	ivMust(t, err)
	if c.Name != "prd" || c.CredentialID != cfg.CredentialID || !c.ExecEnabled || len(c.Filter.NSExclude) != 1 ||
		c.Filter.NSInclude == nil || c.LastSync != nil {
		t.Fatalf("created: %+v", c)
	}
	if _, err := db.CreateCluster(ctx, cfg); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate name: %v", err)
	}
	if _, err := db.CreateCluster(ctx, store.K8sClusterConfig{Name: "x", Connection: "magic"}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("bad connection: %v", err)
	}
	cfg.Name, cfg.Connection, cfg.CredentialID, cfg.ExecEnabled = "dev", store.K8sInCluster, "", false
	u, err := db.UpdateCluster(ctx, c.ID, cfg)
	ivMust(t, err)
	if u.Name != "dev" || u.CredentialID != "" || u.ExecEnabled {
		t.Fatalf("updated: %+v", u)
	}
	_, err = db.CreateCluster(ctx, store.K8sClusterConfig{Name: "stg", Connection: store.K8sInCluster})
	ivMust(t, err)
	list, total, err := db.ListClusters(ctx, store.ClusterFilter{Sort: "-name"}, store.Page{Limit: 1})
	ivMust(t, err)
	if total != 2 || len(list) != 1 || list[0].Name != "stg" {
		t.Fatalf("list: %+v", list)
	}
	ivMust(t, db.DeleteCluster(ctx, c.ID))
	if _, err := db.GetCluster(ctx, c.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
	if err := db.DeleteCluster(ctx, c.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
}

func TestReplaceClusterInventory(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	c, err := db.CreateCluster(ctx, store.K8sClusterConfig{Name: "prd", Connection: store.K8sInCluster})
	ivMust(t, err)
	t1, t2 := ivT0, ivT0.Add(time.Hour)
	pod := func(name, phase, digest string, started time.Time) store.K8sPodObservation {
		return store.K8sPodObservation{Name: name, Node: "node-1", Phase: phase, StartedAt: started, Containers: []store.K8sPodContainerObservation{
			{Name: "api", ImageRef: "registry/api:" + digest, ImageDigest: "sha256:" + digest},
			{Name: "envoy", ImageRef: "envoy:1.29", ImageDigest: "sha256:e1"},
		}}
	}
	inv := store.K8sInventory{Version: "v1.30.2", At: t1, Workloads: []store.K8sWorkloadObservation{
		{Namespace: "shop", Kind: "Deployment", Name: "api", Replicas: 2, Pods: []store.K8sPodObservation{
			pod("api-a", "Running", "v1", t1), pod("api-b", "Running", "v1", t1),
		}},
		{Namespace: "kube-system", Kind: "DaemonSet", Name: "proxy", Replicas: 3, Excluded: true, ExcludedBy: "namespace kube-*"},
		{Namespace: "shop", Kind: "CronJob", Name: "report", Replicas: 0},
	}}
	res, err := db.ReplaceClusterInventory(ctx, c.ID, inv)
	ivMust(t, err)
	if len(res.Workloads) != 3 {
		t.Fatalf("workloads: %+v", res.Workloads)
	}
	var apiRef store.K8sWorkloadRef
	for _, w := range res.Workloads {
		if w.Excluded != (w.AssetID == "") {
			t.Fatalf("asset link: %+v", w)
		}
		if w.Name == "api" {
			apiRef = w
		}
	}
	if !apiRef.AssetCreated {
		t.Fatalf("api ref: %+v", apiRef)
	}

	a, err := db.GetAsset(ctx, apiRef.AssetID)
	ivMust(t, err)
	if a.Kind != store.AssetWorkload || a.Location() != "prd / shop" || a.WorkloadKind != "Deployment" || len(a.Containers) != 2 {
		t.Fatalf("workload asset: %+v", a)
	}
	if a.Containers[0].Name != "api" || a.Containers[0].Instances != 2 || a.Containers[0].ImageDigest != "sha256:v1" ||
		a.Containers[0].Runtime != store.RuntimeKubernetes {
		t.Fatalf("derived container: %+v", a.Containers[0])
	}

	ivMust(t, db.SetPodContainerCoverage(ctx, c.ID, "shop", "api-a", "api", store.CoverageFull, ""))

	wl, total, err := db.ListWorkloads(ctx, c.ID, store.WorkloadFilter{Namespace: "shop", Sort: "name"}, store.Page{})
	ivMust(t, err)
	if total != 2 || wl[0].Name != "api" || wl[0].Pods != 2 || len(wl[0].Coverages) != 2 {
		t.Fatalf("workloads list: %+v", wl)
	}
	excl := true
	_, total, err = db.ListWorkloads(ctx, c.ID, store.WorkloadFilter{Excluded: &excl}, store.Page{})
	ivMust(t, err)
	if total != 1 {
		t.Fatalf("excluded: %d", total)
	}
	cl, _, err := db.ListClusters(ctx, store.ClusterFilter{}, store.Page{})
	ivMust(t, err)
	if cl[0].Workloads != 3 || cl[0].Excluded != 1 || cl[0].Version != "v1.30.2" || cl[0].LastSync == nil {
		t.Fatalf("cluster row: %+v", cl[0])
	}

	pods, total, err := db.ListWorkloadPods(ctx, apiRef.ID, store.PodFilter{Sort: "-name"}, store.Page{Limit: 1})
	ivMust(t, err)
	if total != 2 || pods[0].Name != "api-b" || len(pods[0].Containers) != 2 {
		t.Fatalf("pods: %+v", pods)
	}

	// Rollout: api-a replaced by api-c with a new image; report disappears.
	inv2 := store.K8sInventory{At: t2, Workloads: []store.K8sWorkloadObservation{
		{Namespace: "shop", Kind: "Deployment", Name: "api", Replicas: 2, Pods: []store.K8sPodObservation{
			pod("api-b", "Running", "v1", t1), pod("api-c", "Running", "v2", t2),
		}},
		{Namespace: "kube-system", Kind: "DaemonSet", Name: "proxy", Replicas: 3, Excluded: true},
	}}
	res, err = db.ReplaceClusterInventory(ctx, c.ID, inv2)
	ivMust(t, err)
	if res.GoneWorkloads != 1 || len(res.Workloads) != 2 {
		t.Fatalf("second sync: %+v", res)
	}
	for _, w := range res.Workloads {
		if w.Name == "api" && (w.AssetID != apiRef.AssetID || w.AssetCreated) {
			t.Fatalf("asset not kept: %+v", w)
		}
	}
	inst, total, err := db.ListAssetInstances(ctx, apiRef.AssetID, store.PodFilter{}, store.Page{})
	ivMust(t, err)
	if total != 2 || inst[0].Name != "api-b" || inst[1].Name != "api-c" {
		t.Fatalf("instances: %+v", inst)
	}
	_, total, err = db.ListAssetInstances(ctx, apiRef.AssetID, store.PodFilter{IncludeGone: true, Q: "api-a"}, store.Page{})
	ivMust(t, err)
	if total != 1 {
		t.Fatalf("gone pod history: %d", total)
	}
	a, err = db.GetAsset(ctx, apiRef.AssetID)
	ivMust(t, err)
	if a.Containers[0].ImageDigest != "sha256:v2" || a.Containers[0].PreviousDigest != "sha256:v1" {
		t.Fatalf("rollout container: %+v", a.Containers[0])
	}
	assets, total, err := db.ListAssets(ctx, store.AssetFilter{ClusterID: c.ID}, store.Page{})
	ivMust(t, err)
	if total != 1 || assets[0].ID != apiRef.AssetID {
		t.Fatalf("current workload assets: %+v", assets)
	}
	_, total, err = db.ListAssets(ctx, store.AssetFilter{ClusterID: c.ID, IncludeGone: true}, store.Page{})
	ivMust(t, err)
	if total != 2 {
		t.Fatalf("with gone: %d", total)
	}

	// UpsertWorkloadAsset finds the asset the sync created.
	ref, err := db.UpsertWorkloadAsset(ctx, store.WorkloadIdentity{ClusterID: c.ID, Namespace: "shop", Kind: "Deployment", Name: "api"},
		store.AssetInit{Method: store.CollectK8sExec})
	ivMust(t, err)
	if ref.Created || ref.ID != apiRef.AssetID {
		t.Fatalf("workload upsert: %+v", ref)
	}

	// Purge removes what has been gone for long enough.
	pr, err := db.PurgeGone(ctx, t2.Add(time.Second))
	ivMust(t, err)
	if pr.Assets != 1 || pr.Workloads != 1 || pr.Pods != 1 {
		t.Fatalf("purge: %+v", pr)
	}

	ivMust(t, db.DeleteCluster(ctx, c.ID))
	if n := ivCount(t, db, `SELECT count(*) FROM assets`); n != 0 {
		t.Fatalf("assets after cluster delete: %d", n)
	}
}
