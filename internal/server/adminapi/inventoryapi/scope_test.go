// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package inventoryapi

import (
	"net/http"
	"testing"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/server/scope"
)

// TestDataScopes runs handlers in a scope that holds none of the fixture
// (all of it is in the default scope).
func TestDataScopes(t *testing.T) {
	f := seed(t)
	h := f.h
	other := scope.With(f.ctx, scope.Of("other"))

	_, err := h.GetAsset(other, gen.GetAssetRequestObject{Id: f.web})
	wantStatus(t, "asset of another scope", err, http.StatusNotFound)
	_, err = h.GetK8sCluster(other, gen.GetK8sClusterRequestObject{Id: f.cluster})
	wantStatus(t, "cluster of another scope", err, http.StatusNotFound)
	ap, err := h.ListAssetProcesses(f.ctx, gen.ListAssetProcessesRequestObject{Id: f.web})
	must(t, err)
	_, err = h.GetAssetProcess(other, gen.GetAssetProcessRequestObject{Id: f.web,
		ProcessId: ap.(gen.ListAssetProcesses200JSONResponse).Items[0].Id})
	wantStatus(t, "process of another scope", err, http.StatusNotFound)
	r, err := h.ListAssets(other, gen.ListAssetsRequestObject{})
	must(t, err)
	if l := r.(gen.ListAssets200JSONResponse); l.Total != 0 {
		t.Fatalf("another scope lists %d assets", l.Total)
	}

	// Creating outside the request's scope is forbidden; the kubeconfig of
	// another scope cannot be used.
	_, err = h.CreateK8sCluster(other, gen.CreateK8sClusterRequestObject{Body: &gen.K8sClusterCreate{
		Name: "x", Connection: gen.K8sConnectionInCluster, ScannerId: &f.scanner, ScopeId: ptr(scope.Default)}})
	wantStatus(t, "cluster in a scope outside the request", err, http.StatusForbidden)
	_, err = h.CreateK8sCluster(f.ctx, gen.CreateK8sClusterRequestObject{Body: &gen.K8sClusterCreate{
		Name: "x", Connection: gen.K8sConnectionKubeconfig, CredentialId: &f.kubecfg, ScopeId: ptr("other")}})
	wantStatus(t, "credential of another scope", err, http.StatusForbidden)

	// The default scope sees the fixture; the cluster created there shows
	// its scope.
	c, err := h.CreateK8sCluster(scope.With(f.ctx, scope.Of(scope.Default)), gen.CreateK8sClusterRequestObject{
		Body: &gen.K8sClusterCreate{Name: "y", Connection: gen.K8sConnectionInCluster, ScannerId: &f.scanner}})
	must(t, err)
	if got := c.(gen.CreateK8sCluster201JSONResponse).ScopeId; got != scope.Default {
		t.Fatalf("cluster scope %q", got)
	}
	d, err := h.GetAsset(scope.With(f.ctx, scope.Of(scope.Default)), gen.GetAssetRequestObject{Id: f.web})
	must(t, err)
	if got := d.(gen.GetAsset200JSONResponse).ScopeId; got != scope.Default {
		t.Fatalf("asset scope %q", got)
	}
}
