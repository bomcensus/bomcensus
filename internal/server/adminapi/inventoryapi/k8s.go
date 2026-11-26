// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package inventoryapi

import (
	"context"
	"errors"
	"path"
	"strings"

	"github.com/oapi-codegen/nullable"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/apierr"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// Limits on cluster configuration values.
const (
	maxClusterName   = 200
	maxFilterEntries = 100
	maxFilterEntry   = 512
)

func (h *Handlers) getCluster(ctx context.Context, id string) (store.K8sCluster, error) {
	c, err := h.cfg.Store.GetCluster(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return c, apierr.NotFound("cluster")
	}
	return c, err
}

// ListK8sClusters implements gen.StrictServerInterface.
func (h *Handlers) ListK8sClusters(ctx context.Context, req gen.ListK8sClustersRequestObject) (gen.ListK8sClustersResponseObject, error) {
	prm := req.Params
	p, err := page(prm.Limit, prm.Offset)
	if err != nil {
		return nil, err
	}
	var f store.ClusterFilter
	if f.Q, err = query(prm.Q); err != nil {
		return nil, err
	}
	f.ScopeID = deref(prm.ScopeId)
	if f.Sort, err = sortKey(prm.Sort, map[string]string{
		"name": "name", "version": "version", "connection": "connection", "execEnabled": "exec_enabled",
		"workloadCount": "workloads", "lastSync": "last_sync",
	}); err != nil {
		return nil, err
	}
	rows, total, err := h.cfg.Store.ListClusters(ctx, f, p)
	if err != nil {
		return nil, err
	}
	out := gen.ListK8sClusters200JSONResponse{Items: make([]gen.K8sCluster, 0, len(rows)), Total: total}
	for _, r := range rows {
		out.Items = append(out.Items, k8sCluster(r.K8sCluster))
	}
	return out, nil
}

// CreateK8sCluster implements gen.StrictServerInterface.
func (h *Handlers) CreateK8sCluster(ctx context.Context, req gen.CreateK8sClusterRequestObject) (gen.CreateK8sClusterResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, apierr.Invalid("body is required")
	}
	cfg := store.K8sClusterConfig{
		Name:        b.Name,
		Connection:  store.K8sConnection(b.Connection),
		ExecEnabled: b.ExecEnabled != nil && *b.ExecEnabled,
	}
	if b.CredentialId != nil {
		cfg.CredentialID = *b.CredentialId
	}
	if b.ScannerId != nil {
		cfg.ScannerID = *b.ScannerId
	}
	if b.Filter != nil {
		cfg.Filter = k8sFilterIn(*b.Filter)
	}
	scopeID, err := newScopeID(ctx, b.ScopeId)
	if err != nil {
		return nil, err
	}
	cfg.ScopeID = scopeID
	cfg, err = h.validateCluster(ctx, cfg)
	if err != nil {
		return nil, err
	}
	c, err := h.cfg.Store.CreateCluster(ctx, cfg)
	if errors.Is(err, store.ErrConflict) {
		return nil, apierr.Conflict("a cluster with this name exists")
	}
	if err != nil {
		return nil, err
	}
	h.logChange(ctx, "cluster created", "cluster", c.ID, "name", c.Name)
	return gen.CreateK8sCluster201JSONResponse(k8sCluster(c)), nil
}

// GetK8sCluster implements gen.StrictServerInterface.
func (h *Handlers) GetK8sCluster(ctx context.Context, req gen.GetK8sClusterRequestObject) (gen.GetK8sClusterResponseObject, error) {
	c, err := h.getCluster(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return gen.GetK8sCluster200JSONResponse(k8sCluster(c)), nil
}

// UpdateK8sCluster implements gen.StrictServerInterface. Absent fields are
// kept; null or an empty credentialId or scannerId clears the reference.
// Switching to in_cluster without a credentialId clears the credential.
func (h *Handlers) UpdateK8sCluster(ctx context.Context, req gen.UpdateK8sClusterRequestObject) (gen.UpdateK8sClusterResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, apierr.Invalid("body is required")
	}
	cur, err := h.getCluster(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	cfg := cur.K8sClusterConfig
	if b.Name != nil {
		cfg.Name = *b.Name
	}
	if b.Connection != nil {
		cfg.Connection = store.K8sConnection(*b.Connection)
		if cfg.Connection == store.K8sInCluster && !b.CredentialId.IsSpecified() {
			cfg.CredentialID = ""
		}
	}
	if v, ok := patchString(b.CredentialId); ok {
		cfg.CredentialID = v
	}
	if v, ok := patchString(b.ScannerId); ok {
		cfg.ScannerID = v
	}
	if b.ExecEnabled != nil {
		cfg.ExecEnabled = *b.ExecEnabled
	}
	if b.Filter != nil {
		cfg.Filter = k8sFilterIn(*b.Filter)
	}
	if cfg, err = h.validateCluster(ctx, cfg); err != nil {
		return nil, err
	}
	c, err := h.cfg.Store.UpdateCluster(ctx, req.Id, cfg)
	switch {
	case errors.Is(err, store.ErrConflict):
		return nil, apierr.Conflict("a cluster with this name exists")
	case errors.Is(err, store.ErrNotFound):
		return nil, apierr.NotFound("cluster")
	case err != nil:
		return nil, err
	}
	h.logChange(ctx, "cluster updated", "cluster", c.ID, "name", c.Name)
	return gen.UpdateK8sCluster200JSONResponse(k8sCluster(c)), nil
}

// patchString reads a nullable PATCH field: ok is false when it is absent;
// null gives "".
func patchString(v nullable.Nullable[string]) (string, bool) {
	if !v.IsSpecified() {
		return "", false
	}
	if v.IsNull() {
		return "", true
	}
	return v.MustGet(), true
}

// DeleteK8sCluster implements gen.StrictServerInterface.
func (h *Handlers) DeleteK8sCluster(ctx context.Context, req gen.DeleteK8sClusterRequestObject) (gen.DeleteK8sClusterResponseObject, error) {
	err := h.cfg.Store.DeleteCluster(ctx, req.Id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, apierr.NotFound("cluster")
	}
	if err != nil {
		return nil, err
	}
	h.logChange(ctx, "cluster deleted", "cluster", req.Id)
	return gen.DeleteK8sCluster204Response{}, nil
}

// ListK8sWorkloads implements gen.StrictServerInterface.
func (h *Handlers) ListK8sWorkloads(ctx context.Context, req gen.ListK8sWorkloadsRequestObject) (gen.ListK8sWorkloadsResponseObject, error) {
	prm := req.Params
	p, err := page(prm.Limit, prm.Offset)
	if err != nil {
		return nil, err
	}
	f := store.WorkloadFilter{Excluded: prm.Excluded}
	if f.Q, err = query(prm.Q); err != nil {
		return nil, err
	}
	if prm.Namespace != nil {
		f.Namespace = *prm.Namespace
	}
	if prm.Kind != nil {
		f.Kind = *prm.Kind
	}
	if f.Sort, err = sortKey(prm.Sort, map[string]string{
		"namespace": "namespace", "kind": "kind", "name": "name", "replicas": "replicas",
	}); err != nil {
		return nil, err
	}
	rows, total, err := h.cfg.Store.ListWorkloads(ctx, req.Id, f, p)
	if err != nil {
		return nil, err
	}
	if total == 0 {
		if _, err := h.getCluster(ctx, req.Id); err != nil {
			return nil, err
		}
	}
	out := gen.ListK8sWorkloads200JSONResponse{Items: make([]gen.K8sWorkload, 0, len(rows)), Total: total}
	for _, r := range rows {
		covs := make([]gen.Coverage, 0, len(r.Coverages))
		for _, c := range r.Coverages {
			covs = append(covs, gen.Coverage(c))
		}
		out.Items = append(out.Items, gen.K8sWorkload{
			Id:         r.ID,
			ClusterId:  r.ClusterID,
			Namespace:  r.Namespace,
			Kind:       r.Kind,
			Name:       r.Name,
			Replicas:   r.Replicas,
			AssetId:    str(r.AssetID),
			Excluded:   r.Excluded,
			ExcludedBy: str(r.ExcludedBy),
			Coverages:  covs,
		})
	}
	return out, nil
}

// ListK8sNamespaces implements gen.StrictServerInterface.
func (h *Handlers) ListK8sNamespaces(ctx context.Context, req gen.ListK8sNamespacesRequestObject) (gen.ListK8sNamespacesResponseObject, error) {
	rows, err := h.cfg.Store.ListWorkloadNamespaces(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		if _, err := h.getCluster(ctx, req.Id); err != nil {
			return nil, err
		}
	}
	out := gen.ListK8sNamespaces200JSONResponse{Items: make([]gen.K8sNamespace, 0, len(rows)), Total: len(rows)}
	for _, r := range rows {
		out.Items = append(out.Items, gen.K8sNamespace{Name: r.Name, WorkloadCount: r.Workloads})
	}
	return out, nil
}

// ListK8sWorkloadPods implements gen.StrictServerInterface.
func (h *Handlers) ListK8sWorkloadPods(ctx context.Context, req gen.ListK8sWorkloadPodsRequestObject) (gen.ListK8sWorkloadPodsResponseObject, error) {
	prm := req.Params
	p, err := page(prm.Limit, prm.Offset)
	if err != nil {
		return nil, err
	}
	f, err := podFilter(prm.Q, prm.Phase, prm.Sort)
	if err != nil {
		return nil, err
	}
	rows, total, err := h.cfg.Store.ListWorkloadPods(ctx, req.Id, f, p)
	if err != nil {
		return nil, err
	}
	if total == 0 {
		if _, err := h.cfg.Store.GetWorkload(ctx, req.Id); errors.Is(err, store.ErrNotFound) {
			return nil, apierr.NotFound("workload")
		} else if err != nil {
			return nil, err
		}
	}
	return gen.ListK8sWorkloadPods200JSONResponse(k8sPods(rows, total)), nil
}

// SyncK8sCluster implements gen.StrictServerInterface.
func (h *Handlers) SyncK8sCluster(ctx context.Context, req gen.SyncK8sClusterRequestObject) (gen.SyncK8sClusterResponseObject, error) {
	if _, err := h.getCluster(ctx, req.Id); err != nil {
		return nil, err
	}
	if err := h.cfg.Syncer.RequestSync(ctx, req.Id); err != nil {
		if errors.Is(err, store.ErrInvalidState) {
			return nil, apierr.Conflict("the cluster cannot be synced now").Wrap(err)
		}
		return nil, err
	}
	h.logChange(ctx, "cluster sync requested", "cluster", req.Id)
	return gen.SyncK8sCluster202Response{}, nil
}

// validateCluster checks a configuration as documented on K8sClusterCreate
// and returns it normalized.
func (h *Handlers) validateCluster(ctx context.Context, c store.K8sClusterConfig) (store.K8sClusterConfig, error) {
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" || len(c.Name) > maxClusterName {
		return c, apierr.Invalid("name must be 1 to %d characters", maxClusterName)
	}
	switch c.Connection {
	case store.K8sKubeconfig:
		if c.CredentialID == "" {
			return c, apierr.Invalid("connection kubeconfig requires credentialId")
		}
		switch err := h.cfg.Credentials.CheckKubeconfig(ctx, c.CredentialID); {
		case errors.Is(err, ErrCredentialNotFound):
			return c, apierr.Invalid("credential not found")
		case errors.Is(err, ErrNotKubeconfig):
			return c, apierr.Invalid("credential is not a kubeconfig")
		case err != nil:
			return c, err
		}
	case store.K8sInCluster:
		if c.ScannerID == "" {
			return c, apierr.Invalid("connection in_cluster requires scannerId")
		}
		if c.CredentialID != "" {
			return c, apierr.Invalid("connection in_cluster takes no credentialId")
		}
	default:
		return c, apierr.Invalid("unknown connection %q", string(c.Connection))
	}
	if c.ScannerID != "" {
		a, err := h.cfg.Agents.GetAgent(ctx, c.ScannerID)
		switch {
		case errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrInvalid):
			return c, apierr.Invalid("scanner not found")
		case err != nil:
			return c, err
		case a.Kind != store.AgentKindScanner:
			return c, apierr.Invalid("scannerId is not a scanner")
		case a.State == store.AgentRevoked:
			return c, apierr.Invalid("scanner is revoked")
		}
	}
	f := &c.Filter
	for _, l := range []struct {
		name string
		vals *[]string
		glob bool
	}{
		{"nsInclude", &f.NSInclude, true}, {"nsExclude", &f.NSExclude, true},
		{"labelInclude", &f.LabelInclude, false}, {"labelExclude", &f.LabelExclude, false},
		{"annotationInclude", &f.AnnotationInclude, false}, {"annotationExclude", &f.AnnotationExclude, false},
	} {
		*l.vals = strs(*l.vals)
		if len(*l.vals) > maxFilterEntries {
			return c, apierr.Invalid("filter.%s has more than %d entries", l.name, maxFilterEntries)
		}
		for i, v := range *l.vals {
			v = strings.TrimSpace(v)
			(*l.vals)[i] = v
			if v == "" || len(v) > maxFilterEntry {
				return c, apierr.Invalid("filter.%s entries must be 1 to %d characters", l.name, maxFilterEntry)
			}
			if l.glob {
				if _, err := path.Match(v, ""); err != nil {
					return c, apierr.Invalid("filter.%s: invalid pattern %q", l.name, v)
				}
			}
		}
	}
	return c, nil
}
