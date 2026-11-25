// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package inventoryapi

import (
	"context"
	"errors"
	"time"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/apierr"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// requireAsset turns a missing asset into a 404. List methods of the store
// return an empty list for an unknown parent, so handlers call this when a
// list is empty.
func (h *Handlers) requireAsset(ctx context.Context, id string) error {
	_, err := h.cfg.Store.GetAsset(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return apierr.NotFound("asset")
	}
	return err
}

// ListAssets implements gen.StrictServerInterface.
func (h *Handlers) ListAssets(ctx context.Context, req gen.ListAssetsRequestObject) (gen.ListAssetsResponseObject, error) {
	prm := req.Params
	p, err := page(prm.Limit, prm.Offset)
	if err != nil {
		return nil, err
	}
	var f store.AssetFilter
	if prm.Tag != nil {
		f.Tag = *prm.Tag
	}
	if f.Q, err = query(prm.Q); err != nil {
		return nil, err
	}
	kind, err := enum("kind", prm.Kind)
	if err != nil {
		return nil, err
	}
	method, err := enum("method", prm.Method)
	if err != nil {
		return nil, err
	}
	coverage, err := enum("coverage", prm.Coverage)
	if err != nil {
		return nil, err
	}
	f.Kind, f.Method, f.Coverage = store.AssetKind(kind), store.CollectMethod(method), store.Coverage(coverage)
	if prm.Group != nil {
		f.Group = *prm.Group
	}
	if prm.ClusterId != nil {
		f.ClusterID = *prm.ClusterId
	}
	if prm.ScopeId != nil {
		f.ScopeID = *prm.ScopeId
	}
	if f.Sort, err = sortKey(prm.Sort, map[string]string{
		"name": "name", "kind": "kind", "os": "os", "group": "group", "method": "method",
		"coverage": "coverage", "firstSeen": "first_seen", "lastSeen": "last_seen",
	}); err != nil {
		return nil, err
	}
	rows, total, err := h.cfg.Store.ListAssets(ctx, f, p)
	if err != nil {
		return nil, err
	}
	out := gen.ListAssets200JSONResponse{Items: make([]gen.AssetSummary, 0, len(rows)), Total: total}
	for _, r := range rows {
		out.Items = append(out.Items, rowSummary(r))
	}
	return out, nil
}

// ListAssetGroups implements gen.StrictServerInterface.
func (h *Handlers) ListAssetGroups(ctx context.Context, req gen.ListAssetGroupsRequestObject) (gen.ListAssetGroupsResponseObject, error) {
	prm := req.Params
	p, err := page(prm.Limit, prm.Offset)
	if err != nil {
		return nil, err
	}
	var f store.AssetGroupFilter
	if f.Q, err = query(prm.Q); err != nil {
		return nil, err
	}
	if f.Sort, err = sortKey(prm.Sort, map[string]string{"name": "name", "assetCount": "assets"}); err != nil {
		return nil, err
	}
	rows, total, err := h.cfg.Store.ListAssetGroups(ctx, f, p)
	if err != nil {
		return nil, err
	}
	out := gen.ListAssetGroups200JSONResponse{Items: make([]gen.AssetGroup, 0, len(rows)), Total: total}
	for _, r := range rows {
		out.Items = append(out.Items, gen.AssetGroup{Name: r.Name, AssetCount: r.Assets})
	}
	return out, nil
}

// GetAsset implements gen.StrictServerInterface. Only current containers
// are listed; the API has no field for gone ones.
func (h *Handlers) GetAsset(ctx context.Context, req gen.GetAssetRequestObject) (gen.GetAssetResponseObject, error) {
	a, err := h.cfg.Store.GetAsset(ctx, req.Id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, apierr.NotFound("asset")
	}
	if err != nil {
		return nil, err
	}
	s := assetSummary(a.Asset, 0)
	out := gen.GetAsset200JSONResponse{
		Id: s.Id, ScopeId: s.ScopeId, Name: s.Name, Kind: s.Kind, Group: s.Group, Tags: s.Tags, Os: s.Os, Address: s.Address,
		Method: s.Method, Coverage: s.Coverage, CoverageReason: s.CoverageReason, Privilege: s.Privilege,
		AgentId: s.AgentId, ScanTargetId: s.ScanTargetId, ClusterId: s.ClusterId, ClusterName: s.ClusterName,
		Namespace: s.Namespace, WorkloadKind: s.WorkloadKind, CollectRequestedAt: s.CollectRequestedAt,
		FirstSeen: s.FirstSeen, LastSeen: s.LastSeen,
		Sections:   []gen.SectionCoverage{},
		Containers: []gen.AssetContainer{},
	}
	for _, sec := range a.Sections {
		if sec.Container != "" {
			continue
		}
		out.Sections = append(out.Sections, gen.SectionCoverage{
			Section:     gen.SectionName(sec.Section),
			Coverage:    gen.SectionCoverageLevel(sec.Coverage),
			Reason:      str(sec.Reason),
			CollectedAt: timePtr(sec.CollectedAt),
		})
	}
	for _, c := range a.Containers {
		if c.GoneAt == nil {
			out.Containers = append(out.Containers, assetContainer(c))
		}
	}
	if a.WorkloadID != "" {
		out.WorkloadId, out.Replicas = ptr(a.WorkloadID), ptr(a.Replicas)
	}
	return out, nil
}

// ListAssetComponents implements gen.StrictServerInterface.
func (h *Handlers) ListAssetComponents(ctx context.Context, req gen.ListAssetComponentsRequestObject) (gen.ListAssetComponentsResponseObject, error) {
	prm := req.Params
	p, err := page(prm.Limit, prm.Offset)
	if err != nil {
		return nil, err
	}
	var f store.AssetComponentFilter
	if f.Q, err = query(prm.Q); err != nil {
		return nil, err
	}
	if f.Type, err = enum("type", prm.Type); err != nil {
		return nil, err
	}
	origin, err := enum("origin", prm.Origin)
	if err != nil {
		return nil, err
	}
	f.Origin = store.ComponentOrigin(origin)
	hostOnly := prm.HostOnly != nil && *prm.HostOnly
	switch {
	case hostOnly && prm.Container != nil && *prm.Container != "":
		return nil, apierr.Invalid("container and hostOnly cannot be combined")
	case hostOnly:
		f.Container = ptr("")
	case prm.Container != nil && *prm.Container != "":
		f.Container = ptr(*prm.Container)
	}
	if f.Layer, err = enum("layer", prm.Layer); err != nil {
		return nil, err
	}
	f.InUse = prm.InUse
	f.IncludeRemoved = prm.IncludeRemoved != nil && *prm.IncludeRemoved
	if f.Sort, err = sortKey(prm.Sort, map[string]string{
		"name": "name", "version": "version", "type": "type", "origin": "origin", "method": "method",
		"container": "container", "inUse": "in_use", "firstSeen": "first_seen",
	}); err != nil {
		return nil, err
	}
	rows, total, err := h.cfg.Store.ListAssetComponents(ctx, req.Id, f, p)
	if err != nil {
		return nil, err
	}
	if total == 0 {
		if err := h.requireAsset(ctx, req.Id); err != nil {
			return nil, err
		}
	}
	out := gen.ListAssetComponents200JSONResponse{Items: make([]gen.AssetComponentRow, 0, len(rows)), Total: total}
	for _, r := range rows {
		out.Items = append(out.Items, gen.AssetComponentRow{
			AssetId:        req.Id,
			ComponentId:    r.Component.ID,
			Component:      softwareComponent(r.Component),
			Container:      str(r.Container),
			Layer:          layer(r.Layer),
			Locations:      strs(r.Locations),
			InUse:          r.InUse,
			Method:         gen.DetectMethod(r.Method),
			VersionCommand: str(r.VersionCommand),
			VersionRaw:     str(r.VersionRaw),
			FirstSeen:      r.FirstSeen,
			RemovedAt:      r.RemovedAt,
		})
	}
	return out, nil
}

// ListAssetProcesses implements gen.StrictServerInterface.
func (h *Handlers) ListAssetProcesses(ctx context.Context, req gen.ListAssetProcessesRequestObject) (gen.ListAssetProcessesResponseObject, error) {
	prm := req.Params
	p, err := page(prm.Limit, prm.Offset)
	if err != nil {
		return nil, err
	}
	f := store.ProcessFilter{AssetID: req.Id}
	if f.Q, err = query(prm.Q); err != nil {
		return nil, err
	}
	if f.View, err = enum("view", prm.View); err != nil {
		return nil, err
	}
	if prm.Container != nil && *prm.Container != "" {
		f.Container = ptr(*prm.Container)
	}
	if f.Sort, err = sortKey(prm.Sort, map[string]string{
		"pid": "pid", "user": "user", "exe": "exe", "state": "state", "startedAt": "started_at",
	}); err != nil {
		return nil, err
	}
	if f.Sort == "" {
		f.Sort = "pid"
	}
	rows, total, err := h.cfg.Store.ListProcesses(ctx, f, p)
	if err != nil {
		return nil, err
	}
	if total == 0 {
		if err := h.requireAsset(ctx, req.Id); err != nil {
			return nil, err
		}
	}
	return gen.ListAssetProcesses200JSONResponse(processList(rows, total)), nil
}

func processList(rows []store.ProcessRow, total int) gen.ProcessList {
	out := gen.ProcessList{Items: make([]gen.ProcessInfo, 0, len(rows)), Total: total}
	for _, r := range rows {
		out.Items = append(out.Items, processInfo(r))
	}
	return out
}

// ListAssetInstances implements gen.StrictServerInterface.
func (h *Handlers) ListAssetInstances(ctx context.Context, req gen.ListAssetInstancesRequestObject) (gen.ListAssetInstancesResponseObject, error) {
	prm := req.Params
	p, err := page(prm.Limit, prm.Offset)
	if err != nil {
		return nil, err
	}
	f, err := podFilter(prm.Q, prm.Phase, prm.Sort)
	if err != nil {
		return nil, err
	}
	rows, total, err := h.cfg.Store.ListAssetInstances(ctx, req.Id, f, p)
	if err != nil {
		return nil, err
	}
	if total == 0 {
		if err := h.requireAsset(ctx, req.Id); err != nil {
			return nil, err
		}
	}
	return gen.ListAssetInstances200JSONResponse(k8sPods(rows, total)), nil
}

// CollectAsset implements gen.StrictServerInterface.
func (h *Handlers) CollectAsset(ctx context.Context, req gen.CollectAssetRequestObject) (gen.CollectAssetResponseObject, error) {
	if err := h.requireAsset(ctx, req.Id); err != nil {
		return nil, err
	}
	if err := h.cfg.Collector.RequestCollect(ctx, req.Id); err != nil {
		if errors.Is(err, store.ErrInvalidState) {
			return nil, apierr.Conflict("the asset cannot be collected now").Wrap(err)
		}
		return nil, err
	}
	at := h.cfg.Now().UTC().Truncate(time.Microsecond)
	if err := h.cfg.Store.MarkCollectRequested(ctx, req.Id, at); err != nil {
		return nil, err
	}
	h.logChange(ctx, "collection requested", "asset", req.Id)
	return gen.CollectAsset202JSONResponse{RequestedAt: at}, nil
}
