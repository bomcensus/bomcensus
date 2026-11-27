// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package inventoryapi

import (
	"context"
	"errors"
	"regexp"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/apierr"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// ListComponents implements gen.StrictServerInterface.
func (h *Handlers) ListComponents(ctx context.Context, req gen.ListComponentsRequestObject) (gen.ListComponentsResponseObject, error) {
	prm := req.Params
	p, err := page(prm.Limit, prm.Offset)
	if err != nil {
		return nil, err
	}
	var f store.ComponentFilter
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
	f.InstalledOnly = prm.Installed != nil && *prm.Installed
	f.RunningOnly = prm.Running != nil && *prm.Running
	if f.Sort, err = sortKey(prm.Sort, map[string]string{
		"name": "name", "version": "version", "type": "type", "origin": "origin",
		"assetCount": "assets", "runningAssetCount": "running", "purl": "purl",
	}); err != nil {
		return nil, err
	}
	rows, total, err := h.cfg.Store.ListComponents(ctx, f, p)
	if err != nil {
		return nil, err
	}
	out := gen.ListComponents200JSONResponse{Items: make([]gen.ComponentSummary, 0, len(rows)), Total: total}
	for _, r := range rows {
		out.Items = append(out.Items, componentSummary(r))
	}
	return out, nil
}

// GetComponent implements gen.StrictServerInterface.
func (h *Handlers) GetComponent(ctx context.Context, req gen.GetComponentRequestObject) (gen.GetComponentResponseObject, error) {
	r, err := h.cfg.Store.GetComponent(ctx, req.Id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, apierr.NotFound("component")
	}
	if err != nil {
		return nil, err
	}
	return gen.GetComponent200JSONResponse(componentSummary(r)), nil
}

// ListComponentAssets implements gen.StrictServerInterface.
func (h *Handlers) ListComponentAssets(ctx context.Context, req gen.ListComponentAssetsRequestObject) (gen.ListComponentAssetsResponseObject, error) {
	prm := req.Params
	p, err := page(prm.Limit, prm.Offset)
	if err != nil {
		return nil, err
	}
	f := store.ComponentAssetFilter{
		InUse:          prm.InUse,
		IncludeRemoved: prm.IncludeRemoved != nil && *prm.IncludeRemoved,
	}
	if f.Method, err = enum("method", prm.Method); err != nil {
		return nil, err
	}
	if f.Q, err = query(prm.Q); err != nil {
		return nil, err
	}
	if f.Sort, err = sortKey(prm.Sort, map[string]string{
		"asset": "asset", "method": "method", "inUse": "in_use", "firstSeen": "first_seen",
	}); err != nil {
		return nil, err
	}
	rows, total, err := h.cfg.Store.ListComponentAssets(ctx, req.Id, f, p)
	if err != nil {
		return nil, err
	}
	if total == 0 {
		if _, err := h.GetComponent(ctx, gen.GetComponentRequestObject{Id: req.Id}); err != nil {
			return nil, err
		}
	}
	out := gen.ListComponentAssets200JSONResponse{Items: make([]gen.ComponentAssetRow, 0, len(rows)), Total: total}
	for _, r := range rows {
		out.Items = append(out.Items, gen.ComponentAssetRow{
			AssetId:        r.Asset.ID,
			ComponentId:    req.Id,
			Asset:          rowSummary(r.Asset),
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

// ListProcesses implements gen.StrictServerInterface.
func (h *Handlers) ListProcesses(ctx context.Context, req gen.ListProcessesRequestObject) (gen.ListProcessesResponseObject, error) {
	prm := req.Params
	p, err := page(prm.Limit, prm.Offset)
	if err != nil {
		return nil, err
	}
	var f store.ProcessFilter
	if f.Q, err = query(prm.Q); err != nil {
		return nil, err
	}
	if f.View, err = enum("view", prm.View); err != nil {
		return nil, err
	}
	if f.ExeState, err = enum("state", prm.State); err != nil {
		return nil, err
	}
	if prm.AssetId != nil {
		f.AssetID = *prm.AssetId
	}
	if f.Sort, err = sortKey(prm.Sort, map[string]string{
		"asset": "asset", "exe": "exe", "user": "user", "state": "state", "startedAt": "started_at", "risk": "risk",
	}); err != nil {
		return nil, err
	}
	rows, total, err := h.cfg.Store.ListProcesses(ctx, f, p)
	if err != nil {
		return nil, err
	}
	return gen.ListProcesses200JSONResponse(processList(rows, total)), nil
}

// ListListenPorts implements gen.StrictServerInterface.
func (h *Handlers) ListListenPorts(ctx context.Context, req gen.ListListenPortsRequestObject) (gen.ListListenPortsResponseObject, error) {
	prm := req.Params
	p, err := page(prm.Limit, prm.Offset)
	if err != nil {
		return nil, err
	}
	var f store.ListenPortFilter
	if f.Q, err = query(prm.Q); err != nil {
		return nil, err
	}
	if f.Proto, err = enum("proto", prm.Proto); err != nil {
		return nil, err
	}
	if prm.Port != nil {
		if *prm.Port < 0 || *prm.Port > 65535 {
			return nil, apierr.Invalid("port must be between 0 and 65535")
		}
		f.Port = *prm.Port
	}
	if prm.AssetId != nil {
		f.AssetID = *prm.AssetId
	}
	if f.Sort, err = sortKey(prm.Sort, map[string]string{
		"port": "port", "address": "address", "process": "exe", "user": "user", "asset": "asset",
	}); err != nil {
		return nil, err
	}
	rows, total, err := h.cfg.Store.ListListenPorts(ctx, f, p)
	if err != nil {
		return nil, err
	}
	out := gen.ListListenPorts200JSONResponse{Items: make([]gen.ListenPortRow, 0, len(rows)), Total: total}
	for _, r := range rows {
		row := gen.ListenPortRow{
			Proto:     gen.ListenProto(r.Proto),
			Address:   r.Address,
			Port:      r.Port,
			AssetId:   r.Asset.ID,
			AssetName: r.Asset.Name,
			Container: str(r.Container),
			ProcessId: str(r.ProcessID),
			ExePath:   str(r.Exe),
			User:      str(r.User),
			Uid:       ptr(r.UID),
		}
		if r.ProcessID != "" {
			row.Pid = ptr(r.PID)
		}
		if r.Component != nil {
			row.ComponentId, row.ComponentName = str(r.Component.ID), str(r.Component.Name)
		}
		out.Items = append(out.Items, row)
	}
	return out, nil
}

func containerImage(r store.ImageRow, components int) gen.ContainerImage {
	var size *int64
	if r.Size > 0 {
		size = ptr(r.Size)
	}
	prev := make(gen.PreviousImageTags, 0, len(r.PreviousTags))
	for _, t := range r.PreviousTags {
		prev = append(prev, gen.PreviousImageTag{Tag: t.Tag, LastSeen: t.LastSeen})
	}
	return gen.ContainerImage{
		Digest:         r.Digest,
		CurrentTags:    strs(r.Tags),
		PreviousTags:   prev,
		Os:             str(r.OS),
		Arch:           str(r.Arch),
		SizeBytes:      size,
		FirstSeen:      r.FirstSeen,
		LastSeen:       timePtr(r.LastSeen),
		Usage:          gen.ImageUsage{Assets: r.Assets, Containers: r.Containers, Instances: r.Instances},
		ContentKnown:   r.ContentKnown(),
		ComponentCount: components,
	}
}

// ListImages implements gen.StrictServerInterface.
func (h *Handlers) ListImages(ctx context.Context, req gen.ListImagesRequestObject) (gen.ListImagesResponseObject, error) {
	prm := req.Params
	p, err := page(prm.Limit, prm.Offset)
	if err != nil {
		return nil, err
	}
	f := store.ImageFilter{
		InUseOnly:    prm.InUse != nil && *prm.InUse,
		ContentKnown: prm.ContentKnown,
	}
	if f.Q, err = query(prm.Q); err != nil {
		return nil, err
	}
	if f.Sort, err = sortKey(prm.Sort, map[string]string{
		"tag": "tag", "digest": "digest", "os": "os", "arch": "arch", "size": "size",
		"instances": "instances", "firstSeen": "first_seen",
	}); err != nil {
		return nil, err
	}
	rows, total, err := h.cfg.Store.ListImages(ctx, f, p)
	if err != nil {
		return nil, err
	}
	out := gen.ListImages200JSONResponse{Items: make([]gen.ContainerImage, 0, len(rows)), Total: total}
	for _, r := range rows {
		out.Items = append(out.Items, containerImage(r, r.Components))
	}
	return out, nil
}

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// GetImage implements gen.StrictServerInterface.
func (h *Handlers) GetImage(ctx context.Context, req gen.GetImageRequestObject) (gen.GetImageResponseObject, error) {
	if !digestRE.MatchString(req.Digest) {
		return nil, apierr.Invalid("digest must be sha256:<64 hex digits>")
	}
	d, err := h.cfg.Store.GetImage(ctx, req.Digest)
	if errors.Is(err, store.ErrNotFound) {
		return nil, apierr.NotFound("image")
	}
	if err != nil {
		return nil, err
	}
	comps := []gen.ImageComponent{}
	for off := 0; ; {
		rows, total, err := h.cfg.Store.ListImageComponents(ctx, d.Digest, store.ImageComponentFilter{},
			store.Page{Limit: maxLimit, Offset: off})
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			comps = append(comps, gen.ImageComponent{
				Component: softwareComponent(r.Component),
				Locations: strs(r.Locations),
				Method:    gen.DetectMethod(r.Method),
			})
		}
		off += len(rows)
		if len(rows) == 0 || off >= total {
			break
		}
	}
	img := containerImage(d.ImageRow, len(comps))
	uses := make([]gen.ImageUse, 0, len(d.Uses))
	for _, u := range d.Uses {
		uses = append(uses, gen.ImageUse{Asset: rowSummary(u.Asset), Container: assetContainer(u.Container)})
	}
	return gen.GetImage200JSONResponse{
		Digest: img.Digest, CurrentTags: img.CurrentTags, PreviousTags: img.PreviousTags, Os: img.Os, Arch: img.Arch, SizeBytes: img.SizeBytes,
		FirstSeen: img.FirstSeen, LastSeen: img.LastSeen, Usage: img.Usage, ContentKnown: img.ContentKnown,
		ComponentCount: img.ComponentCount, Uses: uses, Components: comps,
	}, nil
}
