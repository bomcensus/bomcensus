// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package ingest

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/server/normalize"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

const pageSize = 1000

// assetComponents lists the current components of an asset (its own and the
// image content of its containers).
func assetComponents(ctx context.Context, st store.Store, assetID string, f store.AssetComponentFilter) ([]store.AssetComponentRow, error) {
	var out []store.AssetComponentRow
	for off := 0; ; off += pageSize {
		rows, total, err := st.ListAssetComponents(ctx, assetID, f, store.Page{Limit: pageSize, Offset: off})
		if err != nil {
			return nil, fmt.Errorf("ingest: list asset components: %w", err)
		}
		out = append(out, rows...)
		if len(rows) == 0 || off+len(rows) >= total {
			return out, nil
		}
	}
}

// componentIDs maps component identities (normalize.Identity) to the ids
// the store returned for them.
type componentIDs map[string]string

// add records the ids of a ReplaceAssetComponents call over obs.
func (m componentIDs) add(obs []store.ComponentObservation, res store.ReplaceResult) {
	for i, o := range obs {
		if i < len(res.ComponentIDs) && res.ComponentIDs[i] != "" {
			m[normalize.Identity(o.Component)] = res.ComponentIDs[i]
		}
	}
}

// recordHashes resolves the components of hashes and records them. Ids
// written by this report come from known; the others (image content stored
// earlier by digest) are looked up by identity.
func recordHashes(ctx context.Context, st store.Store, known componentIDs, hashes []normalize.FileHash, at time.Time) error {
	if len(hashes) == 0 {
		return nil
	}
	var missing []store.Component
	queued := map[string]bool{}
	for _, h := range hashes {
		k := normalize.Identity(h.Component)
		if known[k] == "" && !queued[k] {
			queued[k] = true
			missing = append(missing, h.Component)
		}
	}
	if len(missing) > 0 {
		found, err := st.LookupComponentIDs(ctx, missing)
		if err != nil {
			return fmt.Errorf("ingest: look up components: %w", err)
		}
		for i, c := range missing {
			if found[i] != "" {
				known[normalize.Identity(c)] = found[i]
			}
		}
	}
	var out []store.FileHash
	for _, h := range hashes {
		if id := known[normalize.Identity(h.Component)]; id != "" {
			out = append(out, store.FileHash{SHA256: h.SHA256, ComponentID: id, Path: h.Path})
		}
	}
	if err := st.RecordFileHashes(ctx, out, at); err != nil {
		return fmt.Errorf("ingest: record file hashes: %w", err)
	}
	return nil
}

// processObservations converts report processes. container maps a runtime
// container id to the container name; nil for a pod scope.
func processObservations(ps []report.Process, container func(id string) string) []store.ProcessObservation {
	out := make([]store.ProcessObservation, 0, len(ps))
	for _, p := range ps {
		o := store.ProcessObservation{
			PID: p.PID, PPID: p.PPID, User: p.User, UID: p.UID, Exe: p.Exe, ExeSource: p.ExeSource,
			ExeState: p.ExeState, SHA256: p.SHA256, Cmdline: p.Cmdline, StartedAt: p.StartedAt,
			OtherNetNS: p.OtherNetNS,
		}
		for _, l := range p.Libs {
			o.Libs = append(o.Libs, store.MappedLib{Path: l.Path, State: l.State, SHA256: l.SHA256})
		}
		for _, l := range p.Listen {
			o.Listen = append(o.Listen, store.ListenAddr{Proto: l.Proto, Address: l.Address, Port: l.Port})
		}
		if p.PackagesKnown {
			o.Packages = append([]string{}, p.Packages...)
		}
		if container != nil && p.ContainerID != "" {
			o.Container = container(p.ContainerID)
		}
		out = append(out, o)
	}
	return out
}

func unownedPorts(us []report.UnownedPort) []store.UnownedPort {
	out := make([]store.UnownedPort, 0, len(us))
	for _, u := range us {
		out = append(out, store.UnownedPort{
			ListenAddr: store.ListenAddr{Proto: u.Proto, Address: u.Address, Port: u.Port}, UID: u.UID,
		})
	}
	return out
}

// linkByPath sets the component of processes whose executable hash does not
// identify one: an executable read from a normal file is linked to the
// component that has its path as a location (an artifact, or the OS package
// that owns it). Replaced and deleted executables are not linked by path:
// the file at the path is not the one running. Processes with a known hash
// are left to the store, which links them through file_hashes.
func linkByPath(ctx context.Context, st store.Store, assetID string, procs []store.ProcessObservation, container *string) error {
	var hashes []string
	for _, p := range procs {
		if p.SHA256 != "" {
			hashes = append(hashes, p.SHA256)
		}
	}
	known := map[string]string{}
	if len(hashes) > 0 {
		m, err := st.ComponentsByFileHash(ctx, hashes)
		if err != nil {
			return fmt.Errorf("ingest: components by file hash: %w", err)
		}
		known = m
	}
	var todo []int
	for i, p := range procs {
		if p.Exe == "" || known[p.SHA256] != "" {
			continue
		}
		if p.ExeState != "" && p.ExeState != report.ExeNormal {
			continue
		}
		// A path inside an archive is not an executable on disk.
		if strings.Contains(p.Exe, "!/") {
			continue
		}
		todo = append(todo, i)
	}
	if len(todo) == 0 {
		return nil
	}
	locOf := func(i int) store.ComponentLocation {
		c := procs[i].Container
		if container != nil {
			c = *container
		}
		return store.ComponentLocation{Container: c, Path: procs[i].Exe}
	}
	locs := make([]store.ComponentLocation, 0, len(todo))
	for _, i := range todo {
		locs = append(locs, locOf(i))
	}
	byPath, err := st.ComponentsAtLocations(ctx, assetID, locs)
	if err != nil {
		return fmt.Errorf("ingest: components at locations: %w", err)
	}
	for _, i := range todo {
		if id := byPath[locOf(i)]; id != "" {
			procs[i].ComponentID = id
		}
	}
	return nil
}

// ownedFromRows rebuilds what owned artifacts added to the package rows of
// a scope, keyed as normalize.LinkOwned looks them up.
func ownedFromRows(rows []store.AssetComponentRow) map[string]normalize.Owned {
	owned := map[string]normalize.Owned{}
	for _, r := range rows {
		if len(r.Locations) == 0 && !r.InUse {
			continue
		}
		key := r.Component.Name
		if r.Component.Arch != "" {
			key += ":" + r.Component.Arch
		}
		o := owned[key]
		o.Locations = append(o.Locations, r.Locations...)
		o.InUse = o.InUse || r.InUse
		owned[key] = o
	}
	return owned
}

// observationsFromRows turns stored rows back into observations.
func observationsFromRows(rows []store.AssetComponentRow) []store.ComponentObservation {
	out := make([]store.ComponentObservation, 0, len(rows))
	for _, r := range rows {
		c := r.Component
		c.ID = ""
		out = append(out, store.ComponentObservation{Component: c, Locations: r.Locations, InUse: r.InUse,
			Method: r.Method, VersionCommand: r.VersionCommand, VersionRaw: r.VersionRaw})
	}
	return out
}

func imageObservations(images []report.Image) []store.ImageObservation {
	var out []store.ImageObservation
	for _, im := range images {
		d := normalize.ImageDigest(im.Digest)
		if d == "" {
			continue
		}
		var tags []string
		for _, t := range im.RepoTags {
			if t = normalize.ImageTag(t); t != "" {
				tags = append(tags, t)
			}
		}
		out = append(out, store.ImageObservation{Digest: d, RepoTags: tags, OS: im.OS, Arch: im.Arch, Size: im.Size})
	}
	return out
}

func osInfo(os report.OS) store.OSInfo {
	name := os.PrettyName
	if name == "" {
		name = os.Name
	}
	version := os.VersionID
	if version == "" {
		version = os.Version
	}
	family := os.Family
	if family == "" {
		family = "linux"
	}
	return store.OSInfo{Family: family, ID: strings.ToLower(os.ID), Name: name, Version: version}
}

func privilege(p report.Privilege) store.Privilege {
	switch p.Level {
	case report.PrivilegePrivileged:
		return store.PrivilegePrivileged
	case report.PrivilegeNonRoot:
		return store.PrivilegeNonRoot
	}
	return ""
}
