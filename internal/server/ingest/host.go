// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package ingest

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/server/normalize"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// applyHost applies a report about a host (subject self or scan_target) and
// returns the asset id.
func (s *Service) applyHost(ctx context.Context, tx store.Store, sender Sender, subj subject, r *report.Report) (string, error) {
	at := s.reportTime(r, nil)
	ref, method, address, err := s.hostAsset(ctx, tx, sender, subj, r, at)
	if err != nil {
		return "", err
	}
	assetID := ref.ID
	detail, err := tx.GetAsset(ctx, assetID)
	if err != nil {
		return "", fmt.Errorf("ingest: get asset: %w", err)
	}
	stored := map[sectionKey]store.SectionState{}
	for _, st := range detail.Sections {
		stored[sectionKey{st.Container, st.Section}] = st
	}

	var hostMeta, pkgMeta, artMeta, procMeta, ctrMeta *report.SectionMeta
	if r.Host != nil {
		hostMeta = &r.Host.SectionMeta
	}
	if r.Packages != nil {
		pkgMeta = &r.Packages.SectionMeta
	}
	if r.Artifacts != nil {
		artMeta = &r.Artifacts.SectionMeta
	}
	if r.Processes != nil {
		procMeta = &r.Processes.SectionMeta
	}
	if r.Containers != nil {
		ctrMeta = &r.Containers.SectionMeta
	}
	hostP := s.planSection(r, "", report.SectionHost, hostMeta, stored)
	pkgP := s.planSection(r, "", report.SectionPackages, pkgMeta, stored)
	artP := s.planSection(r, "", report.SectionArtifacts, artMeta, stored)
	procP := s.planSection(r, "", report.SectionProcesses, procMeta, stored)
	ctrP := s.planSection(r, "", report.SectionContainers, ctrMeta, stored)

	facts := store.AssetFacts{Address: address, Method: method, Privilege: privilege(r.Privilege), SeenAt: at}
	distro := normalize.Distro{ID: detail.OS.ID, VersionID: detail.OS.Version}
	if r.Host != nil && !r.Host.Unchanged {
		distro = normalize.DistroFromOS(&r.Host.OS)
	}
	if hostP.apply {
		facts.OS = osInfo(r.Host.OS)
		facts.Kernel = r.Host.Kernel
		facts.Arch = r.Host.Arch
		if subj.agent != nil {
			facts.Name = r.Host.Hostname
		}
	}

	var hashes []normalize.FileHash
	ids := componentIDs{}
	containerName := runtimeNames(detail.Containers, nil)
	if ctrP.apply {
		h, err := s.applyHostContainers(ctx, tx, assetID, detail.Containers, ctrP, r.Containers, ids)
		if err != nil {
			return "", err
		}
		hashes = append(hashes, h...)
		containerName = runtimeNames(detail.Containers, r.Containers.Containers)
	}
	if pkgP.apply || artP.apply {
		h, err := s.applyHostSoftware(ctx, tx, assetID, distro, pkgP, artP, r, ids)
		if err != nil {
			return "", err
		}
		hashes = append(hashes, h...)
	}
	if err := recordHashes(ctx, tx, ids, hashes, at); err != nil {
		return "", err
	}
	if procP.apply {
		procs := processObservations(r.Processes.Processes, containerName)
		if err := linkByPath(ctx, tx, assetID, procs, nil); err != nil {
			return "", err
		}
		_, err := tx.ReplaceProcesses(ctx, store.ProcessScope{AssetID: assetID}, store.ProcessSnapshot{
			At: procP.at, Processes: procs, UnownedPorts: unownedPorts(r.Processes.UnownedPorts),
		})
		if err != nil {
			return "", fmt.Errorf("ingest: replace processes: %w", err)
		}
	}

	var states []store.SectionState
	for _, p := range []plan{hostP, pkgP, artP, procP, ctrP} {
		if p.present {
			states = append(states, p.state)
			stored[sectionKey{"", p.name}] = p.state
		}
	}
	if err := tx.SetSectionStates(ctx, assetID, states); err != nil {
		return "", fmt.Errorf("ingest: set section states: %w", err)
	}
	facts.Coverage, facts.CoverageReason = hostCoverage(stored)
	if err := tx.UpdateAssetFacts(ctx, assetID, facts); err != nil {
		return "", fmt.Errorf("ingest: update asset: %w", err)
	}
	return assetID, nil
}

// hostAsset finds or creates the host asset of the report and links the
// agent or scan target to it.
func (s *Service) hostAsset(ctx context.Context, tx store.Store, sender Sender, subj subject, r *report.Report, at time.Time) (store.AssetRef, store.CollectMethod, string, error) {
	var machineID, hostname string
	if r.Host != nil {
		machineID, hostname = r.Host.MachineID, r.Host.Hostname
	}
	if subj.agent != nil && subj.target == nil {
		a := subj.agent
		init := store.AssetInit{Name: firstNonEmpty(hostname, a.Hostname), Method: store.CollectAgent, SeenAt: at}
		init.Group, init.Tags = s.enrollDefaults(ctx, tx, *a)
		ref, err := tx.UpsertHostAsset(ctx, store.HostIdentity{AgentID: a.ID, MachineID: machineID}, init)
		if err != nil {
			return ref, "", "", fmt.Errorf("ingest: upsert host asset: %w", err)
		}
		if ref.DuplicateMachineID {
			s.log.Warn("machine id seen on another host asset", "asset", ref.ID, "agent", a.ID, "machine_id", machineID)
		}
		if a.AssetID != ref.ID {
			if err := tx.SetAgentAsset(ctx, a.ID, ref.ID); err != nil {
				return ref, "", "", fmt.Errorf("ingest: link agent: %w", err)
			}
		}
		return ref, store.CollectAgent, firstNonEmpty(hostOf(sender.RemoteAddr), a.Address), nil
	}

	t := subj.target
	if t == nil {
		return store.AssetRef{}, "", "", newErr(ErrForbidden, "no subject")
	}
	// The target identifies the host: its linked asset, else (first report)
	// an asset with the machine id, else a new asset. The store links the
	// target to it.
	id := store.HostIdentity{ScanTargetID: t.ID, MachineID: machineID, Address: t.Address}
	init := store.AssetInit{Name: firstNonEmpty(t.Name, hostname, t.Address), Method: store.CollectSSH, SeenAt: at}
	ref, err := tx.UpsertHostAsset(ctx, id, init)
	if err != nil {
		return ref, "", "", fmt.Errorf("ingest: upsert host asset: %w", err)
	}
	if ref.DuplicateMachineID {
		s.log.Warn("machine id seen on another host asset", "asset", ref.ID, "scan_target", t.ID, "machine_id", machineID)
	}
	return ref, store.CollectSSH, t.Address, nil
}

// enrollDefaults returns the group and tags an agent's asset starts with:
// those recorded at enrollment, else those of the register key.
func (s *Service) enrollDefaults(ctx context.Context, tx store.Store, a store.Agent) (string, []string) {
	if e, err := tx.GetAgentEnrollment(ctx, a.ID); err == nil {
		return e.DefaultGroup, e.DefaultTags
	} else if !errors.Is(err, store.ErrNotFound) {
		s.log.Warn("reading agent enrollment", "agent", a.ID, "err", err)
	}
	if a.RegisterKeyID == "" {
		return "", nil
	}
	k, err := tx.GetRegisterKey(ctx, a.RegisterKeyID)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.log.Warn("reading register key", "agent", a.ID, "key", a.RegisterKeyID, "err", err)
		}
		return "", nil
	}
	return k.DefaultGroup, k.DefaultTags
}

// applyHostSoftware replaces the packages and artifacts of the host itself.
// Artifacts owned by an OS package are recorded as locations of that
// package; when only one of the two sections is in the report, the other
// side is taken from the stored rows so the links survive.
func (s *Service) applyHostSoftware(ctx context.Context, tx store.Store, assetID string, distro normalize.Distro, pkgP, artP plan, r *report.Report, ids componentIDs) ([]normalize.FileHash, error) {
	self := ""
	var storedPkgs []store.AssetComponentRow
	if !pkgP.apply || !artP.apply {
		var err error
		storedPkgs, err = assetComponents(ctx, tx, assetID, store.AssetComponentFilter{Container: &self, Source: store.SourcePackages})
		if err != nil {
			return nil, err
		}
	}

	var pkgObs, artObs []store.ComponentObservation
	var owned map[string]normalize.Owned
	if artP.apply {
		artObs, owned = normalize.Artifacts(r.Artifacts.Artifacts)
	} else {
		owned = ownedFromRows(storedPkgs)
	}
	if pkgP.apply {
		pkgObs = normalize.Packages(r.Packages.Packages, distro)
	} else {
		pkgObs = observationsFromRows(storedPkgs)
	}
	if unmatched := normalize.LinkOwned(pkgObs, owned); len(unmatched) > 0 && artP.apply {
		s.log.Debug("artifacts owned by unknown packages", "asset", assetID, "packages", unmatched)
	}

	if pkgP.apply || len(pkgObs) > 0 {
		opts := store.ReplaceOptions{At: pkgP.at, KeepMissing: pkgP.keepMissing}
		if !pkgP.apply {
			opts = store.ReplaceOptions{At: artP.at, KeepMissing: true}
		}
		scope := store.ComponentScope{AssetID: assetID, Source: store.SourcePackages}
		res, err := tx.ReplaceAssetComponents(ctx, scope, pkgObs, opts)
		if err != nil {
			return nil, fmt.Errorf("ingest: replace packages: %w", err)
		}
		ids.add(pkgObs, res)
	}
	if !artP.apply {
		return nil, nil
	}
	scope := store.ComponentScope{AssetID: assetID, Source: store.SourceArtifacts}
	res, err := tx.ReplaceAssetComponents(ctx, scope, artObs, store.ReplaceOptions{At: artP.at, KeepMissing: artP.keepMissing})
	if err != nil {
		return nil, fmt.Errorf("ingest: replace artifacts: %w", err)
	}
	ids.add(artObs, res)
	return normalize.FileHashes(r.Artifacts.Artifacts, pkgObs), nil
}

// applyHostContainers replaces the containers of a host, records its
// images, stores the content of each image scope by digest and the runtime
// layer of each running container.
func (s *Service) applyHostContainers(ctx context.Context, tx store.Store, assetID string, prev []store.Container, p plan, sec *report.ContainersSection, ids componentIDs) ([]normalize.FileHash, error) {
	storedCov := map[string]store.Coverage{}
	for _, c := range prev {
		if c.GoneAt == nil {
			storedCov[c.Name] = c.Coverage
		}
	}
	byID := map[string]report.Container{}
	var obs []store.ContainerObservation
	var tags []store.ImageObservation
	for _, c := range sec.Containers {
		byID[c.ID] = c
		o := store.ContainerObservation{
			Name: containerNameOf(c), RuntimeID: c.ID, ImageRef: c.ImageRef,
			ImageDigest: normalize.ImageDigest(c.ImageDigest), Runtime: c.Runtime,
			Coverage: containerCoverage(c.Coverage), CoverageReason: c.Reason, StartedAt: c.StartedAt,
		}
		if c.Running {
			o.Instances = 1
		}
		obs = append(obs, o)
		if o.ImageDigest != "" {
			io := store.ImageObservation{Digest: o.ImageDigest}
			if t := normalize.ImageTag(c.ImageRef); t != "" {
				io.RepoTags = []string{t}
			}
			tags = append(tags, io)
		}
	}
	if err := tx.ReplaceContainers(ctx, assetID, obs, store.ReplaceOptions{At: p.at, KeepMissing: p.keepMissing}); err != nil {
		return nil, fmt.Errorf("ingest: replace containers: %w", err)
	}
	if err := tx.UpsertImages(ctx, append(imageObservations(sec.Images), tags...), p.at); err != nil {
		return nil, fmt.Errorf("ingest: upsert images: %w", err)
	}

	var hashes []normalize.FileHash
	for _, sc := range sec.ImageScopes {
		digest := normalize.ImageDigest(sc.Digest)
		if digest == "" {
			continue
		}
		content := normalize.BuildContent(sc.Packages, sc.Artifacts, normalize.DistroFromOS(sc.OS))
		cov := sectionCoverage(p.meta.Coverage)
		if c, ok := byID[sc.FromContainer]; ok {
			if cc := containerCoverage(c.Coverage); cc == store.CoverageFull || cc == store.CoveragePartial {
				cov = cc
			}
		}
		if cov != store.CoverageFull {
			cov = store.CoveragePartial
		}
		if _, err := tx.PutImageContent(ctx, store.ImageContent{Digest: digest, Coverage: cov, CollectedAt: p.at,
			Packages: content.Packages, Artifacts: content.Artifacts}); err != nil {
			return nil, fmt.Errorf("ingest: put image content: %w", err)
		}
		hashes = append(hashes, content.Hashes...)
	}

	for _, c := range sec.Containers {
		cov := containerCoverage(c.Coverage)
		if !c.Running || (cov != store.CoverageFull && cov != store.CoveragePartial) {
			continue
		}
		name := containerNameOf(c)
		arts, _ := normalize.Artifacts(c.RuntimeArtifacts)
		keep := false
		if old, ok := storedCov[name]; ok {
			keep = rank(cov) < rank(old)
		}
		scope := store.ComponentScope{AssetID: assetID, Container: name, Source: store.SourceArtifacts, Layer: store.LayerRuntime}
		res, err := tx.ReplaceAssetComponents(ctx, scope, arts, store.ReplaceOptions{At: p.at, KeepMissing: keep})
		if err != nil {
			return nil, fmt.Errorf("ingest: replace runtime artifacts of %s: %w", name, err)
		}
		ids.add(arts, res)
		hashes = append(hashes, normalize.FileHashes(c.RuntimeArtifacts, nil)...)
	}
	return hashes, nil
}

// containerNameOf is the key of a host container: its name without the
// leading slash docker uses, or the short id.
func containerNameOf(c report.Container) string {
	if n := strings.TrimPrefix(c.Name, "/"); n != "" {
		return n
	}
	return shortID(c.ID)
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// runtimeNames returns a resolver from a runtime container id (as taken
// from a cgroup path) to the container name. Ids are matched exactly or by
// prefix; an unknown id gives its short form, so that the process stays
// apart from the host's own.
func runtimeNames(stored []store.Container, current []report.Container) func(string) string {
	names := map[string]string{}
	for _, c := range stored {
		if c.RuntimeID != "" {
			names[c.RuntimeID] = c.Name
		}
	}
	for _, c := range current {
		if c.ID != "" {
			names[c.ID] = containerNameOf(c)
		}
	}
	return func(id string) string {
		if n, ok := names[id]; ok {
			return n
		}
		if len(id) >= 12 {
			for rid, n := range names {
				if strings.HasPrefix(rid, id) || strings.HasPrefix(id, rid) && len(rid) >= 12 {
					return n
				}
			}
		}
		return shortID(id)
	}
}

// hostOf strips the port from a remote address.
func hostOf(addr string) string {
	if addr == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}
