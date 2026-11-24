// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package ingest

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/server/normalize"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// applyK8sContainer applies the report of one pod container, collected
// through exec. The container belongs to the asset of the pod's workload;
// a pod that the stored inventory does not know yet gives ErrRetryLater.
// It returns the asset id, or "" when the workload is excluded.
func (s *Service) applyK8sContainer(ctx context.Context, tx store.Store, subj subject, r *report.Report) (string, error) {
	k := subj.k8s
	wl, pod, err := findPod(ctx, tx, subj.cluster.ID, k.Namespace, k.Pod)
	if err != nil {
		return "", err
	}
	if wl.Excluded || wl.AssetID == "" {
		s.log.Info("ignoring report of an excluded workload", "cluster", subj.cluster.ID,
			"namespace", k.Namespace, "pod", k.Pod)
		return "", nil
	}
	assetID := wl.AssetID
	name := k.Container
	digest := normalize.ImageDigest(k.ImageDigest)
	if digest == "" {
		for _, c := range pod.Containers {
			if c.Name == name {
				digest = normalize.ImageDigest(c.ImageDigest)
			}
		}
	}
	at := s.reportTime(r, nil)

	detail, err := tx.GetAsset(ctx, assetID)
	if err != nil {
		return "", fmt.Errorf("ingest: get asset: %w", err)
	}
	stored := map[sectionKey]store.SectionState{}
	for _, st := range detail.Sections {
		stored[sectionKey{st.Container, st.Section}] = st
	}

	var pkgs *report.PackagesSection
	var arts *report.ArtifactsSection
	var procs *report.ProcessesSection
	if r.Packages != nil && !r.Packages.Unchanged {
		pkgs = r.Packages
	}
	if r.Artifacts != nil && !r.Artifacts.Unchanged {
		arts = r.Artifacts
	}
	if r.Processes != nil && !r.Processes.Unchanged {
		procs = r.Processes
	}
	distro := normalize.Distro{}
	if r.Host != nil && !r.Host.Unchanged {
		distro = normalize.DistroFromOS(&r.Host.OS)
	}

	var hashes []normalize.FileHash
	ids := componentIDs{}
	if pkgs != nil || arts != nil {
		var pkgList []report.Package
		var imageArts, runtimeArts []report.Artifact
		if pkgs != nil {
			pkgList = pkgs.Packages
		}
		if arts != nil {
			for _, a := range arts.Artifacts {
				if a.Layer == report.LayerRuntime {
					runtimeArts = append(runtimeArts, a)
				} else {
					imageArts = append(imageArts, a)
				}
			}
		}
		content := normalize.BuildContent(pkgList, imageArts, distro)
		hashes = append(hashes, content.Hashes...)
		cov := store.CoverageFull
		if pkgs == nil || arts == nil || sectionCoverage(pkgs.Coverage) != store.CoverageFull ||
			sectionCoverage(arts.Coverage) != store.CoverageFull {
			cov = store.CoveragePartial
		}
		if arts != nil {
			scope := store.GoBinaryScope{Digest: digest}
			if digest == "" {
				scope = store.GoBinaryScope{AssetID: assetID, Container: name, Layer: store.LayerImage}
			}
			if err := tx.ReplaceGoBinaries(ctx, scope, normalize.GoBinaries(imageArts), store.ReplaceOptions{At: at}); err != nil {
				return "", fmt.Errorf("ingest: replace go binaries: %w", err)
			}
		}
		if digest != "" {
			if _, err := tx.PutImageContent(ctx, store.ImageContent{Digest: digest, Coverage: cov, CollectedAt: at,
				Packages: content.Packages, Artifacts: content.Artifacts}); err != nil {
				return "", fmt.Errorf("ingest: put image content: %w", err)
			}
		} else {
			// Without a digest the image content cannot be shared; it is
			// kept on the container as layer image.
			for _, part := range []struct {
				src store.ComponentSource
				obs []store.ComponentObservation
				on  bool
			}{{store.SourcePackages, content.Packages, pkgs != nil}, {store.SourceArtifacts, content.Artifacts, arts != nil}} {
				if !part.on {
					continue
				}
				scope := store.ComponentScope{AssetID: assetID, Container: name, Source: part.src, Layer: store.LayerImage}
				res, err := tx.ReplaceAssetComponents(ctx, scope, part.obs, store.ReplaceOptions{At: at})
				if err != nil {
					return "", fmt.Errorf("ingest: replace image layer: %w", err)
				}
				ids.add(part.obs, res)
			}
		}
		if arts != nil {
			obs, _ := normalize.Artifacts(runtimeArts)
			scope := store.ComponentScope{AssetID: assetID, Container: name, Source: store.SourceArtifacts, Layer: store.LayerRuntime}
			res, err := tx.ReplaceAssetComponents(ctx, scope, obs, store.ReplaceOptions{At: at})
			if err != nil {
				return "", fmt.Errorf("ingest: replace runtime artifacts: %w", err)
			}
			ids.add(obs, res)
			if err := tx.ReplaceGoBinaries(ctx, store.GoBinaryScope{AssetID: assetID, Container: name, Layer: store.LayerRuntime},
				normalize.GoBinaries(runtimeArts), store.ReplaceOptions{At: at}); err != nil {
				return "", fmt.Errorf("ingest: replace go binaries: %w", err)
			}
			hashes = append(hashes, normalize.FileHashes(runtimeArts, nil)...)
		}
	}
	if err := recordHashes(ctx, tx, ids, hashes, at); err != nil {
		return "", err
	}
	if procs != nil {
		obs := processObservations(procs.Processes, nil)
		if err := linkByPath(ctx, tx, assetID, obs, &name); err != nil {
			return "", err
		}
		scope := store.ProcessScope{AssetID: assetID, Pod: pod.Name, Container: name}
		if _, err := tx.ReplaceProcesses(ctx, scope, store.ProcessSnapshot{At: at, Processes: obs,
			UnownedPorts: unownedPorts(procs.UnownedPorts)}); err != nil {
			return "", fmt.Errorf("ingest: replace processes: %w", err)
		}
	}

	// Coverage of the pod container and of the workload container: what is
	// known about them now, not what this exec happened to collect.
	var storedPC store.K8sPodContainer
	for _, c := range pod.Containers {
		if c.Name == name {
			storedPC = c
		}
	}
	cov, reason, ok, err := podContainerCoverage(ctx, tx, digest, storedPC, pkgs, arts, procs)
	if err != nil {
		return "", err
	}
	if ok {
		if err := tx.SetPodContainerCoverage(ctx, subj.cluster.ID, k.Namespace, pod.Name, name, cov, reason); err != nil &&
			!errors.Is(err, store.ErrNotFound) {
			return "", fmt.Errorf("ingest: set pod container coverage: %w", err)
		}
		ccov, creason, err := instancesCoverage(ctx, tx, wl.ID, pod.Name, name, cov, reason)
		if err != nil {
			return "", err
		}
		if err := tx.SetContainerCoverage(ctx, assetID, name, ccov, creason); err != nil &&
			!errors.Is(err, store.ErrNotFound) {
			return "", fmt.Errorf("ingest: set container coverage: %w", err)
		}
	}

	// Section states per container; a report older than the stored state
	// of a section does not overwrite it.
	var states []store.SectionState
	for _, sec := range []struct {
		name string
		meta *report.SectionMeta
	}{
		{report.SectionHost, metaOf(r.Host != nil, func() *report.SectionMeta { return &r.Host.SectionMeta })},
		{report.SectionPackages, metaOf(r.Packages != nil, func() *report.SectionMeta { return &r.Packages.SectionMeta })},
		{report.SectionArtifacts, metaOf(r.Artifacts != nil, func() *report.SectionMeta { return &r.Artifacts.SectionMeta })},
		{report.SectionProcesses, metaOf(r.Processes != nil, func() *report.SectionMeta { return &r.Processes.SectionMeta })},
	} {
		if p := s.planSection(r, name, sec.name, sec.meta, stored); p.present {
			states = append(states, p.state)
		}
	}
	if err := tx.SetSectionStates(ctx, assetID, states); err != nil {
		return "", fmt.Errorf("ingest: set section states: %w", err)
	}

	detail, err = tx.GetAsset(ctx, assetID)
	if err != nil {
		return "", fmt.Errorf("ingest: get asset: %w", err)
	}
	facts := store.AssetFacts{Method: store.CollectK8sExec, Privilege: privilege(r.Privilege), SeenAt: at}
	if r.Host != nil && !r.Host.Unchanged {
		facts.OS = osInfo(r.Host.OS)
		facts.Arch = r.Host.Arch
	}
	facts.Coverage, facts.CoverageReason = workloadCoverage(detail.Containers)
	if err := tx.UpdateAssetFacts(ctx, assetID, facts); err != nil {
		return "", fmt.Errorf("ingest: update asset: %w", err)
	}
	return assetID, nil
}

func metaOf(ok bool, f func() *report.SectionMeta) *report.SectionMeta {
	if !ok {
		return nil
	}
	return f()
}

// podContainerCoverage is what is known about one pod container after an
// exec collection:
//
//	full, partial  the content of its image is known (collected from any
//	               container with the digest; partial when only in part)
//	               and its processes were collected
//	process_only   its processes were collected, the image content is not
//	               known
//
// The processes count as collected when this report carries them or an
// earlier one did (stored coverage full, partial or process_only). ok is
// false when the report carries no content and no processes.
func podContainerCoverage(ctx context.Context, st store.Store, digest string, stored store.K8sPodContainer,
	pkgs *report.PackagesSection, arts *report.ArtifactsSection, procs *report.ProcessesSection) (store.Coverage, string, bool, error) {
	if pkgs == nil && arts == nil && procs == nil {
		return "", "", false, nil
	}
	var notes []string
	note := func(name string, m report.SectionMeta) {
		if sectionCoverage(m.Coverage) != store.CoverageFull {
			notes = append(notes, name+": "+firstNonEmpty(m.Reason, string(m.Coverage)))
		}
	}

	// Content of this exec, if it collected any.
	var execContent store.Coverage
	var execNotes []string
	if pkgs != nil || arts != nil {
		if pkgs == nil {
			notes = append(notes, "packages: not collected")
		} else {
			note(report.SectionPackages, pkgs.SectionMeta)
		}
		if arts == nil {
			notes = append(notes, "artifacts: not collected")
		} else {
			note(report.SectionArtifacts, arts.SectionMeta)
		}
		execContent, execNotes = store.CoverageFull, notes
		if len(notes) > 0 {
			execContent = store.CoveragePartial
		}
		notes = nil
	}

	// What is known about the image content.
	content := execContent
	if digest != "" {
		c, err := st.ImageContentCoverage(ctx, digest)
		if err != nil {
			return "", "", false, fmt.Errorf("ingest: image content coverage: %w", err)
		}
		content = c
	} else if content == "" && (stored.Coverage == store.CoverageFull || stored.Coverage == store.CoveragePartial) {
		// Without a digest the content is kept on the container itself.
		content = stored.Coverage
	}
	switch {
	case content == store.CoveragePartial && execContent == store.CoveragePartial:
		notes = append(notes, execNotes...)
	case content == store.CoveragePartial:
		notes = append(notes, "image content collected in part")
	}

	procsKnown := procs != nil
	if procs != nil {
		note(report.SectionProcesses, procs.SectionMeta)
	} else {
		switch stored.Coverage {
		case store.CoverageFull, store.CoveragePartial, store.CoverageProcessOnly:
			procsKnown = true
		}
	}

	switch {
	case content == "" && !procsKnown:
		return "", "", false, nil
	case content == "":
		return store.CoverageProcessOnly, strings.Join(notes, "; "), true, nil
	case !procsKnown:
		notes = append(notes, "processes: not collected")
	}
	if len(notes) == 0 && content == store.CoverageFull {
		return store.CoverageFull, "", true, nil
	}
	return store.CoveragePartial, strings.Join(notes, "; "), true, nil
}

// instancesCoverage is the coverage of a workload container: the rule of
// podContainerCoverage over its running instances. Instances not collected
// yet are left out. All alike gives that coverage; full mixed with partial
// gives partial; process_only mixed with content known gives partial.
// podName is the instance just collected, with coverage cov.
func instancesCoverage(ctx context.Context, st store.Store, workloadID, podName, container string, cov store.Coverage, reason string) (store.Coverage, string, error) {
	type inst struct {
		cov    store.Coverage
		reason string
	}
	insts := []inst{{cov, reason}}
	for page := (store.Page{Limit: 1000}); ; page.Offset += page.Limit {
		pods, total, err := st.ListWorkloadPods(ctx, workloadID, store.PodFilter{}, page)
		if err != nil {
			return "", "", fmt.Errorf("ingest: list workload pods: %w", err)
		}
		for _, p := range pods {
			if p.Name == podName || p.Phase != "Running" {
				continue
			}
			for _, c := range p.Containers {
				if c.Name != container {
					continue
				}
				switch c.Coverage {
				case store.CoverageFull, store.CoveragePartial, store.CoverageProcessOnly:
					insts = append(insts, inst{c.Coverage, c.CoverageReason})
				}
			}
		}
		if len(pods) == 0 || page.Offset+len(pods) >= total {
			break
		}
	}
	counts := map[store.Coverage]int{}
	var reasons []string
	seen := map[string]bool{}
	for _, in := range insts {
		counts[in.cov]++
		if in.reason != "" && !seen[in.reason] {
			seen[in.reason] = true
			reasons = append(reasons, in.reason)
		}
	}
	sort.Strings(reasons)
	switch {
	case counts[store.CoverageFull] == len(insts):
		return store.CoverageFull, "", nil
	case counts[store.CoverageProcessOnly] == len(insts):
		return store.CoverageProcessOnly, strings.Join(reasons, "; "), nil
	case counts[store.CoverageProcessOnly] > 0:
		reasons = append([]string{fmt.Sprintf("image content not known for %d of %d instances",
			counts[store.CoverageProcessOnly], len(insts))}, reasons...)
	}
	return store.CoveragePartial, strings.Join(reasons, "; "), nil
}

// findPod looks a current pod and its workload up in the stored inventory
// of a cluster.
func findPod(ctx context.Context, st store.Store, clusterID, namespace, podName string) (store.K8sWorkload, store.K8sPod, error) {
	notYet := newErr(ErrRetryLater, "pod %s/%s of cluster %s not in the inventory", namespace, podName, clusterID)
	pod, err := st.GetPod(ctx, clusterID, namespace, podName)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.K8sWorkload{}, store.K8sPod{}, notYet
	case err != nil:
		return store.K8sWorkload{}, store.K8sPod{}, fmt.Errorf("ingest: get pod: %w", err)
	case pod.GoneAt != nil:
		return store.K8sWorkload{}, store.K8sPod{}, notYet
	}
	w, err := st.GetWorkload(ctx, pod.WorkloadID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.K8sWorkload{}, store.K8sPod{}, notYet
	case err != nil:
		return store.K8sWorkload{}, store.K8sPod{}, fmt.Errorf("ingest: get workload: %w", err)
	case w.GoneAt != nil:
		return store.K8sWorkload{}, store.K8sPod{}, notYet
	}
	return w, pod, nil
}

// IngestK8sInventory replaces the stored inventory of a cluster. Only the
// cluster's scanner may send it. An inventory collected before the last
// stored sync is ignored.
func (s *Service) IngestK8sInventory(ctx context.Context, sender Sender, clusterID string, inv agentapi.K8sInventory) error {
	if inv.ClusterId != "" && inv.ClusterId != clusterID {
		return newErr(ErrInvalid, "inventory of cluster %q sent for %q", inv.ClusterId, clusterID)
	}
	return s.st.WithTx(ctx, func(tx store.Store) error {
		if _, err := senderAgent(ctx, tx, sender); err != nil {
			return err
		}
		c, err := clusterOf(ctx, tx, sender, clusterID)
		if err != nil {
			return err
		}
		at := inv.CollectedAt.UTC()
		if at.IsZero() {
			at = s.now()
		}
		if c.LastSync != nil && at.Before(*c.LastSync) {
			s.log.Info("ignoring older cluster inventory", "cluster", clusterID, "collected_at", at, "last_sync", *c.LastSync)
			return nil
		}
		si, images, err := k8sInventory(inv, at)
		if err != nil {
			return err
		}
		res, err := tx.ReplaceClusterInventory(ctx, clusterID, si)
		if err != nil {
			if errors.Is(err, store.ErrInvalid) {
				return newErr(ErrInvalid, "%v", err)
			}
			return fmt.Errorf("ingest: replace cluster inventory: %w", err)
		}
		src := store.ImageSource{Kind: store.ImageSourceCluster, ID: clusterID}
		if err := tx.UpsertImages(ctx, src, images, store.ReplaceOptions{At: at}); err != nil {
			return fmt.Errorf("ingest: upsert images: %w", err)
		}
		s.log.Debug("cluster inventory stored", "cluster", clusterID, "workloads", len(res.Workloads), "gone", res.GoneWorkloads)
		return nil
	})
}

// k8sInventory converts the scanner payload. Pods are grouped under their
// workload; a pod whose workload is missing from the payload gets one.
func k8sInventory(inv agentapi.K8sInventory, at time.Time) (store.K8sInventory, []store.ImageObservation, error) {
	type wkey struct{ ns, kind, name string }
	out := store.K8sInventory{Version: inv.ServerVersion, At: at}
	index := map[wkey]int{}
	for _, w := range inv.Workloads {
		if w.Namespace == "" || w.Kind == "" || w.Name == "" {
			return out, nil, newErr(ErrInvalid, "incomplete workload")
		}
		k := wkey{w.Namespace, w.Kind, w.Name}
		if _, dup := index[k]; dup {
			continue
		}
		o := store.K8sWorkloadObservation{Namespace: w.Namespace, Kind: w.Kind, Name: w.Name, Replicas: w.Replicas}
		if w.ExcludedBy != nil && *w.ExcludedBy != "" {
			o.Excluded, o.ExcludedBy = true, *w.ExcludedBy
		}
		index[k] = len(out.Workloads)
		out.Workloads = append(out.Workloads, o)
	}
	images := map[string]map[string]bool{}
	for _, p := range inv.Pods {
		if p.Namespace == "" || p.Name == "" {
			return out, nil, newErr(ErrInvalid, "incomplete pod")
		}
		kind, name := p.WorkloadKind, p.WorkloadName
		if kind == "" || name == "" {
			kind, name = "Pod", p.Name
		}
		k := wkey{p.Namespace, kind, name}
		i, ok := index[k]
		if !ok {
			i = len(out.Workloads)
			index[k] = i
			out.Workloads = append(out.Workloads, store.K8sWorkloadObservation{Namespace: p.Namespace, Kind: kind, Name: name})
		}
		if out.Workloads[i].Excluded {
			continue
		}
		po := store.K8sPodObservation{Name: p.Name, Node: p.Node, Phase: string(p.Phase)}
		if p.StartedAt != nil {
			po.StartedAt = p.StartedAt.UTC()
		}
		for _, c := range p.Containers {
			co := store.K8sPodContainerObservation{Name: c.Name, ImageRef: c.ImageRef}
			if c.ImageDigest != nil {
				co.ImageDigest = normalize.ImageDigest(*c.ImageDigest)
			}
			po.Containers = append(po.Containers, co)
			if co.ImageDigest != "" {
				if images[co.ImageDigest] == nil {
					images[co.ImageDigest] = map[string]bool{}
				}
				if t := normalize.ImageTag(c.ImageRef); t != "" {
					images[co.ImageDigest][t] = true
				}
			}
		}
		out.Workloads[i].Pods = append(out.Workloads[i].Pods, po)
	}
	var obs []store.ImageObservation
	for d, tags := range images {
		o := store.ImageObservation{Digest: d}
		for t := range tags {
			o.RepoTags = append(o.RepoTags, t)
		}
		sort.Strings(o.RepoTags)
		obs = append(obs, o)
	}
	sort.Slice(obs, func(i, j int) bool { return obs[i].Digest < obs[j].Digest })
	return out, obs, nil
}
