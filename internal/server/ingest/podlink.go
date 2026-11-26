// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package ingest

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

// applyPodLinks follows a host report to the workloads of the pods whose
// containers the host runs. Their findings are recomputed with what the
// host saw. When the containers section was applied, the coverage of a
// pod container whose content the host read is raised to that of the host
// container: without exec into the pod, the node agent is the only
// collection of it.
func (s *Service) applyPodLinks(ctx context.Context, tx store.Store, hostID string, containers bool) error {
	if err := tx.TouchPodLinks(ctx, hostID); err != nil {
		return fmt.Errorf("ingest: touch pod links: %w", err)
	}
	if !containers {
		return nil
	}
	host, err := tx.GetAsset(ctx, hostID)
	if err != nil {
		return fmt.Errorf("ingest: get asset: %w", err)
	}
	byWorkload := map[string][]store.Container{}
	var order []string
	for _, c := range host.Containers {
		if c.Workload == nil || c.GoneAt != nil || c.Instances == 0 {
			continue
		}
		if c.Coverage != store.CoverageFull && c.Coverage != store.CoveragePartial {
			continue
		}
		id := c.Workload.AssetID
		if _, ok := byWorkload[id]; !ok {
			order = append(order, id)
		}
		byWorkload[id] = append(byWorkload[id], c)
	}
	for _, id := range order {
		if err := s.nodeCoverage(ctx, tx, id, host.Name, byWorkload[id]); err != nil {
			return err
		}
	}
	return nil
}

// nodeCoverage records the coverage of the pod containers of one workload
// that a host collected, where it is higher than what exec collected, then
// that of the workload's containers and of the workload asset.
func (s *Service) nodeCoverage(ctx context.Context, tx store.Store, workloadAssetID, hostName string, cs []store.Container) error {
	w, err := tx.GetAsset(ctx, workloadAssetID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("ingest: get asset: %w", err)
	}
	if w.ClusterID == "" || w.WorkloadID == "" {
		return nil
	}
	for _, c := range cs {
		pod, err := tx.GetPod(ctx, w.ClusterID, w.Namespace, c.Workload.Pod)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return fmt.Errorf("ingest: get pod: %w", err)
		}
		if i := slices.IndexFunc(pod.Containers, func(pc store.K8sPodContainer) bool { return pc.Name == c.PodContainer }); i >= 0 &&
			rank(pod.Containers[i].Coverage) >= rank(c.Coverage) {
			continue
		}
		reason := c.CoverageReason
		if reason != "" {
			reason = "node agent " + hostName + ": " + reason
		}
		err = tx.SetPodContainerCoverage(ctx, w.ClusterID, w.Namespace, c.Workload.Pod, c.PodContainer, c.Coverage, reason)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return fmt.Errorf("ingest: set pod container coverage: %w", err)
		}
		ccov, creason, err := instancesCoverage(ctx, tx, w.WorkloadID, c.Workload.Pod, c.PodContainer, c.Coverage, reason)
		if err != nil {
			return err
		}
		if err := tx.SetContainerCoverage(ctx, workloadAssetID, c.PodContainer, ccov, creason); err != nil &&
			!errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("ingest: set container coverage: %w", err)
		}
	}
	w, err = tx.GetAsset(ctx, workloadAssetID)
	if err != nil {
		return fmt.Errorf("ingest: get asset: %w", err)
	}
	facts := store.AssetFacts{}
	facts.Coverage, facts.CoverageReason = workloadCoverage(w.Containers)
	if err := tx.UpdateAssetFacts(ctx, workloadAssetID, facts); err != nil {
		return fmt.Errorf("ingest: update asset: %w", err)
	}
	return nil
}
