// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package scansvc

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/bomcensus/bomcensus/internal/scanner/kube"
	"github.com/bomcensus/bomcensus/internal/scanner/runner"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// RequestCollect collects an asset that no agent collects: the host of a
// scan target is scanned (RequestRun); the pods of a workload are collected
// through exec, one full collection per container of the workload and the
// process section from the other replicas. It returns store.ErrNotFound for
// an unknown asset, ErrExecDisabled when the workload's cluster has exec
// off and ErrNotCollectable for other assets or a workload without running
// pods.
func (s *Service) RequestCollect(ctx context.Context, assetID string) error {
	a, err := s.st.GetAsset(ctx, assetID)
	if err != nil {
		return fmt.Errorf("scansvc: asset %s: %w", assetID, err)
	}
	if a.ScanTargetID != "" {
		return s.RequestRun(ctx, a.ScanTargetID)
	}
	if a.Kind != store.AssetWorkload || a.ClusterID == "" || a.WorkloadID == "" {
		return ErrNotCollectable
	}
	c, err := s.st.GetCluster(ctx, a.ClusterID)
	if err != nil {
		return fmt.Errorf("scansvc: cluster %s: %w", a.ClusterID, err)
	}
	if !c.ExecEnabled {
		return ErrExecDisabled
	}
	inv, err := s.workloadInventory(ctx, a)
	if err != nil {
		return err
	}
	targets, err := s.plan(ctx, inv, kube.PlanOptions{FullPerWorkload: true})
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("workload has no running pods: %w", ErrNotCollectable)
	}
	if c.ScannerID != "" {
		sc, err := s.scanner(ctx, c.ScannerID)
		if err != nil {
			return err
		}
		return s.dispatchExec(ctx, sc, c, targets)
	}
	if !s.embedded {
		return ErrNoScanner
	}
	kc, err := s.kubeconfig(ctx, c)
	if err != nil {
		return fmt.Errorf("scansvc: cluster %s: %w", c.ID, err)
	}
	// The exec lease is taken inside the job; the pool key keeps a second
	// request for the cluster out while this one waits or runs.
	return s.startEmbeddedKey(ctx, leaseKey(kindExec, c.ID)+":request", func(ctx context.Context) {
		s.runEmbeddedExec(ctx, c, kc, targets)
	})
}

// startEmbeddedKey queues fn on the embedded pool under key without a
// lease of its own.
func (s *Service) startEmbeddedKey(_ context.Context, key string, fn func(context.Context)) error {
	if !s.embedded {
		return ErrNoScanner
	}
	switch err := s.pool.Submit(key, fn); {
	case err == nil:
		return nil
	case errors.Is(err, runner.ErrInFlight):
		return ErrInFlight
	default:
		return ErrBusy
	}
}

// workloadInventory builds a one-workload inventory from the stored pods.
// The store keeps no per-container state, so the containers of a running
// pod count as running.
func (s *Service) workloadInventory(ctx context.Context, a store.AssetDetail) (*kube.Inventory, error) {
	inv := &kube.Inventory{Workloads: []kube.Workload{{Namespace: a.Namespace, Kind: a.WorkloadKind, Name: a.WorkloadName}}}
	for off := 0; ; {
		pods, total, err := s.st.ListWorkloadPods(ctx, a.WorkloadID, store.PodFilter{}, store.Page{Limit: 1000, Offset: off})
		if err != nil {
			return nil, fmt.Errorf("scansvc: pods of workload %s: %w", a.WorkloadID, err)
		}
		for _, p := range pods {
			if p.GoneAt != nil {
				continue
			}
			kp := kube.Pod{Namespace: p.Namespace, Name: p.Name, WorkloadKind: a.WorkloadKind, WorkloadName: a.WorkloadName,
				Node: p.Node, Phase: corev1.PodPhase(p.Phase)}
			running := kp.Phase == corev1.PodRunning
			for _, c := range p.Containers {
				kp.Containers = append(kp.Containers, kube.Container{Name: c.Name, ImageRef: c.ImageRef,
					ImageDigest: c.ImageDigest, Running: running})
			}
			inv.Pods = append(inv.Pods, kp)
		}
		off += len(pods)
		if len(pods) == 0 || off >= total {
			return inv, nil
		}
	}
}
