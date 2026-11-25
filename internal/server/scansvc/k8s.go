// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package scansvc

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/bomcensus/bomcensus/agentproto/dto"
	"github.com/bomcensus/bomcensus/internal/scanner/kube"
	"github.com/bomcensus/bomcensus/internal/scanner/runner"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// RequestSync starts an inventory sync of a cluster now, followed by the
// exec collection when the cluster has exec enabled. Errors as for
// RequestRun.
func (s *Service) RequestSync(ctx context.Context, clusterID string) error {
	c, err := s.st.GetCluster(ctx, clusterID)
	if err != nil {
		return fmt.Errorf("scansvc: cluster %s: %w", clusterID, err)
	}
	return s.startSync(ctx, c)
}

func (s *Service) startSync(ctx context.Context, c store.K8sCluster) error {
	jobID := newJobID(kindSync, c.ID)
	if c.ScannerID == "" {
		return s.startEmbedded(ctx, leaseKey(kindSync, c.ID), jobID, func(ctx context.Context) { s.runEmbeddedSync(ctx, c, jobID) })
	}
	sc, err := s.scanner(ctx, c.ScannerID)
	if err != nil {
		return err
	}
	return s.dispatchSync(ctx, sc, c, jobID)
}

// ScheduleK8s starts the syncs of clusters whose last sync or sync attempt
// is at least the sync interval ago. It is the handler of
// job.KindK8sSyncDue.
func (s *Service) ScheduleK8s(ctx context.Context) error {
	now := s.now().UTC()
	interval := s.syncInterval(ctx)
	var errs []error
	for off := 0; ; {
		rows, total, err := s.st.ListClusters(ctx, store.ClusterFilter{}, store.Page{Limit: 1000, Offset: off})
		if err != nil {
			return errors.Join(append(errs, fmt.Errorf("scansvc: list clusters: %w", err))...)
		}
		for _, r := range rows {
			c := r.K8sCluster
			if c.ScannerID == "" && !s.embedded {
				continue
			}
			last := time.Time{}
			if c.LastSync != nil {
				last = *c.LastSync
			}
			l, err := s.leases.Get(ctx, leaseKey(kindSync, c.ID))
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if l.Started.After(last) {
				last = l.Started
			}
			if !last.IsZero() && now.Sub(last) < interval {
				continue
			}
			s.logStart("sync", c.ID, s.startSync(ctx, c))
		}
		off += len(rows)
		if len(rows) == 0 || off >= total {
			break
		}
	}
	return errors.Join(errs...)
}

// kubeconfig opens the kubeconfig of a cluster; nil means in-cluster.
func (s *Service) kubeconfig(ctx context.Context, c store.K8sCluster) ([]byte, error) {
	if c.Connection != store.K8sKubeconfig {
		return nil, nil
	}
	cred, err := s.st.GetCredentialWithSecret(ctx, c.CredentialID)
	if err != nil {
		return nil, fmt.Errorf("credential %s: %w", c.CredentialID, err)
	}
	if cred.Kind != store.CredentialKubeconfig {
		return nil, fmt.Errorf("credential %s is not a kubeconfig", cred.ID)
	}
	sec, err := s.secrets.OpenCredential(cred.ID, cred.Secret)
	if err != nil {
		return nil, fmt.Errorf("credential %s: %w", cred.ID, err)
	}
	if sec.Kubeconfig == "" {
		return nil, fmt.Errorf("credential %s holds no kubeconfig", cred.ID)
	}
	return []byte(sec.Kubeconfig), nil
}

func kubeFilter(f store.K8sFilter) kube.Filter {
	return kube.Filter{
		NamespaceInclude: f.NSInclude, NamespaceExclude: f.NSExclude,
		LabelInclude: f.LabelInclude, LabelExclude: f.LabelExclude,
		AnnotationInclude: f.AnnotationInclude, AnnotationExclude: f.AnnotationExclude,
	}
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return slices.Clone(v)
}

func apiFilter(f store.K8sFilter) dto.K8sFilter {
	return dto.K8sFilter{
		NamespaceInclude: nonNil(f.NSInclude), NamespaceExclude: nonNil(f.NSExclude),
		LabelInclude: nonNil(f.LabelInclude), LabelExclude: nonNil(f.LabelExclude),
		AnnotationInclude: nonNil(f.AnnotationInclude), AnnotationExclude: nonNil(f.AnnotationExclude),
	}
}

func (s *Service) runEmbeddedSync(ctx context.Context, c store.K8sCluster, jobID string) {
	sink := &embeddedSink{s: s}
	kc, err := s.kubeconfig(ctx, c)
	if err != nil {
		s.failJob(ctx, sink, jobID, runner.ReasonSecret, err)
		return
	}
	inv, err := s.run.RunK8sSync(ctx, runner.K8sSyncJob{JobID: jobID, ClusterID: c.ID, Kubeconfig: kc, Filter: kubeFilter(c.Filter)}, s.deps(sink))
	if err != nil {
		s.log.Warn("result of an embedded sync was not stored", "job_id", jobID, "error", err)
	}
	if inv == nil || !c.ExecEnabled || ctx.Err() != nil {
		return
	}
	targets, err := s.plan(ctx, inv, kube.PlanOptions{})
	if err != nil {
		s.log.Warn("cannot plan the exec collection", "cluster", c.ID, "error", err)
		return
	}
	s.runEmbeddedExec(ctx, c, kc, targets)
}

// runEmbeddedExec runs an exec collection in the calling goroutine under
// the cluster's exec lease.
func (s *Service) runEmbeddedExec(ctx context.Context, c store.K8sCluster, kc []byte, targets []kube.ExecTarget) {
	if len(targets) == 0 {
		return
	}
	jobID := newJobID(kindExec, c.ID)
	lease := leaseKey(kindExec, c.ID)
	now := s.now().UTC()
	ok, err := s.leases.Acquire(ctx, lease, jobID, now, now.Add(embeddedLeaseTTL))
	if err != nil || !ok {
		s.log.Info("exec collection skipped: another one is in flight", "cluster", c.ID, "error", err)
		return
	}
	release := s.keepLease(ctx, lease, jobID)
	defer release()
	job := runner.K8sExecJob{JobID: jobID, ClusterID: c.ID, Kubeconfig: kc, Targets: s.withGoSymbols(ctx, c.ID, targets),
		Policy: s.policy(ctx), Limits: s.limits}
	if _, err := s.run.RunK8sExec(ctx, job, s.deps(&embeddedSink{s: s})); err != nil {
		s.log.Warn("result of an embedded exec collection was not stored", "job_id", jobID, "error", err)
	}
}

// plan decides the exec targets of an inventory with the image content
// already known.
func (s *Service) plan(ctx context.Context, inv *kube.Inventory, opts kube.PlanOptions) ([]kube.ExecTarget, error) {
	seen := map[string]bool{}
	var digests []string
	for _, p := range inv.Pods {
		for _, c := range p.Containers {
			if c.ImageDigest != "" && !seen[c.ImageDigest] {
				seen[c.ImageDigest] = true
				digests = append(digests, c.ImageDigest)
			}
		}
	}
	known := map[string]bool{}
	if len(digests) > 0 {
		have, err := s.st.KnownImageContent(ctx, digests)
		if err != nil {
			return nil, fmt.Errorf("scansvc: known image content: %w", err)
		}
		for _, d := range have {
			known[d] = true
		}
	}
	return kube.Plan(inv, known, opts), nil
}

func (s *Service) dispatchSync(ctx context.Context, sc store.Agent, c store.K8sCluster, jobID string) error {
	d := dto.K8sSyncDirective{
		Type: dto.K8sSync, JobId: jobID, ClusterId: c.ID, Connection: dto.K8sConnection(c.Connection),
		Filter: apiFilter(c.Filter), ExecEnabled: c.ExecEnabled,
	}
	if c.Connection == store.K8sKubeconfig {
		kc, err := s.kubeconfig(ctx, c)
		if err != nil {
			return fmt.Errorf("scansvc: cluster %s: %w", c.ID, err)
		}
		sealed, err := seal(sc, jobID, "kubeconfig", kc)
		if err != nil {
			return err
		}
		d.Kubeconfig = &sealed
	}
	var body dto.Directive
	if err := body.FromK8sSyncDirective(d); err != nil {
		return err
	}
	return s.submitDirective(ctx, sc, leaseKey(kindSync, c.ID), "k8s_sync:"+c.ID, jobID, body, runner.DefaultSyncTimeout)
}

func (s *Service) dispatchExec(ctx context.Context, sc store.Agent, c store.K8sCluster, targets []kube.ExecTarget) error {
	jobID := newJobID(kindExec, c.ID)
	d := dto.K8sExecDirective{
		Type: dto.K8sExec, JobId: jobID, ClusterId: c.ID, Connection: dto.K8sConnection(c.Connection),
		Policy: runner.PolicyToAPI(s.policy(ctx)), Targets: make([]dto.K8sExecTarget, 0, len(targets)),
	}
	if sc.HasFeature(store.FeatureGoSymbols) {
		targets = s.withGoSymbols(ctx, c.ID, targets)
	}
	for _, t := range targets {
		at := t.API()
		if t.Node != "" {
			node := t.Node
			at.Node = &node
		}
		d.Targets = append(d.Targets, at)
	}
	if c.Connection == store.K8sKubeconfig {
		kc, err := s.kubeconfig(ctx, c)
		if err != nil {
			return fmt.Errorf("scansvc: cluster %s: %w", c.ID, err)
		}
		sealed, err := seal(sc, jobID, "kubeconfig", kc)
		if err != nil {
			return err
		}
		d.Kubeconfig = &sealed
	}
	var body dto.Directive
	if err := body.FromK8sExecDirective(d); err != nil {
		return err
	}
	return s.submitDirective(ctx, sc, leaseKey(kindExec, c.ID), "k8s_exec:"+c.ID, jobID, body, runner.DefaultExecTimeout)
}

// InventoryIngested is called after the inventory a remote scanner sent for
// a cluster was stored. With exec enabled it plans the exec collection and
// sends it to the cluster's scanner. Errors are worth logging only; the
// inventory itself is stored.
func (s *Service) InventoryIngested(ctx context.Context, clusterID string, inv dto.K8sInventory) error {
	c, err := s.st.GetCluster(ctx, clusterID)
	if err != nil {
		return fmt.Errorf("scansvc: cluster %s: %w", clusterID, err)
	}
	if c.ScannerID == "" || !c.ExecEnabled {
		return nil
	}
	sc, err := s.scanner(ctx, c.ScannerID)
	if err != nil {
		return err
	}
	targets, err := s.plan(ctx, InventoryFromAPI(inv), kube.PlanOptions{})
	if err != nil || len(targets) == 0 {
		return err
	}
	err = s.dispatchExec(ctx, sc, c, targets)
	if errors.Is(err, ErrInFlight) {
		s.log.Info("exec collection not sent: another one is in flight", "cluster", c.ID)
		return nil
	}
	return err
}

// InventoryFromAPI converts an uploaded inventory back for planning. A
// container is running when it has a start time.
func InventoryFromAPI(in dto.K8sInventory) *kube.Inventory {
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	inv := &kube.Inventory{CollectedAt: in.CollectedAt, ServerVersion: in.ServerVersion}
	for _, w := range in.Workloads {
		inv.Workloads = append(inv.Workloads, kube.Workload{UID: str(w.Uid), Namespace: w.Namespace, Kind: w.Kind,
			Name: w.Name, Replicas: w.Replicas, ExcludedBy: str(w.ExcludedBy)})
	}
	for _, p := range in.Pods {
		kp := kube.Pod{UID: str(p.Uid), Namespace: p.Namespace, Name: p.Name, WorkloadKind: p.WorkloadKind,
			WorkloadName: p.WorkloadName, Node: p.Node, Phase: corev1.PodPhase(p.Phase)}
		if p.StartedAt != nil {
			kp.StartedAt = *p.StartedAt
		}
		for _, c := range p.Containers {
			kc := kube.Container{Name: c.Name, ImageRef: c.ImageRef, ImageDigest: str(c.ImageDigest),
				Ready: c.Ready != nil && *c.Ready, Running: c.StartedAt != nil}
			if c.StartedAt != nil {
				kc.StartedAt = *c.StartedAt
			}
			kp.Containers = append(kp.Containers, kc)
		}
		inv.Pods = append(inv.Pods, kp)
	}
	return inv
}
