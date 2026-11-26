// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package runner

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/bomcensus/bomcensus/agentproto/dto"
	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/scanner/kube"
)

// Default timeouts of Kubernetes jobs.
const (
	DefaultSyncTimeout = 10 * time.Minute
	DefaultExecTimeout = 2 * time.Hour
)

// K8sSyncJob reads the inventory of one cluster.
type K8sSyncJob struct {
	JobID     string
	ClusterID string
	// Kubeconfig is the kubeconfig file content; empty uses the in-cluster
	// service account.
	Kubeconfig []byte
	Filter     kube.Filter
	// Timeout bounds the sync; zero means DefaultSyncTimeout.
	Timeout time.Duration
}

// RunK8sSync reads the inventory of a cluster, submits it and then the
// result: ok, partial when some resources could not be read (the warnings
// are in the message) or failed. It returns the inventory when it was
// submitted, for planning the exec collection.
func RunK8sSync(ctx context.Context, job K8sSyncJob, d Deps) (inv *kube.Inventory, err error) {
	d = d.withDefaults()
	log := d.Logger.With("job_id", job.JobID, "cluster", job.ClusterID)
	start := d.Now()
	res := newResult(start)
	defer func() {
		if v := recover(); v != nil {
			inv = nil
			res = newResult(start)
			res.fail(ReasonInternal, recovered(log, job.JobID, v).Error())
		}
		err = submit(ctx, d, job.JobID, &res)
	}()
	inv = runK8sSync(ctx, job, d, &res, log)
	return inv, nil
}

func runK8sSync(ctx context.Context, job K8sSyncJob, d Deps, res *Result, log *slog.Logger) *kube.Inventory {
	if job.JobID == "" || job.ClusterID == "" {
		res.fail(ReasonInvalidJob, "job id and cluster are required")
		return nil
	}
	timeout := job.Timeout
	if timeout <= 0 {
		timeout = DefaultSyncTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c, err := d.KubeClient(d.kubeConfig(job.Kubeconfig))
	if err != nil {
		res.fail(ReasonKubeClient, err.Error())
		return nil
	}
	inv, err := d.kubeSync(ctx, c, job.Filter)
	if err != nil {
		reason, ok := ctxReason(err)
		if !ok {
			reason = ReasonSyncFailed
		}
		log.Warn("kubernetes sync failed", "error", err)
		res.fail(reason, err.Error())
		return nil
	}
	if err := d.Sink.SubmitInventory(ctx, inv.Payload(job.ClusterID, job.JobID)); err != nil {
		res.fail(ReasonSubmitFailed, err.Error())
		return nil
	}
	if len(inv.Warnings) > 0 {
		res.partial(ReasonSyncWarnings, strings.Join(inv.Warnings, "; "))
	}
	log.Info("kubernetes sync finished", "workloads", len(inv.Workloads), "pods", len(inv.Pods), "warnings", len(inv.Warnings))
	return inv
}

// K8sExecJob collects containers of one cluster through pods/exec.
type K8sExecJob struct {
	JobID      string
	ClusterID  string
	Kubeconfig []byte
	Targets    []kube.ExecTarget
	Policy     report.Policy
	// Limits bound concurrent exec sessions; zero fields take
	// kube.DefaultLimits.
	Limits kube.Limits
	// Timeout bounds the whole job; zero means DefaultExecTimeout.
	Timeout time.Duration
}

// RunK8sExec collects the targets within the limits. Each report is
// submitted as soon as its container is done (subject k8s_container); the
// result lists the outcome of every target and is ok when all succeeded,
// failed when none did and partial otherwise.
func RunK8sExec(ctx context.Context, job K8sExecJob, d Deps) (res Result, err error) {
	d = d.withDefaults()
	log := d.Logger.With("job_id", job.JobID, "cluster", job.ClusterID)
	start := d.Now()
	res = newResult(start)
	defer func() {
		if v := recover(); v != nil {
			res = newResult(start)
			res.fail(ReasonInternal, recovered(log, job.JobID, v).Error())
		}
		err = submit(ctx, d, job.JobID, &res)
	}()
	runK8sExec(ctx, job, d, &res, log)
	return res, nil
}

func runK8sExec(ctx context.Context, job K8sExecJob, d Deps, res *Result, log *slog.Logger) {
	if job.JobID == "" || job.ClusterID == "" {
		res.fail(ReasonInvalidJob, "job id and cluster are required")
		return
	}
	targets := []dto.ExecTargetResult{}
	res.Targets = &targets
	if len(job.Targets) == 0 {
		return
	}
	timeout := job.Timeout
	if timeout <= 0 {
		timeout = DefaultExecTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c, err := d.KubeClient(d.kubeConfig(job.Kubeconfig))
	if err != nil {
		res.fail(ReasonKubeClient, err.Error())
		for _, t := range job.Targets {
			targets = append(targets, failedTarget(t, ReasonKubeClient))
		}
		res.Targets = &targets
		return
	}
	kd := kube.Deps{ClusterID: job.ClusterID, Probe: d.probe(), Policy: job.Policy, Detectors: d.detectors(), Logger: d.Logger}
	collect := func(ctx context.Context, t kube.ExecTarget) (r *report.Report, o kube.ContainerOutcome, err error) {
		defer func() {
			if v := recover(); v != nil {
				r, err = nil, recovered(log, job.JobID, v)
				o = kube.ContainerOutcome{Coverage: dto.CoverageFailed, Reason: ReasonInternal, ExitCode: -1}
			}
		}()
		return d.kubeCollect(ctx, c, t, kd)
	}
	ok, failed := 0, 0
	done := func(r kube.Result) {
		tr := r.Outcome.Result(r.Target, "")
		if r.Report != nil {
			if err := submitContainer(ctx, d, job, r); err != nil {
				log.Warn("report of a container was not submitted", "namespace", r.Target.Namespace,
					"pod", r.Target.Pod, "container", r.Target.Container, "error", err)
				tr = failedTarget(r.Target, Message(ReasonSubmitFailed, err.Error()))
			}
		} else if r.Err != nil && (tr.Reason == nil || *tr.Reason == "") {
			reason := r.Err.Error()
			tr.Reason = &reason
		}
		switch tr.Status {
		case dto.ScanJobStatusOk:
			ok++
		case dto.ScanJobStatusFailed:
			failed++
		}
		targets = append(targets, tr)
	}
	runErr := kube.RunPlan(ctx, job.Targets, job.Limits, collect, done)
	res.Targets = &targets
	switch {
	case failed == len(targets):
		reason := ReasonExecIncomplete
		if r, ok := ctxReason(runErr); ok {
			reason = r
		}
		res.fail(reason, fmt.Sprintf("no container of %d collected", len(targets)))
	case ok < len(targets):
		res.partial(ReasonExecIncomplete, fmt.Sprintf("%d of %d containers collected fully", ok, len(targets)))
	}
	log.Info("kubernetes exec collection finished", "targets", len(targets), "ok", ok, "failed", failed)
}

func submitContainer(ctx context.Context, d Deps, job K8sExecJob, r kube.Result) error {
	t := r.Target
	r.Report.Subject = &report.Subject{Kind: report.SubjectK8sContainer, K8s: &report.K8sSubject{
		ClusterID: job.ClusterID, Namespace: t.Namespace, Pod: t.Pod, Container: t.Container,
		ImageRef: t.ImageRef, ImageDigest: t.ImageDigest,
	}}
	enc, err := encodeReport(r.Report)
	if err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	// Reports of finished containers are handed over even after the job's
	// deadline.
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
	defer cancel()
	return d.Sink.SubmitReport(sctx, enc, job.JobID)
}

func failedTarget(t kube.ExecTarget, reason string) dto.ExecTargetResult {
	return kube.ContainerOutcome{Coverage: dto.CoverageFailed, Reason: reason, ExitCode: -1}.Result(t, "")
}
