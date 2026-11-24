// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/bomcensus/bomcensus/internal/agent/core"
	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/report/reportapi"
	"github.com/bomcensus/bomcensus/internal/scanner/hpkebox"
	"github.com/bomcensus/bomcensus/internal/scanner/kube"
	"github.com/bomcensus/bomcensus/internal/scanner/runner"
	"github.com/bomcensus/bomcensus/internal/sign"
)

// Directive types handled by the scanner.
const (
	directiveScanSSH = "scan_ssh"
	directiveK8sSync = "k8s_sync"
	directiveK8sExec = "k8s_exec"
)

// jobRunner runs jobs; the runner package outside tests.
type jobRunner interface {
	RunSSH(ctx context.Context, job runner.SSHJob, d runner.Deps) (runner.Result, error)
	RunK8sSync(ctx context.Context, job runner.K8sSyncJob, d runner.Deps) (*kube.Inventory, error)
	RunK8sExec(ctx context.Context, job runner.K8sExecJob, d runner.Deps) (runner.Result, error)
}

type packageRunner struct{}

func (packageRunner) RunSSH(ctx context.Context, j runner.SSHJob, d runner.Deps) (runner.Result, error) {
	return runner.RunSSH(ctx, j, d)
}

func (packageRunner) RunK8sSync(ctx context.Context, j runner.K8sSyncJob, d runner.Deps) (*kube.Inventory, error) {
	return runner.RunK8sSync(ctx, j, d)
}

func (packageRunner) RunK8sExec(ctx context.Context, j runner.K8sExecJob, d runner.Deps) (runner.Result, error) {
	return runner.RunK8sExec(ctx, j, d)
}

// scanner handles the scan directives. Each job is opened (its secrets
// decrypted) on the poll loop and run on the pool.
type scanner struct {
	agentID func() string
	key     []byte // HPKE private key
	deps    runner.Deps
	pool    *runner.Pool
	run     jobRunner
	log     *slog.Logger
}

// register installs the directive handlers.
func (s *scanner) register(rt interface {
	Handle(string, core.DirectiveHandler)
}) {
	rt.Handle(directiveScanSSH, s.handleScanSSH)
	rt.Handle(directiveK8sSync, s.handleK8sSync)
	rt.Handle(directiveK8sExec, s.handleK8sExec)
}

// open decrypts a sealed directive secret bound to this scanner, the job
// and the field.
func (s *scanner) open(sealed []byte, jobID, field string) ([]byte, error) {
	return hpkebox.Open(s.key, sealed, hpkebox.SecretInfo(s.agentID(), jobID, field))
}

// reject reports a job that is not run.
func (s *scanner) reject(ctx context.Context, jobID, reason string, cause error) {
	s.log.Warn("scan job not run", "job_id", jobID, "reason", reason, "error", cause)
	now := time.Now().UTC()
	m := runner.Message(reason, cause.Error())
	res := runner.Result{ScanJobResult: agentapi.ScanJobResult{Status: agentapi.ScanJobStatusFailed, Message: &m,
		StartedAt: now, FinishedAt: now}}
	if err := s.deps.Sink.SubmitResult(ctx, jobID, res); err != nil {
		s.log.Warn("cannot report the rejected job", "job_id", jobID, "error", err)
	}
}

// start queues a job. A job for a subject that is still running, or one
// that does not fit the backlog, is reported as failed so that the server
// can schedule it again.
func (s *scanner) start(ctx context.Context, key, jobID string, fn func(ctx context.Context)) {
	if err := s.pool.Submit(key, fn); err != nil {
		s.reject(ctx, jobID, runner.ReasonBusy, err)
	}
}

func (s *scanner) handleScanSSH(ctx context.Context, d agentapi.Directive) error {
	sd, err := d.AsScanSshDirective()
	if err != nil {
		return fmt.Errorf("decode scan_ssh: %w", err)
	}
	if sd.JobId == "" {
		return errors.New("scan_ssh without job id")
	}
	plain, err := s.open(sd.Credential, sd.JobId, "credential")
	if err != nil {
		s.reject(ctx, sd.JobId, runner.ReasonSecret, err)
		return nil
	}
	var cs agentapi.SSHCredentialSecret
	err = json.Unmarshal(plain, &cs)
	clear(plain)
	if err != nil {
		s.reject(ctx, sd.JobId, runner.ReasonSecret, fmt.Errorf("decode credential: %w", err))
		return nil
	}
	job := runner.SSHJob{
		JobID: sd.JobId, TargetID: sd.ScanTargetId, Address: sd.Address, Port: sd.Port, User: sd.Username,
		Sudo: sd.Sudo, Policy: runner.PolicyFromAPI(sd.Policy), GoSymbols: reportapi.GoSymbolQueryPtr(sd.GoSymbols),
	}
	if sd.HostKey != nil {
		job.HostKey = *sd.HostKey
	}
	if sd.HostKeyFingerprint != nil {
		job.HostKeyFingerprint = *sd.HostKeyFingerprint
	}
	if cs.PrivateKey != nil {
		job.Credential.PrivateKey = []byte(*cs.PrivateKey)
	}
	if cs.Passphrase != nil {
		job.Credential.Passphrase = []byte(*cs.Passphrase)
	}
	if cs.Password != nil {
		job.Credential.Password = *cs.Password
	}
	if sd.Sections != nil {
		for _, sec := range *sd.Sections {
			job.Sections = append(job.Sections, string(sec))
		}
	}
	s.start(ctx, "ssh:"+sd.ScanTargetId, sd.JobId, func(ctx context.Context) {
		defer clear(job.Credential.PrivateKey)
		defer clear(job.Credential.Passphrase)
		if _, err := s.run.RunSSH(ctx, job, s.deps); err != nil {
			s.log.Warn("ssh job result not delivered", "job_id", job.JobID, "error", err)
		}
	})
	return nil
}

// kubeconfig opens the sealed kubeconfig of a kubeconfig connection; nil
// means in-cluster.
func (s *scanner) kubeconfig(conn agentapi.K8sConnection, sealed *[]byte, jobID string) ([]byte, error) {
	switch conn {
	case agentapi.InCluster:
		return nil, nil
	case agentapi.Kubeconfig:
		if sealed == nil {
			return nil, errors.New("kubeconfig connection without kubeconfig")
		}
		return s.open(*sealed, jobID, "kubeconfig")
	}
	return nil, fmt.Errorf("unknown connection %q", conn)
}

func (s *scanner) handleK8sSync(ctx context.Context, d agentapi.Directive) error {
	sd, err := d.AsK8sSyncDirective()
	if err != nil {
		return fmt.Errorf("decode k8s_sync: %w", err)
	}
	if sd.JobId == "" {
		return errors.New("k8s_sync without job id")
	}
	kc, err := s.kubeconfig(sd.Connection, sd.Kubeconfig, sd.JobId)
	if err != nil {
		s.reject(ctx, sd.JobId, runner.ReasonSecret, err)
		return nil
	}
	job := runner.K8sSyncJob{JobID: sd.JobId, ClusterID: sd.ClusterId, Kubeconfig: kc, Filter: kube.FilterFromAPI(sd.Filter)}
	s.start(ctx, "sync:"+sd.ClusterId, sd.JobId, func(ctx context.Context) {
		defer clear(kc)
		if _, err := s.run.RunK8sSync(ctx, job, s.deps); err != nil {
			s.log.Warn("sync job result not delivered", "job_id", job.JobID, "error", err)
		}
	})
	return nil
}

func (s *scanner) handleK8sExec(ctx context.Context, d agentapi.Directive) error {
	ed, err := d.AsK8sExecDirective()
	if err != nil {
		return fmt.Errorf("decode k8s_exec: %w", err)
	}
	if ed.JobId == "" {
		return errors.New("k8s_exec without job id")
	}
	kc, err := s.kubeconfig(ed.Connection, ed.Kubeconfig, ed.JobId)
	if err != nil {
		s.reject(ctx, ed.JobId, runner.ReasonSecret, err)
		return nil
	}
	job := runner.K8sExecJob{JobID: ed.JobId, ClusterID: ed.ClusterId, Kubeconfig: kc, Policy: runner.PolicyFromAPI(ed.Policy)}
	for _, t := range ed.Targets {
		kt := kube.TargetFromAPI(t)
		if t.Node != nil {
			// The per-node limit of the exec plan needs the node.
			kt.Node = *t.Node
		}
		job.Targets = append(job.Targets, kt)
	}
	s.start(ctx, "exec:"+ed.ClusterId, ed.JobId, func(ctx context.Context) {
		defer clear(kc)
		if _, err := s.run.RunK8sExec(ctx, job, s.deps); err != nil {
			s.log.Warn("exec job result not delivered", "job_id", job.JobID, "error", err)
		}
	})
	return nil
}

// ── sink ────────────────────────────────────────────────────────────────

// reportSubmitter queues reports for upload (*core.Runtime).
type reportSubmitter interface {
	SubmitReport(ctx context.Context, encoded []byte, meta core.ReportMeta) error
}

// clientSink delivers reports through the runtime's spool and inventories
// and results through the signed client.
type clientSink struct {
	reports reportSubmitter
	client  func() *agentapi.ClientWithResponses
	log     *slog.Logger
	// retryWait is the pause between result attempts.
	retryWait time.Duration
}

// SubmitReport implements runner.Sink. A failed upload leaves the report in
// the spool, which is retried later, so it is not an error.
func (c *clientSink) SubmitReport(ctx context.Context, encoded []byte, jobID string) error {
	if err := c.reports.SubmitReport(ctx, encoded, core.ReportMeta{JobID: jobID}); err != nil {
		c.log.Warn("report upload deferred", "job_id", jobID, "error", err)
	}
	return nil
}

// SubmitInventory implements runner.Sink.
func (c *clientSink) SubmitInventory(ctx context.Context, inv agentapi.K8sInventory) error {
	resp, err := c.client().UploadK8sInventoryWithResponse(ctx, inv)
	if err != nil {
		return fmt.Errorf("upload inventory: %w", err)
	}
	return core.DecodeResponse(resp.HTTPResponse, resp.Body, http.StatusNoContent, nil)
}

// SubmitResult implements runner.Sink. Temporary failures are retried a
// few times.
func (c *clientSink) SubmitResult(ctx context.Context, jobID string, res runner.Result) error {
	body, err := json.Marshal(res)
	if err != nil {
		return err
	}
	var last error
	for attempt := range 4 {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return errors.Join(last, ctx.Err())
			case <-time.After(c.retryWait * time.Duration(attempt)):
			}
		}
		resp, err := c.client().SubmitScanJobResultWithBodyWithResponse(ctx, jobID, "application/json", bytes.NewReader(body))
		if err == nil {
			err = core.DecodeResponse(resp.HTTPResponse, resp.Body, http.StatusNoContent, nil)
		}
		if err == nil {
			return nil
		}
		last = fmt.Errorf("submit result of %s: %w", jobID, err)
		var api *core.APIError
		if errors.As(err, &api) && api.Status >= 400 && api.Status < 500 && api.Status != http.StatusConflict &&
			api.Status != http.StatusTooManyRequests {
			return last
		}
	}
	return last
}

// ── probe ───────────────────────────────────────────────────────────────

// probeCache downloads probes from the server and keeps the last one per
// platform in memory, keyed by its version. An entry is reused until it is
// older than ttl; then the probe is downloaded again and replaces the entry
// when its version differs. Bytes that fail verification are never cached.
// The collectors verify the bytes again before each transfer.
type probeCache struct {
	client func() *agentapi.ClientWithResponses
	verify func([]byte) error
	ttl    time.Duration
	now    func() time.Time

	mu      sync.Mutex
	entries map[string]probeEntry
}

type probeEntry struct {
	version string
	data    []byte
	checked time.Time
}

func newProbeCache(client func() *agentapi.ClientWithResponses) *probeCache {
	return &probeCache{client: client, verify: sign.VerifyELF, ttl: 10 * time.Minute, now: time.Now, entries: map[string]probeEntry{}}
}

// Get is a runner.ProbeSource.
func (p *probeCache) Get(ctx context.Context, goos, arch string) ([]byte, error) {
	key := goos + "/" + arch
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[key]
	if ok && p.now().Sub(e.checked) < p.ttl {
		return e.data, nil
	}
	resp, err := p.client().DownloadProbeWithResponse(ctx, agentapi.TargetOs(goos), agentapi.TargetArch(arch))
	if err == nil {
		err = core.DecodeResponse(resp.HTTPResponse, resp.Body, http.StatusOK, nil)
	}
	if err != nil {
		if ok {
			// Keep using the verified probe while the server is unreachable.
			return e.data, nil
		}
		return nil, fmt.Errorf("download probe for %s: %w", key, err)
	}
	version := resp.HTTPResponse.Header.Get("Bomcensus-Probe-Version")
	if ok && version != "" && version == e.version {
		e.checked = p.now()
		p.entries[key] = e
		return e.data, nil
	}
	if err := p.verify(resp.Body); err != nil {
		return nil, fmt.Errorf("probe %s for %s: %w", version, key, err)
	}
	p.entries[key] = probeEntry{version: version, data: resp.Body, checked: p.now()}
	return resp.Body, nil
}
