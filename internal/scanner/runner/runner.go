// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package runner runs scan jobs: an SSH collection of one host, the
// inventory sync of a Kubernetes cluster and the exec collection of
// containers. It is shared by the scanner embedded in the server and the
// remote scanner; where the results go is the caller's Sink.
//
// Every Run function submits exactly one result for its job, also when the
// job fails or panics. The error a Run function returns is only about
// handing the result to the sink.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bomcensus/bomcensus/agentproto/dto"
	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/scanner/kube"
	"github.com/bomcensus/bomcensus/internal/scanner/ssh"
)

// Sink receives what a job produces.
type Sink interface {
	// SubmitReport hands over one encoded report (report.Encode) of the
	// job. It returns an error only when the report is lost; a report that
	// is queued for a later upload is not an error.
	SubmitReport(ctx context.Context, encoded []byte, jobID string) error
	// SubmitInventory hands over the inventory of a cluster.
	SubmitInventory(ctx context.Context, inv dto.K8sInventory) error
	// SubmitResult hands over the outcome of the job, after its reports.
	SubmitResult(ctx context.Context, jobID string, res Result) error
}

// ProbeSource returns the signed probe executable for a platform. The
// collectors verify the bytes before each transfer.
type ProbeSource func(ctx context.Context, os, arch string) ([]byte, error)

// Result is the outcome of a job in its wire form. For scan_ssh it carries
// the host key the target presented, in full (HostKey) and as fingerprint.
type Result struct {
	dto.ScanJobResult
}

// Reason codes start the message of a failed or partial result
// ("<code>: <detail>").
const (
	ReasonHostKeyChanged      = "host_key_changed"
	ReasonHostKeyUnavailable  = "host_key_unavailable"
	ReasonInvalidJob          = "invalid_job"
	ReasonConnectFailed       = "connect_failed"
	ReasonAuthFailed          = "auth_failed"
	ReasonUnsupportedPlatform = "unsupported_platform"
	ReasonProbeUnavailable    = "probe_unavailable"
	ReasonProbeRejected       = "probe_rejected"
	ReasonNoExecDir           = "no_exec_dir"
	ReasonReportTooLarge      = "report_too_large"
	ReasonTimeout             = "timeout"
	ReasonCanceled            = "canceled"
	ReasonCollectFailed       = "collect_failed"
	ReasonSubmitFailed        = "submit_failed"
	ReasonKubeClient          = "kube_client"
	ReasonSyncFailed          = "sync_failed"
	ReasonInternal            = "internal_error"
	ReasonSecret              = "secret_unavailable"
	ReasonBusy                = "scanner_busy"
	ReasonSudoFallback        = "sudo_fallback"
	ReasonPartialSections     = "partial_sections"
	ReasonSyncWarnings        = "sync_warnings"
	ReasonExecIncomplete      = "exec_incomplete"
)

// maxMessage bounds result messages.
const maxMessage = 1024

// Message formats a result message from a reason code and a detail.
func Message(reason, detail string) string {
	m := reason
	if detail != "" {
		m += ": " + detail
	}
	if len(m) > maxMessage {
		m = m[:maxMessage]
		for !utf8.ValidString(m) {
			m = m[:len(m)-1]
		}
	}
	return m
}

// ReasonOf returns the reason code at the start of a result message, or
// "" when there is none.
func ReasonOf(message string) string {
	code, _, _ := strings.Cut(message, ":")
	for _, r := range code {
		if (r < 'a' || r > 'z') && r != '_' {
			return ""
		}
	}
	return code
}

// Deps are the collaborators of the Run functions.
type Deps struct {
	Sink   Sink
	Probe  ProbeSource
	Logger *slog.Logger
	// KubeClient builds the Kubernetes client; nil uses kube.NewClient.
	KubeClient func(kube.Config) (*kube.Client, error)
	// AllowExternalKubeCredentials is passed to kube.Config: kubeconfigs may
	// run credential plugins or read local files. Only the operator of a
	// remote scanner turns it on.
	AllowExternalKubeCredentials bool
	// UserAgent of Kubernetes API requests.
	UserAgent string
	Now       func() time.Time

	// Replacements for tests.
	sshCollect  func(context.Context, ssh.Target, ssh.Deps) (*ssh.Result, error)
	kubeSync    func(context.Context, *kube.Client, kube.Filter) (*kube.Inventory, error)
	kubeCollect func(context.Context, *kube.Client, kube.ExecTarget, kube.Deps) (*report.Report, kube.ContainerOutcome, error)
}

func (d Deps) withDefaults() Deps {
	if d.Logger == nil {
		d.Logger = slog.New(slog.DiscardHandler)
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.KubeClient == nil {
		d.KubeClient = kube.NewClient
	}
	if d.UserAgent == "" {
		d.UserAgent = "bomcensus-scanner"
	}
	if d.sshCollect == nil {
		d.sshCollect = ssh.Collect
	}
	if d.kubeSync == nil {
		d.kubeSync = kube.Sync
	}
	if d.kubeCollect == nil {
		d.kubeCollect = kube.CollectContainer
	}
	return d
}

func (d Deps) probe() func(ctx context.Context, goos, arch string) ([]byte, error) {
	if d.Probe == nil {
		return func(context.Context, string, string) ([]byte, error) {
			return nil, errors.New("no probe source")
		}
	}
	return d.Probe
}

func (d Deps) kubeConfig(kubeconfig []byte) kube.Config {
	return kube.Config{Kubeconfig: kubeconfig, AllowExternalCredentials: d.AllowExternalKubeCredentials, UserAgent: d.UserAgent}
}

// newResult starts a result.
func newResult(started time.Time) Result {
	return Result{ScanJobResult: dto.ScanJobResult{StartedAt: started.UTC(), Status: dto.ScanJobStatusOk}}
}

func (r *Result) fail(reason, detail string) {
	r.Status = dto.ScanJobStatusFailed
	r.setMessage(Message(reason, detail))
}

func (r *Result) partial(reason, detail string) {
	if r.Status == dto.ScanJobStatusOk {
		r.Status = dto.ScanJobStatusPartial
	}
	r.setMessage(Message(reason, detail))
}

func (r *Result) setMessage(m string) {
	if r.Message != nil && *r.Message != "" {
		m = Message(*r.Message+"; "+m, "")
	}
	r.Message = &m
}

// submit finishes and hands over the result.
func submit(ctx context.Context, d Deps, jobID string, res *Result) error {
	res.FinishedAt = d.Now().UTC()
	if res.FinishedAt.Before(res.StartedAt) {
		res.FinishedAt = res.StartedAt
	}
	// The result is sent even when the job's context ended, so that the
	// server learns about the cancellation.
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	if err := d.Sink.SubmitResult(sctx, jobID, *res); err != nil {
		return fmt.Errorf("runner: submit result of job %s: %w", jobID, err)
	}
	return nil
}

// recovered turns a panic into an error with the stack logged.
func recovered(log *slog.Logger, job string, v any) error {
	log.Error("scan job panicked", "job_id", job, "panic", v, "stack", string(debug.Stack()))
	return fmt.Errorf("panic: %v", v)
}

func encodeReport(r *report.Report) ([]byte, error) {
	var buf bytes.Buffer
	if err := report.Encode(&buf, r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// PolicyFromAPI converts the policy of a directive.
func PolicyFromAPI(p dto.Policy) report.Policy {
	out := report.Policy{ExecVersion: p.ExecVersion, CollectCmdline: p.CollectCmdline, ScanContainers: p.ScanContainers}
	if p.ExcludePaths != nil {
		out.ExcludePaths = append([]string(nil), (*p.ExcludePaths)...)
	}
	if p.WalkPaths != nil {
		out.WalkPaths = append([]string(nil), (*p.WalkPaths)...)
	}
	if p.MaxRuntimeSeconds != nil {
		out.MaxRuntimeSeconds = *p.MaxRuntimeSeconds
	}
	if p.MemoryLimitMb != nil {
		out.MemoryLimitMB = *p.MemoryLimitMb
	}
	return out
}

// PolicyToAPI converts a policy to its directive form.
func PolicyToAPI(p report.Policy) dto.Policy {
	out := dto.Policy{ExecVersion: p.ExecVersion, CollectCmdline: p.CollectCmdline, ScanContainers: p.ScanContainers}
	if len(p.ExcludePaths) > 0 {
		ex := append([]string(nil), p.ExcludePaths...)
		out.ExcludePaths = &ex
	}
	if len(p.WalkPaths) > 0 {
		w := append([]string(nil), p.WalkPaths...)
		out.WalkPaths = &w
	}
	if p.MaxRuntimeSeconds > 0 {
		v := p.MaxRuntimeSeconds
		out.MaxRuntimeSeconds = &v
	}
	if p.MemoryLimitMB > 0 {
		v := p.MemoryLimitMB
		out.MemoryLimitMb = &v
	}
	return out
}

// errReason classifies context errors.
func ctxReason(err error) (string, bool) {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return ReasonTimeout, true
	case errors.Is(err, context.Canceled):
		return ReasonCanceled, true
	}
	return "", false
}
