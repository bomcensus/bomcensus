// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package scansvc schedules agentless collection: SSH scans of scan targets
// and the inventory sync and exec collection of Kubernetes clusters.
//
// Work for a target or cluster without a scanner runs in this process (the
// embedded scanner) through internal/scanner/runner; work for one assigned
// to a remote scanner becomes a directive with its secrets sealed to that
// scanner's HPKE key. Results of remote scanners come back through
// RecordJobResult and InventoryIngested and are applied the same way as
// those of the embedded scanner.
//
// A job id is "<kind>.<subject id>.<random>" with kind ssh, sync or exec,
// so a result can be routed without a job table. At most one job per
// subject and kind is in flight (store.ScanLeases, directive dedupe keys
// and the embedded worker pool).
package scansvc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/scanner/hpkebox"
	"github.com/bomcensus/bomcensus/internal/scanner/kube"
	"github.com/bomcensus/bomcensus/internal/scanner/runner"
	"github.com/bomcensus/bomcensus/internal/scanner/ssh"
	serveragent "github.com/bomcensus/bomcensus/internal/server/agentapi"
	"github.com/bomcensus/bomcensus/internal/server/ingest"
	"github.com/bomcensus/bomcensus/internal/server/job"
	"github.com/bomcensus/bomcensus/internal/server/secret"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// Errors of the request methods. They wrap store.ErrInvalidState (shown as
// 409 "cannot be done now") or store.ErrConflict (409 "already running").
var (
	ErrNoScanner          = fmt.Errorf("scansvc: no scanner available: %w", store.ErrInvalidState)
	ErrScannerUnavailable = fmt.Errorf("scansvc: the assigned scanner cannot take work: %w", store.ErrInvalidState)
	ErrExecDisabled       = fmt.Errorf("scansvc: exec collection is disabled for the cluster: %w", store.ErrInvalidState)
	ErrNotCollectable     = fmt.Errorf("scansvc: the asset cannot be collected by a scanner: %w", store.ErrInvalidState)
	ErrInFlight           = fmt.Errorf("scansvc: a job for this subject is already in flight: %w", store.ErrConflict)
	ErrBusy               = fmt.Errorf("scansvc: the embedded scanner is busy: %w", store.ErrConflict)
)

// Job kinds inside job ids.
const (
	kindSSH  = "ssh"
	kindSync = "sync"
	kindExec = "exec"
)

// Settings.
const (
	// SettingK8s is the settings key (store.Settings, table settings) of
	// the server-wide Kubernetes options, a K8sSettings document such as
	// {"syncIntervalMinutes": 15}. It applies to every cluster and every
	// replica and is read on each scheduler run, so a change takes effect
	// within a minute. There is no admin API for it; it is written with
	// PutSetting (or SQL).
	SettingK8s = "k8s"
	// DefaultSyncIntervalMinutes applies when the setting is absent,
	// unreadable or below 1.
	DefaultSyncIntervalMinutes = 15
)

// K8sSettings is the document under SettingK8s.
type K8sSettings struct {
	// SyncIntervalMinutes is the time between inventory syncs of a
	// cluster, counted from its last stored inventory or sync attempt.
	SyncIntervalMinutes int `json:"syncIntervalMinutes"`
}

// Timing.
const (
	// SchedulerInterval is the period of the scan_ssh_due and k8s_sync_due
	// jobs.
	SchedulerInterval = time.Minute
	// DirectiveTTL bounds how long a directive waits for an offline
	// scanner.
	DirectiveTTL = time.Hour
	leaseGrace   = 5 * time.Minute
)

// Store is what the service reads and writes. *postgres.DB implements it.
type Store interface {
	store.ScanLeases
	GetSetting(ctx context.Context, key string) (json.RawMessage, error)
	GetScanTarget(ctx context.Context, id string) (store.ScanTarget, error)
	ListDueScanTargets(ctx context.Context, scannerID string, now time.Time, limit int) ([]store.ScanTarget, error)
	SetScanTargetHostKey(ctx context.Context, id string, key []byte) error
	RecordScanRun(ctx context.Context, id string, run store.ScanRun) error
	GetCredentialWithSecret(ctx context.Context, id string) (store.Credential, error)
	GetCluster(ctx context.Context, id string) (store.K8sCluster, error)
	ListClusters(ctx context.Context, f store.ClusterFilter, p store.Page) ([]store.K8sClusterRow, int, error)
	RecordClusterSync(ctx context.Context, id string, status store.K8sSyncStatus, message string, at time.Time) error
	SetPodContainerCoverage(ctx context.Context, clusterID, namespace, pod, container string, coverage store.Coverage, reason string) error
	KnownImageContent(ctx context.Context, digests []string) ([]string, error)
	GetAgent(ctx context.Context, id string) (store.Agent, error)
	ListAgents(ctx context.Context, f store.AgentFilter, p store.Page) ([]store.Agent, int, error)
	GetAsset(ctx context.Context, id string) (store.AssetDetail, error)
	ListWorkloadPods(ctx context.Context, workloadID string, f store.PodFilter, p store.Page) ([]store.K8sPod, int, error)
	EnqueueDirective(ctx context.Context, d store.Directive) (store.Directive, bool, error)
	GoSymbolQueryFor(ctx context.Context, assetID, container string) (store.GoSymbolQuery, error)
	ClusterGoSymbolQueries(ctx context.Context, clusterID string) ([]store.WorkloadGoSymbolQuery, error)
}

// Ingester applies what scanners produce (*ingest.Service).
type Ingester interface {
	IngestReport(ctx context.Context, sender ingest.Sender, raw []byte) error
	IngestK8sInventory(ctx context.Context, sender ingest.Sender, clusterID string, inv agentapi.K8sInventory) error
	RecordScanResult(ctx context.Context, sender ingest.Sender, targetID string, res ingest.ScanResult) error
}

// Notifier wakes the long poll of an agent (*dispatch.Service).
type Notifier interface {
	Notify(agentID string)
}

// CredentialOpener decrypts stored credentials (*secret.Box).
type CredentialOpener interface {
	OpenCredential(id string, ciphertext []byte) (secret.CredentialSecret, error)
}

// ProbeFunc returns the probe for a platform and its version
// ((*updatesvc.Service).Probe).
type ProbeFunc func(ctx context.Context, os, arch string) ([]byte, string, error)

// Runner runs jobs of the embedded scanner. DefaultRunner calls the
// runner package.
type Runner interface {
	RunSSH(ctx context.Context, job runner.SSHJob, d runner.Deps) (runner.Result, error)
	RunK8sSync(ctx context.Context, job runner.K8sSyncJob, d runner.Deps) (*kube.Inventory, error)
	RunK8sExec(ctx context.Context, job runner.K8sExecJob, d runner.Deps) (runner.Result, error)
}

// DefaultRunner is the Runner of the runner package.
type DefaultRunner struct{}

// RunSSH implements Runner.
func (DefaultRunner) RunSSH(ctx context.Context, j runner.SSHJob, d runner.Deps) (runner.Result, error) {
	return runner.RunSSH(ctx, j, d)
}

// RunK8sSync implements Runner.
func (DefaultRunner) RunK8sSync(ctx context.Context, j runner.K8sSyncJob, d runner.Deps) (*kube.Inventory, error) {
	return runner.RunK8sSync(ctx, j, d)
}

// RunK8sExec implements Runner.
func (DefaultRunner) RunK8sExec(ctx context.Context, j runner.K8sExecJob, d runner.Deps) (runner.Result, error) {
	return runner.RunK8sExec(ctx, j, d)
}

// Config configures New.
type Config struct {
	Store   Store
	Ingest  Ingester
	Notify  Notifier
	Secrets CredentialOpener
	// Probe serves the embedded scanner; nil fails its collections.
	Probe ProbeFunc
	// Queue, when set, gets the handlers and periodic schedules of
	// job.KindScanSSHDue and job.KindK8sSyncDue. It must not be started.
	Queue job.Queue
	// Runner defaults to DefaultRunner.
	Runner Runner
	// EmbeddedScanner runs work without an assigned scanner in this
	// process. When false that work is refused (ErrNoScanner) and skipped
	// by the schedulers.
	EmbeddedScanner bool
	// Workers bounds concurrent embedded jobs (default 4); Backlog bounds
	// the queued ones (default 64).
	Workers int
	Backlog int
	// ExecLimits bound concurrent exec sessions of one embedded job.
	ExecLimits kube.Limits
	Logger     *slog.Logger
	Now        func() time.Time
}

// Service schedules and dispatches scan jobs.
type Service struct {
	st       Store
	ing      Ingester
	notify   Notifier
	secrets  CredentialOpener
	probe    ProbeFunc
	leases   leases
	run      Runner
	embedded bool
	limits   kube.Limits
	log      *slog.Logger
	now      func() time.Time
	pool     *runner.Pool

	// mu serializes taking a lease and enqueuing its directive.
	mu sync.Mutex
}

// New returns a service. With cfg.Queue it registers the scheduler jobs.
func New(cfg Config) (*Service, error) {
	if cfg.Store == nil || cfg.Ingest == nil || cfg.Secrets == nil {
		return nil, errors.New("scansvc: Store, Ingest and Secrets are required")
	}
	s := &Service{
		st: cfg.Store, ing: cfg.Ingest, notify: cfg.Notify, secrets: cfg.Secrets, probe: cfg.Probe,
		run: cfg.Runner, embedded: cfg.EmbeddedScanner, limits: cfg.ExecLimits,
		log: cfg.Logger, now: cfg.Now,
	}
	if s.run == nil {
		s.run = DefaultRunner{}
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.now == nil {
		s.now = time.Now
	}
	s.leases = leases{st: cfg.Store, now: s.now}
	if s.notify == nil {
		s.notify = noNotify{}
	}
	workers, backlog := cfg.Workers, cfg.Backlog
	if workers <= 0 {
		workers = 4
	}
	if backlog <= 0 {
		backlog = 64
	}
	s.pool = runner.NewPool(workers, backlog, s.log)
	if cfg.Queue != nil {
		if err := s.Register(cfg.Queue); err != nil {
			return nil, err
		}
	}
	return s, nil
}

type noNotify struct{}

func (noNotify) Notify(string) {}

// Register adds the scheduler handlers and their periodic schedules to q.
// New calls it when Config.Queue is set.
func (s *Service) Register(q job.Queue) error {
	if err := q.Register(job.KindScanSSHDue, func(ctx context.Context, _ job.Job) error { return s.ScheduleSSH(ctx) }); err != nil {
		return fmt.Errorf("scansvc: register %s: %w", job.KindScanSSHDue, err)
	}
	if err := q.Register(job.KindK8sSyncDue, func(ctx context.Context, _ job.Job) error { return s.ScheduleK8s(ctx) }); err != nil {
		return fmt.Errorf("scansvc: register %s: %w", job.KindK8sSyncDue, err)
	}
	if err := q.Periodic(job.KindScanSSHDue, SchedulerInterval, job.ScanSSHDueArgs{}, job.MaxAttempts(1)); err != nil {
		return fmt.Errorf("scansvc: schedule %s: %w", job.KindScanSSHDue, err)
	}
	if err := q.Periodic(job.KindK8sSyncDue, SchedulerInterval, job.K8sSyncDueArgs{}, job.MaxAttempts(1)); err != nil {
		return fmt.Errorf("scansvc: schedule %s: %w", job.KindK8sSyncDue, err)
	}
	return nil
}

// Run waits for ctx to end, then cancels the running embedded jobs and
// waits up to 30 seconds for them to report.
func (s *Service) Run(ctx context.Context) error {
	<-ctx.Done()
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := s.pool.Close(cctx); err != nil {
		s.log.Warn("embedded scan jobs did not stop in time", "error", err)
	}
	return nil
}

// ── job ids ─────────────────────────────────────────────────────────────

func newJobID(kind, subject string) string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return kind + "." + subject + "." + hex.EncodeToString(b[:])
}

// parseJobID splits a job id made by newJobID.
func parseJobID(id string) (kind, subject string, ok bool) {
	kind, rest, ok := strings.Cut(id, ".")
	if !ok {
		return "", "", false
	}
	i := strings.LastIndexByte(rest, '.')
	if i <= 0 || i == len(rest)-1 {
		return "", "", false
	}
	switch kind {
	case kindSSH, kindSync, kindExec:
		return kind, rest[:i], true
	}
	return "", "", false
}

func leaseKey(kind, subject string) string { return kind + ":" + subject }

// ── helpers ─────────────────────────────────────────────────────────────

// permanentError is answered with 400 by the agent API.
type permanentError struct{ err error }

func (e *permanentError) Error() string   { return e.err.Error() }
func (e *permanentError) Unwrap() error   { return e.err }
func (e *permanentError) Permanent() bool { return true }

func forbidden(format string, args ...any) error {
	return &permanentError{fmt.Errorf("scansvc: "+format, args...)}
}

// policy is the collection policy configured for agents.
func (s *Service) policy(ctx context.Context) report.Policy {
	p := report.DefaultPolicy()
	raw, err := s.st.GetSetting(ctx, serveragent.SettingCollectPolicy)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.log.Warn("cannot read the collection policy, using the default", "error", err)
		}
		return p
	}
	var cp serveragent.CollectPolicy
	if err := json.Unmarshal(raw, &cp); err != nil || cp.Policy == nil {
		return p
	}
	return runner.PolicyFromAPI(*cp.Policy)
}

func (s *Service) syncInterval(ctx context.Context) time.Duration {
	raw, err := s.st.GetSetting(ctx, SettingK8s)
	if err == nil {
		var k K8sSettings
		if json.Unmarshal(raw, &k) == nil && k.SyncIntervalMinutes >= 1 {
			return time.Duration(k.SyncIntervalMinutes) * time.Minute
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		s.log.Warn("cannot read the kubernetes settings, using the default sync interval", "error", err)
	}
	return DefaultSyncIntervalMinutes * time.Minute
}

func (s *Service) probeSource() runner.ProbeSource {
	return func(ctx context.Context, os, arch string) ([]byte, error) {
		if s.probe == nil {
			return nil, errors.New("no release with a probe is available")
		}
		b, _, err := s.probe(ctx, os, arch)
		return b, err
	}
}

func (s *Service) deps(sink runner.Sink) runner.Deps {
	return runner.Deps{Sink: sink, Probe: s.probeSource(), Logger: s.log, Now: s.now, UserAgent: "bomcensus-server"}
}

// scanner returns the approved scanner with a usable encryption key.
func (s *Service) scanner(ctx context.Context, id string) (store.Agent, error) {
	a, err := s.st.GetAgent(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return a, fmt.Errorf("scanner %s does not exist: %w", id, ErrScannerUnavailable)
	}
	if err != nil {
		return a, fmt.Errorf("scansvc: get scanner %s: %w", id, err)
	}
	switch {
	case a.Kind != store.AgentKindScanner:
		return a, fmt.Errorf("agent %s is not a scanner: %w", id, ErrScannerUnavailable)
	case a.State != store.AgentApproved:
		return a, fmt.Errorf("scanner %s is %s: %w", id, a.State, ErrScannerUnavailable)
	}
	if err := hpkebox.CheckPublicKey(a.HPKEPublicKey); err != nil {
		return a, fmt.Errorf("scanner %s has no usable encryption key: %w", id, ErrScannerUnavailable)
	}
	return a, nil
}

// scanners lists the approved scanners.
func (s *Service) scanners(ctx context.Context) ([]store.Agent, error) {
	var out []store.Agent
	for off := 0; ; {
		page, total, err := s.st.ListAgents(ctx, store.AgentFilter{Kind: store.AgentKindScanner}, store.Page{Limit: 1000, Offset: off})
		if err != nil {
			return nil, fmt.Errorf("scansvc: list scanners: %w", err)
		}
		for _, a := range page {
			if a.State == store.AgentApproved {
				out = append(out, a)
			}
		}
		off += len(page)
		if len(page) == 0 || off >= total {
			return out, nil
		}
	}
}

// seal encrypts a directive secret to the scanner.
func seal(sc store.Agent, jobID, field string, plaintext []byte) ([]byte, error) {
	out, err := hpkebox.Seal(sc.HPKEPublicKey, plaintext, hpkebox.SecretInfo(sc.ID, jobID, field))
	if err != nil {
		return nil, fmt.Errorf("scansvc: seal %s for scanner %s: %w", field, sc.ID, err)
	}
	return out, nil
}

// submitDirective takes the lease of the job and queues its directive for
// the scanner. When a directive with the same dedupe key is still pending,
// that one stays and the lease passes to its job.
func (s *Service) submitDirective(ctx context.Context, sc store.Agent, lease, dedupe, jobID string, body agentapi.Directive, jobTimeout time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	until := now.Add(DirectiveTTL + jobTimeout + leaseGrace)
	ok, err := s.leases.Acquire(ctx, lease, jobID, now, until)
	if err != nil {
		return err
	}
	if !ok {
		return ErrInFlight
	}
	typ, _ := body.Discriminator()
	payload, err := directivePayload(body)
	if err != nil {
		_ = s.leases.Release(ctx, lease, jobID)
		return err
	}
	exp := now.Add(DirectiveTTL)
	out, created, err := s.st.EnqueueDirective(ctx, store.Directive{AgentID: sc.ID, Type: typ, Payload: payload,
		DedupeKey: dedupe, CreatedAt: now, ExpiresAt: &exp})
	if err != nil {
		_ = s.leases.Release(ctx, lease, jobID)
		return fmt.Errorf("scansvc: enqueue %s for %s: %w", typ, sc.ID, err)
	}
	if !created {
		var prev struct {
			JobID string `json:"job_id"`
		}
		_ = json.Unmarshal(out.Payload, &prev)
		_ = s.leases.Release(ctx, lease, jobID)
		if prev.JobID != "" {
			if _, err := s.leases.Acquire(ctx, lease, prev.JobID, now, until); err != nil {
				return err
			}
		}
		return ErrInFlight
	}
	s.notify.Notify(sc.ID)
	s.log.Info("scan job sent to scanner", "type", typ, "job_id", jobID, "scanner", sc.ID)
	return nil
}

// directivePayload is the stored form of a directive: its JSON object
// without the id (see dispatch.Payload).
func directivePayload(d agentapi.Directive) (json.RawMessage, error) {
	raw, err := d.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("scansvc: encode directive: %w", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, fmt.Errorf("scansvc: directive is not a JSON object: %w", store.ErrInvalid)
	}
	delete(m, "id")
	return json.Marshal(m)
}

// startEmbedded takes the lease and queues fn on the embedded pool. The
// lease is renewed while fn runs and released when it returns.
func (s *Service) startEmbedded(ctx context.Context, lease, jobID string, fn func(ctx context.Context)) error {
	if !s.embedded {
		return ErrNoScanner
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pool.InFlight(lease) {
		return ErrInFlight
	}
	now := s.now().UTC()
	ok, err := s.leases.Acquire(ctx, lease, jobID, now, now.Add(embeddedLeaseTTL))
	if err != nil {
		return err
	}
	if !ok {
		return ErrInFlight
	}
	err = s.pool.Submit(lease, func(ctx context.Context) {
		// The lease is renewed from the start: the job may wait for a
		// worker longer than the lease lasts.
		release := s.keepLease(ctx, lease, jobID)
		defer release()
		fn(ctx)
	})
	if err != nil {
		_ = s.leases.Release(ctx, lease, jobID)
		switch {
		case errors.Is(err, runner.ErrInFlight):
			return ErrInFlight
		case errors.Is(err, runner.ErrPoolFull), errors.Is(err, runner.ErrPoolClosed):
			return ErrBusy
		}
		return err
	}
	return nil
}

// ignorable are request errors a scheduler only logs at debug level.
func ignorable(err error) bool {
	return errors.Is(err, ErrInFlight) || errors.Is(err, ErrBusy)
}

func sshTimeout() time.Duration { return ssh.DefaultTimeout }
