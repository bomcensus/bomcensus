// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package scansvc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"

	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/scanner/hpkebox"
	"github.com/bomcensus/bomcensus/internal/scanner/kube"
	"github.com/bomcensus/bomcensus/internal/scanner/runner"
	"github.com/bomcensus/bomcensus/internal/server/ingest"
	"github.com/bomcensus/bomcensus/internal/server/job"
	"github.com/bomcensus/bomcensus/internal/server/secret"
	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/internal/server/store/postgres"
)

var _ Store = (*postgres.DB)(nil)

const (
	digestKnown = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	digestNew   = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// fakeRunner stands in for the runner package. RunSSH submits a report and
// a result like the real one; gate, when set, holds every job until closed.
type fakeRunner struct {
	mu      sync.Mutex
	ssh     []runner.SSHJob
	syncs   []runner.K8sSyncJob
	execs   []runner.K8sExecJob
	gate    chan struct{}
	hostKey []byte
	sshRes  func(job runner.SSHJob) runner.Result // nil: ok with hostKey
	inv     *kube.Inventory
	done    chan string
}

func (f *fakeRunner) wait(ctx context.Context) {
	if f.gate != nil {
		select {
		case <-f.gate:
		case <-ctx.Done():
		}
	}
}

func (f *fakeRunner) finished(id string) {
	if f.done != nil {
		f.done <- id
	}
}

func (f *fakeRunner) RunSSH(ctx context.Context, j runner.SSHJob, d runner.Deps) (runner.Result, error) {
	f.mu.Lock()
	f.ssh = append(f.ssh, j)
	f.mu.Unlock()
	defer f.finished(j.JobID)
	f.wait(ctx)
	now := time.Now().UTC()
	key := f.hostKey
	res := runner.Result{ScanJobResult: agentapi.ScanJobResult{Status: agentapi.ScanJobStatusOk, StartedAt: now, FinishedAt: now, HostKey: &key}}
	if f.sshRes != nil {
		res = f.sshRes(j)
	}
	if res.Status != agentapi.ScanJobStatusFailed {
		r := &report.Report{SchemaVersion: report.SchemaVersion, CollectedAt: now,
			Subject: &report.Subject{Kind: report.SubjectScanTarget, ScanTargetID: j.TargetID},
			Host: &report.HostSection{SectionMeta: report.SectionMeta{Coverage: report.CoverageFull, CollectedAt: now},
				Hostname: "db-01", MachineID: "0123456789abcdef0123456789abcdef", Arch: "amd64"}}
		var buf bytes.Buffer
		if err := report.Encode(&buf, r); err != nil {
			return res, err
		}
		if err := d.Sink.SubmitReport(ctx, buf.Bytes(), j.JobID); err != nil {
			return res, err
		}
	}
	return res, d.Sink.SubmitResult(ctx, j.JobID, res)
}

func (f *fakeRunner) RunK8sSync(ctx context.Context, j runner.K8sSyncJob, d runner.Deps) (*kube.Inventory, error) {
	f.mu.Lock()
	f.syncs = append(f.syncs, j)
	f.mu.Unlock()
	defer f.finished(j.JobID)
	f.wait(ctx)
	now := time.Now().UTC()
	if err := d.Sink.SubmitInventory(ctx, f.inv.Payload(j.ClusterID, j.JobID)); err != nil {
		return nil, err
	}
	res := runner.Result{ScanJobResult: agentapi.ScanJobResult{Status: agentapi.ScanJobStatusOk, StartedAt: now, FinishedAt: now}}
	return f.inv, d.Sink.SubmitResult(ctx, j.JobID, res)
}

func (f *fakeRunner) RunK8sExec(ctx context.Context, j runner.K8sExecJob, d runner.Deps) (runner.Result, error) {
	f.mu.Lock()
	f.execs = append(f.execs, j)
	f.mu.Unlock()
	defer f.finished(j.JobID)
	now := time.Now().UTC()
	var targets []agentapi.ExecTargetResult
	for _, t := range j.Targets {
		targets = append(targets, kube.ContainerOutcome{Coverage: agentapi.CoverageUnsupported, Reason: "no shell"}.Result(t, ""))
	}
	res := runner.Result{ScanJobResult: agentapi.ScanJobResult{Status: agentapi.ScanJobStatusFailed, StartedAt: now, FinishedAt: now, Targets: &targets}}
	return res, d.Sink.SubmitResult(ctx, j.JobID, res)
}

func (f *fakeRunner) counts() (ssh, syncs, execs int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.ssh), len(f.syncs), len(f.execs)
}

type fixture struct {
	t      *testing.T
	ctx    context.Context
	db     *postgres.DB
	box    *secret.Box
	run    *fakeRunner
	svc    *Service
	cancel context.CancelFunc
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func newFixture(t *testing.T, embedded bool) *fixture {
	db := newTestDB(t)
	key := make([]byte, secret.KeySize)
	_, _ = rand.Read(key)
	box, err := secret.New(key)
	must(t, err)
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := gossh.NewSignerFromKey(hostPriv)
	f := &fixture{t: t, ctx: context.Background(), db: db, box: box,
		run: &fakeRunner{hostKey: signer.PublicKey().Marshal(), done: make(chan string, 16)}}
	f.svc, err = New(Config{Store: db, Ingest: ingest.New(db, nil, nil), Secrets: box, Runner: f.run, EmbeddedScanner: embedded})
	must(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	stopped := make(chan struct{})
	go func() { _ = f.svc.Run(ctx); close(stopped) }()
	t.Cleanup(func() { cancel(); <-stopped })
	return f
}

func (f *fixture) waitDone() string {
	f.t.Helper()
	select {
	case id := <-f.run.done:
		return id
	case <-time.After(10 * time.Second):
		f.t.Fatal("job did not finish")
		return ""
	}
}

// waitLease waits until the embedded goroutine released the lease.
func (f *fixture) waitLease(key string) {
	f.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		l, err := f.svc.leases.Get(f.ctx, key)
		must(f.t, err)
		if !l.Active(time.Now()) {
			return
		}
		if time.Now().After(deadline) {
			f.t.Fatal("lease not released")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (f *fixture) credential(kind store.CredentialKind, sec secret.CredentialSecret) store.Credential {
	f.t.Helper()
	id := newUUID(f.t)
	ct, err := f.box.SealCredential(id, sec)
	must(f.t, err)
	c, err := f.db.CreateCredential(f.ctx, store.Credential{ID: id, Name: "cred-" + randHex(4), Kind: kind, Username: "scan", Secret: ct})
	must(f.t, err)
	return c
}

func (f *fixture) target(scannerID string, interval int) store.ScanTarget {
	f.t.Helper()
	cred := f.credential(store.CredentialSSHPassword, secret.CredentialSecret{Password: "hunter2"})
	tg, err := f.db.CreateScanTarget(f.ctx, store.ScanTarget{Name: "db-" + randHex(4), Address: "10.0.0.9", Port: 22,
		CredentialID: cred.ID, ScannerID: scannerID, Sudo: true, IntervalMinutes: interval})
	must(f.t, err)
	return tg
}

// scanner creates an approved scanner with an HPKE key pair and returns
// the private key.
func (f *fixture) scanner() (store.Agent, []byte) {
	f.t.Helper()
	pub := make([]byte, 32)
	_, _ = rand.Read(pub)
	rk, err := f.db.CreateRegisterKey(f.ctx, store.RegisterKey{ID: randHex(5) + "x", Name: "scanners-" + randHex(3), PublicKey: pub,
		Target: store.AgentKindScanner, Approval: store.ApprovalAuto})
	must(f.t, err)
	priv, hpub, err := hpkebox.GenerateKey()
	must(f.t, err)
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	a, err := f.db.CreateAgent(f.ctx, store.Agent{Kind: store.AgentKindScanner, Hostname: "scanner", IdentityKey: id,
		HPKEPublicKey: hpub, State: store.AgentApproved, RegisterKeyID: rk.ID})
	must(f.t, err)
	return a, priv
}

func (f *fixture) pending(agentID string) []store.Directive {
	f.t.Helper()
	ds, err := f.db.ListPendingDirectives(f.ctx, agentID, time.Now(), 0)
	must(f.t, err)
	return ds
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	const hexd = "0123456789abcdef"
	out := make([]byte, 0, 2*n)
	for _, c := range b {
		out = append(out, hexd[c>>4], hexd[c&15])
	}
	return string(out)
}

func newUUID(t *testing.T) string {
	t.Helper()
	h := randHex(16)
	return h[:8] + "-" + h[8:12] + "-4" + h[13:16] + "-a" + h[17:20] + "-" + h[20:32]
}

// ── tests ───────────────────────────────────────────────────────────────

func TestJobIDs(t *testing.T) {
	id := newJobID(kindSSH, "0190-ab")
	k, s, ok := parseJobID(id)
	if !ok || k != kindSSH || s != "0190-ab" {
		t.Fatalf("parse %q: %s %s %v", id, k, s, ok)
	}
	for _, bad := range []string{"", "ssh", "ssh.x", "ssh..abc", "other.x.abc", "ssh.x."} {
		if _, _, ok := parseJobID(bad); ok {
			t.Errorf("parsed %q", bad)
		}
	}
}

func TestEmbeddedScheduleNoDoubleRunAndPinning(t *testing.T) {
	f := newFixture(t, true)
	f.run.gate = make(chan struct{})
	tg := f.target("", 60)
	f.target("", 0) // on demand only: never scheduled

	must(t, f.svc.ScheduleSSH(f.ctx))
	must(t, f.svc.ScheduleSSH(f.ctx))
	if err := f.svc.RequestRun(f.ctx, tg.ID); !errors.Is(err, ErrInFlight) || !errors.Is(err, store.ErrConflict) {
		t.Fatalf("run while in flight: %v", err)
	}
	close(f.run.gate)
	f.waitDone()
	f.waitLease(leaseKey(kindSSH, tg.ID))
	if n, _, _ := f.run.counts(); n != 1 {
		t.Fatalf("ssh runs: %d", n)
	}
	j := f.run.ssh[0]
	if j.Credential.Password != "hunter2" || j.User != "scan" || !j.Sudo || j.HostKey != nil || !j.Policy.ExecVersion {
		t.Fatalf("job %+v", j)
	}
	got, err := f.db.GetScanTarget(f.ctx, tg.ID)
	must(t, err)
	if !bytes.Equal(got.HostKey, f.run.hostKey) {
		t.Fatal("host key not pinned on first success")
	}
	if got.LastRun == nil || got.LastRun.Result != store.ScanOK || got.AssetID == "" {
		t.Fatalf("run not recorded: %+v", got)
	}
	// Not due again within the interval.
	must(t, f.svc.ScheduleSSH(f.ctx))
	time.Sleep(50 * time.Millisecond)
	if n, _, _ := f.run.counts(); n != 1 {
		t.Fatalf("ssh runs after the first: %d", n)
	}

	// The next run carries the pinned key; a mismatch is recorded as a
	// failure and leaves the pin alone.
	f.run.sshRes = func(j runner.SSHJob) runner.Result {
		m := runner.Message(runner.ReasonHostKeyChanged, "offered SHA256:x")
		now := time.Now().UTC()
		return runner.Result{ScanJobResult: agentapi.ScanJobResult{Status: agentapi.ScanJobStatusFailed, Message: &m, StartedAt: now, FinishedAt: now}}
	}
	must(t, f.svc.RequestRun(f.ctx, tg.ID))
	f.waitDone()
	f.waitLease(leaseKey(kindSSH, tg.ID))
	if !bytes.Equal(f.run.ssh[1].HostKey, f.run.hostKey) {
		t.Fatal("pinned key not passed to the run")
	}
	got, err = f.db.GetScanTarget(f.ctx, tg.ID)
	must(t, err)
	if got.LastRun.Result != store.ScanFailed || runner.ReasonOf(got.LastRun.Message) != runner.ReasonHostKeyChanged {
		t.Fatalf("mismatch not recorded: %+v", got.LastRun)
	}
	if !bytes.Equal(got.HostKey, f.run.hostKey) {
		t.Fatal("pin changed")
	}

	// A successful run that saw another key than the pinned one is refused.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	os, _ := gossh.NewSignerFromKey(other)
	f.run.sshRes = func(runner.SSHJob) runner.Result {
		now := time.Now().UTC()
		k := os.PublicKey().Marshal()
		return runner.Result{ScanJobResult: agentapi.ScanJobResult{Status: agentapi.ScanJobStatusOk, StartedAt: now, FinishedAt: now, HostKey: &k}}
	}
	must(t, f.svc.RequestRun(f.ctx, tg.ID))
	f.waitDone()
	f.waitLease(leaseKey(kindSSH, tg.ID))
	got, _ = f.db.GetScanTarget(f.ctx, tg.ID)
	if got.LastRun.Result != store.ScanFailed || runner.ReasonOf(got.LastRun.Message) != runner.ReasonHostKeyChanged {
		t.Fatalf("unpinned key accepted: %+v", got.LastRun)
	}
}

func TestEmbeddedOff(t *testing.T) {
	f := newFixture(t, false)
	tg := f.target("", 60)
	if err := f.svc.RequestRun(f.ctx, tg.ID); !errors.Is(err, ErrNoScanner) || !errors.Is(err, store.ErrInvalidState) {
		t.Fatalf("run: %v", err)
	}
	cl, err := f.db.CreateCluster(f.ctx, store.K8sClusterConfig{Name: "c", Connection: store.K8sInCluster})
	must(t, err)
	if err := f.svc.RequestSync(f.ctx, cl.ID); !errors.Is(err, ErrNoScanner) {
		t.Fatalf("sync: %v", err)
	}
	must(t, f.svc.ScheduleSSH(f.ctx))
	must(t, f.svc.ScheduleK8s(f.ctx))
	time.Sleep(50 * time.Millisecond)
	if a, b, c := f.run.counts(); a+b+c != 0 {
		t.Fatal("embedded work ran while the embedded scanner is off")
	}
	if err := f.svc.RequestRun(f.ctx, "00000000-0000-4000-a000-000000000000"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown target: %v", err)
	}
}

func TestRemoteSSHDispatch(t *testing.T) {
	f := newFixture(t, true)
	sc, priv := f.scanner()
	other, _ := f.scanner()
	tg := f.target(sc.ID, 60)

	must(t, f.svc.ScheduleSSH(f.ctx))
	must(t, f.svc.ScheduleSSH(f.ctx))
	ds := f.pending(sc.ID)
	if len(ds) != 1 || ds[0].Type != "scan_ssh" {
		t.Fatalf("pending: %+v", ds)
	}
	if n, _, _ := f.run.counts(); n != 0 {
		t.Fatal("remote target ran embedded")
	}
	var d agentapi.ScanSshDirective
	must(t, json.Unmarshal(ds[0].Payload, &d))
	if d.ScanTargetId != tg.ID || d.Address != "10.0.0.9" || d.Username != "scan" || !d.Sudo || d.HostKeyFingerprint != nil || d.HostKey != nil {
		t.Fatalf("directive %+v", d)
	}
	// The credential opens only with this scanner's key, job and field.
	plain, err := hpkebox.Open(priv, d.Credential, hpkebox.SecretInfo(sc.ID, d.JobId, "credential"))
	must(t, err)
	var cs agentapi.SSHCredentialSecret
	must(t, json.Unmarshal(plain, &cs))
	if cs.Kind != agentapi.SshPassword || cs.Password == nil || *cs.Password != "hunter2" {
		t.Fatalf("secret %+v", cs)
	}
	otherPriv, _, _ := hpkebox.GenerateKey()
	if _, err := hpkebox.Open(otherPriv, d.Credential, hpkebox.SecretInfo(sc.ID, d.JobId, "credential")); err == nil {
		t.Fatal("opened with another key")
	}
	if _, err := hpkebox.Open(priv, d.Credential, hpkebox.SecretInfo(other.ID, d.JobId, "credential")); err == nil {
		t.Fatal("opened for another scanner")
	}

	// Acknowledged but not finished: still in flight.
	_, err = f.db.AckDirectives(f.ctx, sc.ID, []string{ds[0].ID}, time.Now())
	must(t, err)
	must(t, f.svc.ScheduleSSH(f.ctx))
	if err := f.svc.RequestRun(f.ctx, tg.ID); !errors.Is(err, ErrInFlight) {
		t.Fatalf("run while in flight: %v", err)
	}
	if len(f.pending(sc.ID)) != 0 {
		t.Fatal("dispatched twice")
	}

	// Results: another scanner is refused, unknown jobs are not found.
	now := time.Now().UTC()
	fp := gossh.FingerprintSHA256(mustKey(t, f.run.hostKey))
	res := agentapi.ScanJobResult{Status: agentapi.ScanJobStatusOk, StartedAt: now.Add(-time.Second), FinishedAt: now, HostKeyFingerprint: &fp}
	if err := f.svc.RecordJobResult(f.ctx, other, d.JobId, res); err == nil || !isPermanent(err) {
		t.Fatalf("result from another scanner: %v", err)
	}
	if err := f.svc.RecordJobResult(f.ctx, sc, "nope", res); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown job: %v", err)
	}
	// Only the fingerprint: nothing is pinned.
	must(t, f.svc.RecordJobResult(f.ctx, sc, d.JobId, res))
	if got, _ := f.db.GetScanTarget(f.ctx, tg.ID); got.HostKey != nil {
		t.Fatal("pinned from a fingerprint")
	}
	// With the full key the first successful result pins it.
	wire := f.run.hostKey
	res.HostKey = &wire
	must(t, f.svc.RecordJobResult(f.ctx, sc, d.JobId, res))
	got, _ := f.db.GetScanTarget(f.ctx, tg.ID)
	if !bytes.Equal(got.HostKey, f.run.hostKey) || got.LastRun == nil || got.LastRun.Result != store.ScanOK {
		t.Fatalf("result not applied: %+v", got)
	}

	// Lease released: the next request sends a directive carrying the pin.
	must(t, f.svc.RequestRun(f.ctx, tg.ID))
	ds = f.pending(sc.ID)
	if len(ds) != 1 {
		t.Fatalf("pending after result: %d", len(ds))
	}
	must(t, json.Unmarshal(ds[0].Payload, &d))
	if d.HostKeyFingerprint == nil || *d.HostKeyFingerprint != fp || d.HostKey == nil || !bytes.Equal(*d.HostKey, f.run.hostKey) {
		t.Fatal("pinned key not in the directive")
	}
	// A fingerprint that differs from the pin fails the run.
	bad := "SHA256:AAAA"
	res.HostKeyFingerprint, res.HostKey = &bad, nil
	must(t, f.svc.RecordJobResult(f.ctx, sc, d.JobId, res))
	got, _ = f.db.GetScanTarget(f.ctx, tg.ID)
	if got.LastRun.Result != store.ScanFailed || runner.ReasonOf(got.LastRun.Message) != runner.ReasonHostKeyChanged {
		t.Fatalf("mismatch not recorded: %+v", got.LastRun)
	}
}

func mustKey(t *testing.T, wire []byte) gossh.PublicKey {
	k, err := gossh.ParsePublicKey(wire)
	must(t, err)
	return k
}

func isPermanent(err error) bool {
	var p interface{ Permanent() bool }
	return errors.As(err, &p) && p.Permanent()
}

func testInventory() *kube.Inventory {
	now := time.Now().UTC().Truncate(time.Second)
	pod := func(name, digest string) kube.Pod {
		return kube.Pod{UID: "u-" + name, Namespace: "prod", Name: name, WorkloadKind: kube.KindDeployment, WorkloadName: "web",
			Node: "n1", Phase: corev1.PodRunning, StartedAt: now,
			Containers: []kube.Container{{Name: "app", ImageRef: "web:1", ImageDigest: digest, Ready: true, Running: true, StartedAt: now}}}
	}
	return &kube.Inventory{
		CollectedAt: now, ServerVersion: "v1.31.0",
		Namespaces: []kube.Namespace{{Name: "prod"}},
		Workloads: []kube.Workload{
			{UID: "w1", Namespace: "prod", Kind: kube.KindDeployment, Name: "web", Replicas: 2},
			{UID: "w2", Namespace: "prod", Kind: kube.KindDeployment, Name: "api", Replicas: 1},
		},
		Pods: []kube.Pod{pod("web-a", digestKnown), pod("web-b", digestKnown),
			func() kube.Pod { p := pod("api-a", digestNew); p.WorkloadName = "api"; return p }()},
	}
}

func (f *fixture) knownImage() {
	f.t.Helper()
	_, err := f.db.PutImageContent(f.ctx, store.ImageContent{Digest: digestKnown, Coverage: store.CoverageFull, CollectedAt: time.Now()})
	must(f.t, err)
}

func sectionsOf(ts []kube.ExecTarget) map[string]string {
	out := map[string]string{}
	for _, t := range ts {
		out[t.Pod] = strings.Join(t.Sections, ",")
	}
	return out
}

func TestEmbeddedSyncPlansExec(t *testing.T) {
	f := newFixture(t, true)
	f.knownImage()
	f.run.inv = testInventory()
	cl, err := f.db.CreateCluster(f.ctx, store.K8sClusterConfig{Name: "prd", Connection: store.K8sInCluster, ExecEnabled: true,
		Filter: store.K8sFilter{NSExclude: []string{"kube-*"}}})
	must(t, err)
	must(t, f.svc.ScheduleK8s(f.ctx))
	f.waitDone() // sync
	f.waitDone() // exec
	f.waitLease(leaseKey(kindSync, cl.ID))
	_, syncs, execs := f.run.counts()
	if syncs != 1 || execs != 1 {
		t.Fatalf("syncs %d execs %d", syncs, execs)
	}
	if f.run.syncs[0].Kubeconfig != nil || len(f.run.syncs[0].Filter.NamespaceExclude) != 1 {
		t.Fatalf("sync job %+v", f.run.syncs[0])
	}
	got := sectionsOf(f.run.execs[0].Targets)
	// The known digest gets processes only; the new one a full collection.
	if got["web-a"] != "processes" || got["web-b"] != "processes" || !strings.Contains(got["api-a"], "packages") {
		t.Fatalf("plan %v", got)
	}
	c, err := f.db.GetCluster(f.ctx, cl.ID)
	must(t, err)
	if c.LastSync == nil || c.Workloads != 2 {
		t.Fatalf("inventory not stored: %+v", c)
	}
	pod, err := f.db.GetPod(f.ctx, cl.ID, "prod", "api-a")
	must(t, err)
	if len(pod.Containers) != 1 || pod.Containers[0].Coverage != store.CoverageUnsupported {
		t.Fatalf("coverage of a failed container not recorded: %+v", pod.Containers)
	}
	// Synced just now: not due.
	must(t, f.svc.ScheduleK8s(f.ctx))
	time.Sleep(50 * time.Millisecond)
	if _, syncs, _ := f.run.counts(); syncs != 1 {
		t.Fatalf("synced again within the interval: %d", syncs)
	}
	// A short interval from the settings makes it due again.
	must(t, f.db.PutSetting(f.ctx, SettingK8s, json.RawMessage(`{"syncIntervalMinutes":1}`)))
	if got := f.svc.syncInterval(f.ctx); got != time.Minute {
		t.Fatalf("interval %v", got)
	}
}

func TestRemoteK8s(t *testing.T) {
	f := newFixture(t, true)
	f.knownImage()
	sc, priv := f.scanner()
	kc := f.credential(store.CredentialKubeconfig, secret.CredentialSecret{Kubeconfig: "apiVersion: v1\nkind: Config\n"})
	cl, err := f.db.CreateCluster(f.ctx, store.K8sClusterConfig{Name: "edge", Connection: store.K8sKubeconfig, CredentialID: kc.ID,
		ScannerID: sc.ID, ExecEnabled: true})
	must(t, err)

	must(t, f.svc.ScheduleK8s(f.ctx))
	must(t, f.svc.ScheduleK8s(f.ctx))
	ds := f.pending(sc.ID)
	if len(ds) != 1 || ds[0].Type != "k8s_sync" {
		t.Fatalf("pending %+v", ds)
	}
	var sd agentapi.K8sSyncDirective
	must(t, json.Unmarshal(ds[0].Payload, &sd))
	if sd.ClusterId != cl.ID || !sd.ExecEnabled || sd.Connection != agentapi.Kubeconfig || sd.Kubeconfig == nil {
		t.Fatalf("directive %+v", sd)
	}
	plain, err := hpkebox.Open(priv, *sd.Kubeconfig, hpkebox.SecretInfo(sc.ID, sd.JobId, "kubeconfig"))
	must(t, err)
	if !strings.HasPrefix(string(plain), "apiVersion") {
		t.Fatal("kubeconfig not sealed")
	}
	if _, err := hpkebox.Open(priv, *sd.Kubeconfig, hpkebox.SecretInfo(sc.ID, sd.JobId, "credential")); err == nil {
		t.Fatal("kubeconfig opens as another field")
	}

	// The scanner uploads the inventory; the upload path calls the hook.
	inv := testInventory().Payload(cl.ID, sd.JobId)
	scSender := ingest.Sender{AgentID: sc.ID, Kind: store.AgentKindScanner}
	must(t, ingest.New(f.db, nil, nil).IngestK8sInventory(f.ctx, scSender, cl.ID, inv))
	must(t, f.svc.InventoryIngested(f.ctx, cl.ID, inv))
	ds = f.pending(sc.ID)
	if len(ds) != 2 || ds[1].Type != "k8s_exec" {
		t.Fatalf("pending %+v", ds)
	}
	var ed agentapi.K8sExecDirective
	must(t, json.Unmarshal(ds[1].Payload, &ed))
	ts := make([]kube.ExecTarget, 0, len(ed.Targets))
	for _, et := range ed.Targets {
		if et.Node == nil || *et.Node != "n1" {
			t.Fatalf("target without node: %+v", et)
		}
		ts = append(ts, kube.TargetFromAPI(et))
	}
	if got := sectionsOf(ts); got["web-a"] != "processes" || !strings.Contains(got["api-a"], "packages") {
		t.Fatalf("plan %v", got)
	}
	if _, err := hpkebox.Open(priv, *ed.Kubeconfig, hpkebox.SecretInfo(sc.ID, ed.JobId, "kubeconfig")); err != nil {
		t.Fatal(err)
	}
	// A second inventory does not send a second exec while one is in flight.
	must(t, f.svc.InventoryIngested(f.ctx, cl.ID, inv))
	if len(f.pending(sc.ID)) != 2 {
		t.Fatal("exec dispatched twice")
	}

	// Sync failure is recorded on the cluster; exec results set coverage.
	now := time.Now().UTC()
	m := "sync_failed: forbidden"
	must(t, f.svc.RecordJobResult(f.ctx, sc, sd.JobId, agentapi.ScanJobResult{Status: agentapi.ScanJobStatusFailed, Message: &m,
		StartedAt: now, FinishedAt: now.Add(time.Second)}))
	c, _ := f.db.GetCluster(f.ctx, cl.ID)
	if c.SyncStatus != store.K8sSyncFailed || c.SyncMessage != m {
		t.Fatalf("sync status %s %q", c.SyncStatus, c.SyncMessage)
	}
	reason := "no shell"
	targets := []agentapi.ExecTargetResult{{Namespace: "prod", Pod: "api-a", Container: "app", Status: agentapi.ScanJobStatusFailed,
		Coverage: agentapi.CoverageUnsupported, Reason: &reason}}
	must(t, f.svc.RecordJobResult(f.ctx, sc, ed.JobId, agentapi.ScanJobResult{Status: agentapi.ScanJobStatusFailed,
		StartedAt: now, FinishedAt: now, Targets: &targets}))
	pod, err := f.db.GetPod(f.ctx, cl.ID, "prod", "api-a")
	must(t, err)
	if pod.Containers[0].Coverage != store.CoverageUnsupported || pod.Containers[0].CoverageReason != reason {
		t.Fatalf("coverage %+v", pod.Containers[0])
	}
	// Exec lease released by the result.
	l, err := f.svc.leases.Get(f.ctx, leaseKey(kindExec, cl.ID))
	must(t, err)
	if l.Active(time.Now()) {
		t.Fatal("exec lease still held")
	}
}

func TestRequestCollect(t *testing.T) {
	f := newFixture(t, true)
	tg := f.target("", 0)
	must(t, f.svc.RequestRun(f.ctx, tg.ID))
	f.waitDone()
	f.waitLease(leaseKey(kindSSH, tg.ID))
	got, _ := f.db.GetScanTarget(f.ctx, tg.ID)
	if got.AssetID == "" {
		t.Fatal("no asset for the target")
	}
	must(t, f.svc.RequestCollect(f.ctx, got.AssetID))
	f.waitDone()
	if n, _, _ := f.run.counts(); n != 2 {
		t.Fatalf("collect of a scan target asset: %d runs", n)
	}

	cl, err := f.db.CreateCluster(f.ctx, store.K8sClusterConfig{Name: "prd", Connection: store.K8sInCluster, ExecEnabled: true})
	must(t, err)
	f.run.inv = testInventory()
	must(t, f.svc.RequestSync(f.ctx, cl.ID))
	f.waitDone()
	f.waitDone()
	f.waitLease(leaseKey(kindSync, cl.ID))
	ws, _, err := f.db.ListWorkloads(f.ctx, cl.ID, store.WorkloadFilter{}, store.Page{})
	must(t, err)
	var web store.K8sWorkloadRow
	for _, w := range ws {
		if w.Name == "web" {
			web = w
		}
	}
	must(t, f.svc.RequestCollect(f.ctx, web.AssetID))
	f.waitDone()
	_, _, execs := f.run.counts()
	if execs != 2 {
		t.Fatalf("execs %d", execs)
	}
	sec := sectionsOf(f.run.execs[1].Targets)
	// Requested collection: one full collection even for a known image.
	full := 0
	for pod, s := range sec {
		if !strings.HasPrefix(pod, "web-") {
			t.Fatalf("collected another workload: %s", pod)
		}
		if strings.Contains(s, "packages") {
			full++
		}
	}
	if len(sec) != 2 || full != 1 {
		t.Fatalf("targets %v", sec)
	}

	must(t, f.db.PutSetting(f.ctx, "unused", json.RawMessage(`{}`)))
	cl2, err := f.db.UpdateCluster(f.ctx, cl.ID, store.K8sClusterConfig{Name: "prd", Connection: store.K8sInCluster})
	must(t, err)
	if err := f.svc.RequestCollect(f.ctx, web.AssetID); !errors.Is(err, ErrExecDisabled) {
		t.Fatalf("exec disabled on %s: %v", cl2.ID, err)
	}
}

func TestRegister(t *testing.T) {
	db := newTestDB(t)
	key := make([]byte, secret.KeySize)
	box, _ := secret.New(key)
	q := job.NewMemory(nil)
	_, err := New(Config{Store: db, Ingest: ingest.New(db, nil, nil), Secrets: box, Queue: q})
	must(t, err)
	if err := q.Register(job.KindScanSSHDue, func(context.Context, job.Job) error { return nil }); err == nil {
		t.Fatal("scan_ssh_due not registered")
	}
}
