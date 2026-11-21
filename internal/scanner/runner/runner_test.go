// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package runner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/scanner/kube"
	"github.com/bomcensus/bomcensus/internal/scanner/ssh"
)

type fakeSink struct {
	mu          sync.Mutex
	reports     []*report.Report
	jobs        []string
	inventories []agentapi.K8sInventory
	results     map[string]Result
	reportErr   error
}

func newSink() *fakeSink { return &fakeSink{results: map[string]Result{}} }

func (s *fakeSink) SubmitReport(_ context.Context, enc []byte, jobID string) error {
	if s.reportErr != nil {
		return s.reportErr
	}
	r, err := report.Decode(bytes.NewReader(enc))
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reports = append(s.reports, r)
	s.jobs = append(s.jobs, jobID)
	return nil
}

func (s *fakeSink) SubmitInventory(_ context.Context, inv agentapi.K8sInventory) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inventories = append(s.inventories, inv)
	return nil
}

func (s *fakeSink) SubmitResult(_ context.Context, jobID string, res Result) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.results[jobID]; dup {
		return errors.New("result submitted twice")
	}
	s.results[jobID] = res
	return nil
}

func hostKey(t *testing.T) gossh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func sampleReport() *report.Report {
	return &report.Report{
		SchemaVersion: report.SchemaVersion,
		CollectedAt:   time.Unix(1700000000, 0).UTC(),
		Subject:       &report.Subject{Kind: report.SubjectSelf},
		Host:          &report.HostSection{SectionMeta: report.SectionMeta{Coverage: report.CoverageFull}, Hostname: "db-01"},
		Packages:      &report.PackagesSection{SectionMeta: report.SectionMeta{Coverage: report.CoverageFull}},
	}
}

func msg(r Result) string {
	if r.Message == nil {
		return ""
	}
	return *r.Message
}

func TestRunSSHSuccess(t *testing.T) {
	key := hostKey(t).PublicKey()
	sink := newSink()
	var got ssh.Target
	d := Deps{Sink: sink, sshCollect: func(_ context.Context, tg ssh.Target, _ ssh.Deps) (*ssh.Result, error) {
		got = tg
		return &ssh.Result{Report: sampleReport(), HostKey: key.Marshal(), Duration: time.Second}, nil
	}}
	job := SSHJob{JobID: "j1", TargetID: "t1", Address: "10.0.0.9", Port: 2222, User: "scan",
		Credential: SSHCredential{Password: "pw"}, Sudo: true, Sections: []string{"packages"},
		Policy: report.DefaultPolicy()}
	res, err := RunSSH(context.Background(), job, d)
	if err != nil {
		t.Fatal(err)
	}
	if got.Address != "10.0.0.9" || got.Port != 2222 || got.User != "scan" || got.Auth.Password != "pw" ||
		!got.Sudo || got.HostKey != nil || len(got.Request.Sections) != 1 || !got.Request.Policy.ExecVersion {
		t.Fatalf("target not built from job: %+v", got)
	}
	if res.Status != agentapi.ScanJobStatusOk || res.HostKey == nil || !bytes.Equal(*res.HostKey, key.Marshal()) ||
		res.HostKeyFingerprint == nil || *res.HostKeyFingerprint != gossh.FingerprintSHA256(key) {
		t.Fatalf("result: %+v", res)
	}
	if len(sink.reports) != 1 || sink.jobs[0] != "j1" {
		t.Fatalf("reports: %d", len(sink.reports))
	}
	s := sink.reports[0].Subject
	if s == nil || s.Kind != report.SubjectScanTarget || s.ScanTargetID != "t1" {
		t.Fatalf("subject: %+v", s)
	}
	if _, ok := sink.results["j1"]; !ok {
		t.Fatal("no result submitted")
	}
	if res.FinishedAt.Before(res.StartedAt) {
		t.Fatal("finished before started")
	}
}

func TestRunSSHPartial(t *testing.T) {
	rep := sampleReport()
	rep.Packages.Coverage = report.CoveragePartial
	sink := newSink()
	d := Deps{Sink: sink, sshCollect: func(context.Context, ssh.Target, ssh.Deps) (*ssh.Result, error) {
		return &ssh.Result{Report: rep, SudoFallback: "sudo asks for a password"}, nil
	}}
	res, _ := RunSSH(context.Background(), SSHJob{JobID: "j", TargetID: "t", Address: "a", User: "u", Sudo: true}, d)
	if res.Status != agentapi.ScanJobStatusPartial {
		t.Fatalf("status %s", res.Status)
	}
	if m := msg(res); !strings.Contains(m, ReasonSudoFallback) || !strings.Contains(m, "packages") {
		t.Fatalf("message %q", m)
	}
}

func TestRunSSHFailures(t *testing.T) {
	key := hostKey(t).PublicKey()
	other := hostKey(t).PublicKey()
	cases := []struct {
		name   string
		job    func(*SSHJob)
		err    error
		reason string
	}{
		{"host key changed", func(j *SSHJob) { j.HostKey = key.Marshal() },
			&ssh.HostKeyChangedError{Address: "a:22", Fingerprint: gossh.FingerprintSHA256(other), Key: other.Marshal()}, ReasonHostKeyChanged},
		{"fingerprint only", func(j *SSHJob) { j.HostKeyFingerprint = gossh.FingerprintSHA256(key) }, nil, ReasonHostKeyUnavailable},
		{"fingerprint mismatch", func(j *SSHJob) {
			j.HostKey = key.Marshal()
			j.HostKeyFingerprint = gossh.FingerprintSHA256(other)
		}, nil, ReasonHostKeyUnavailable},
		{"probe rejected", nil, ssh.ErrProbeRejected, ReasonProbeRejected},
		{"no exec dir", nil, ssh.ErrNoExecDir, ReasonNoExecDir},
		{"timeout", nil, context.DeadlineExceeded, ReasonTimeout},
		{"auth", nil, errors.New("ssh: handshake failed: ssh: unable to authenticate"), ReasonAuthFailed},
		{"connect", nil, &net.OpError{Op: "dial", Err: errors.New("refused")}, ReasonConnectFailed},
		{"invalid", func(j *SSHJob) { j.Address = "" }, nil, ReasonInvalidJob},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sink := newSink()
			called := false
			d := Deps{Sink: sink, sshCollect: func(context.Context, ssh.Target, ssh.Deps) (*ssh.Result, error) {
				called = true
				if c.err == nil {
					return &ssh.Result{Report: sampleReport()}, nil
				}
				return nil, c.err
			}}
			job := SSHJob{JobID: "j", TargetID: "t", Address: "a", User: "u"}
			if c.job != nil {
				c.job(&job)
			}
			res, err := RunSSH(context.Background(), job, d)
			if err != nil {
				t.Fatal(err)
			}
			if res.Status != agentapi.ScanJobStatusFailed || ReasonOf(msg(res)) != c.reason {
				t.Fatalf("status %s message %q, want reason %s", res.Status, msg(res), c.reason)
			}
			if c.err == nil && called {
				t.Fatal("collected although the job is not runnable")
			}
			if len(sink.reports) != 0 || len(sink.results) != 1 {
				t.Fatalf("reports %d results %d", len(sink.reports), len(sink.results))
			}
			if c.reason == ReasonHostKeyChanged && (res.HostKey == nil || !bytes.Equal(*res.HostKey, other.Marshal()) ||
				*res.HostKeyFingerprint != gossh.FingerprintSHA256(other)) {
				t.Fatal("the offered key is not reported")
			}
		})
	}
}

func TestRunSSHPanicContained(t *testing.T) {
	sink := newSink()
	d := Deps{Sink: sink, sshCollect: func(context.Context, ssh.Target, ssh.Deps) (*ssh.Result, error) {
		panic("boom")
	}}
	res, err := RunSSH(context.Background(), SSHJob{JobID: "j", TargetID: "t", Address: "a", User: "u"}, d)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != agentapi.ScanJobStatusFailed || ReasonOf(msg(res)) != ReasonInternal || len(sink.results) != 1 {
		t.Fatalf("result %+v", res)
	}
}

// handshakeServer accepts SSH connections with key as host key and refuses
// every login. It is enough to see the host key check of the real client.
func handshakeServer(t *testing.T, key gossh.Signer) (addr string, logins *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	logins = new(atomic.Int64)
	cfg := &gossh.ServerConfig{PasswordCallback: func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error) {
		logins.Add(1)
		return nil, errors.New("denied")
	}}
	cfg.AddHostKey(key)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _, _, _ = gossh.NewServerConn(c, cfg)
			}()
		}
	}()
	return ln.Addr().String(), logins
}

func TestRunSSHRealHostKeyMismatch(t *testing.T) {
	served := hostKey(t)
	pinned := hostKey(t).PublicKey()
	addr, logins := handshakeServer(t, served)
	host, port, _ := net.SplitHostPort(addr)
	var p int
	for _, ch := range port {
		p = p*10 + int(ch-'0')
	}
	sink := newSink()
	job := SSHJob{JobID: "j", TargetID: "t", Address: host, Port: p, User: "u",
		Credential: SSHCredential{Password: "secret"}, HostKey: pinned.Marshal(), Timeout: 20 * time.Second}
	res, err := RunSSH(context.Background(), job, Deps{Sink: sink})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != agentapi.ScanJobStatusFailed || ReasonOf(msg(res)) != ReasonHostKeyChanged {
		t.Fatalf("status %s message %q", res.Status, msg(res))
	}
	if *res.HostKeyFingerprint != gossh.FingerprintSHA256(served.PublicKey()) {
		t.Fatal("offered key not reported")
	}
	if logins.Load() != 0 {
		t.Fatal("the password was sent to a host with the wrong key")
	}
}

func TestReasonOf(t *testing.T) {
	for in, want := range map[string]string{
		"host_key_changed: x": ReasonHostKeyChanged,
		"timeout":             ReasonTimeout,
		"Some error: x":       "",
		"":                    "",
	} {
		if got := ReasonOf(in); got != want {
			t.Errorf("ReasonOf(%q) = %q, want %q", in, got, want)
		}
	}
	long := Message("x", strings.Repeat("é", 2000))
	if len(long) > maxMessage || !strings.HasPrefix(long, "x: ") {
		t.Fatal("message not bounded")
	}
}

func TestPolicyConversion(t *testing.T) {
	p := report.Policy{ExecVersion: true, ExcludePaths: []string{"/data"}, MaxRuntimeSeconds: 60, MemoryLimitMB: 64}
	back := PolicyFromAPI(PolicyToAPI(p))
	if back.ExecVersion != p.ExecVersion || len(back.ExcludePaths) != 1 || back.MaxRuntimeSeconds != 60 || back.MemoryLimitMB != 64 {
		t.Fatalf("round trip: %+v", back)
	}
}

// ── kubernetes ──────────────────────────────────────────────────────────

func runningPod(ns, name, node, digest string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID("uid-" + name), Labels: map[string]string{"app": name}},
		Spec:       corev1.PodSpec{NodeName: node, Containers: []corev1.Container{{Name: "app", Image: "nginx:1"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
			Name: "app", Ready: true, ImageID: "docker-pullable://nginx@" + digest,
			State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.Now()}},
		}}},
	}
}

const digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestRunK8sSync(t *testing.T) {
	cs := fake.NewClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prod"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
		runningPod("prod", "web", "n1", digestA),
		runningPod("kube-system", "dns", "n1", digestA),
	)
	sink := newSink()
	var cfg kube.Config
	d := Deps{Sink: sink, KubeClient: func(c kube.Config) (*kube.Client, error) {
		cfg = c
		return kube.NewClientWith(cs, nil), nil
	}}
	job := K8sSyncJob{JobID: "s1", ClusterID: "c1", Kubeconfig: []byte("kc"), Filter: kube.Filter{NamespaceExclude: []string{"kube-*"}}}
	inv, err := RunK8sSync(context.Background(), job, d)
	if err != nil {
		t.Fatal(err)
	}
	if string(cfg.Kubeconfig) != "kc" || cfg.AllowExternalCredentials {
		t.Fatalf("client config %+v", cfg)
	}
	if inv == nil || len(inv.Pods) != 1 || inv.Pods[0].Name != "web" {
		t.Fatalf("inventory %+v", inv)
	}
	if len(sink.inventories) != 1 || sink.inventories[0].ClusterId != "c1" || *sink.inventories[0].JobId != "s1" {
		t.Fatal("inventory not submitted")
	}
	res := sink.results["s1"]
	if res.Status == agentapi.ScanJobStatusFailed {
		t.Fatalf("result %+v %q", res.Status, msg(res))
	}
}

func TestRunK8sSyncFailure(t *testing.T) {
	sink := newSink()
	d := Deps{Sink: sink, KubeClient: func(kube.Config) (*kube.Client, error) { return nil, errors.New("bad kubeconfig") }}
	inv, err := RunK8sSync(context.Background(), K8sSyncJob{JobID: "s", ClusterID: "c"}, d)
	if err != nil || inv != nil {
		t.Fatal(inv, err)
	}
	if r := sink.results["s"]; r.Status != agentapi.ScanJobStatusFailed || ReasonOf(msg(r)) != ReasonKubeClient {
		t.Fatalf("result %+v", r)
	}
	if len(sink.inventories) != 0 {
		t.Fatal("inventory submitted")
	}
}

func TestRunK8sExec(t *testing.T) {
	sink := newSink()
	var mu sync.Mutex
	var active, peak int
	d := Deps{Sink: sink,
		KubeClient: func(kube.Config) (*kube.Client, error) { return kube.NewClientWith(fake.NewClientset(), nil), nil },
		kubeCollect: func(_ context.Context, _ *kube.Client, tg kube.ExecTarget, kd kube.Deps) (*report.Report, kube.ContainerOutcome, error) {
			mu.Lock()
			active++
			peak = max(peak, active)
			mu.Unlock()
			defer func() { mu.Lock(); active--; mu.Unlock() }()
			time.Sleep(20 * time.Millisecond)
			if kd.ClusterID != "c1" {
				t.Errorf("deps cluster %q", kd.ClusterID)
			}
			switch tg.Pod {
			case "distroless":
				return nil, kube.ContainerOutcome{Coverage: agentapi.CoverageUnsupported, Reason: "no shell"}, nil
			case "boom":
				panic("collector bug")
			}
			r := sampleReport()
			r.Host = nil
			return r, kube.ContainerOutcome{Coverage: agentapi.CoverageFull}, nil
		}}
	targets := []kube.ExecTarget{
		{Namespace: "a", Pod: "p1", Container: "app", Node: "n1", ImageDigest: digestA},
		{Namespace: "b", Pod: "p2", Container: "app", Node: "n2"},
		{Namespace: "c", Pod: "distroless", Container: "app", Node: "n3"},
		{Namespace: "d", Pod: "boom", Container: "app", Node: "n4"},
	}
	res, err := RunK8sExec(context.Background(), K8sExecJob{JobID: "e1", ClusterID: "c1", Targets: targets,
		Limits: kube.Limits{Total: 2, PerNode: 1, PerNamespace: 1}}, d)
	if err != nil {
		t.Fatal(err)
	}
	if peak > 2 {
		t.Fatalf("limit exceeded: %d", peak)
	}
	if res.Status != agentapi.ScanJobStatusPartial || res.Targets == nil || len(*res.Targets) != 4 {
		t.Fatalf("result %s %q", res.Status, msg(res))
	}
	byPod := map[string]agentapi.ExecTargetResult{}
	for _, tr := range *res.Targets {
		byPod[tr.Pod] = tr
	}
	if byPod["p1"].Status != agentapi.ScanJobStatusOk || byPod["distroless"].Coverage != agentapi.CoverageUnsupported ||
		byPod["boom"].Status != agentapi.ScanJobStatusFailed {
		t.Fatalf("targets %+v", byPod)
	}
	if len(sink.reports) != 2 {
		t.Fatalf("reports %d", len(sink.reports))
	}
	for _, r := range sink.reports {
		k := r.Subject.K8s
		if r.Subject.Kind != report.SubjectK8sContainer || k == nil || k.ClusterID != "c1" || k.Container != "app" {
			t.Fatalf("subject %+v", r.Subject)
		}
		if k.Pod == "p1" && k.ImageDigest != digestA {
			t.Fatal("image digest missing from subject")
		}
	}
}

func TestRunK8sExecNothingCollected(t *testing.T) {
	sink := newSink()
	sink.reportErr = errors.New("server down")
	d := Deps{Sink: sink,
		KubeClient: func(kube.Config) (*kube.Client, error) { return kube.NewClientWith(fake.NewClientset(), nil), nil },
		kubeCollect: func(context.Context, *kube.Client, kube.ExecTarget, kube.Deps) (*report.Report, kube.ContainerOutcome, error) {
			return sampleReport(), kube.ContainerOutcome{Coverage: agentapi.CoverageFull}, nil
		}}
	res, _ := RunK8sExec(context.Background(), K8sExecJob{JobID: "e", ClusterID: "c",
		Targets: []kube.ExecTarget{{Namespace: "a", Pod: "p", Container: "c"}}}, d)
	if res.Status != agentapi.ScanJobStatusFailed || (*res.Targets)[0].Status != agentapi.ScanJobStatusFailed {
		t.Fatalf("result %s", res.Status)
	}
}

func TestPool(t *testing.T) {
	p := NewPool(2, 1, nil)
	release := make(chan struct{})
	var ran atomic.Int64
	job := func(ctx context.Context) {
		ran.Add(1)
		select {
		case <-release:
		case <-ctx.Done():
		}
	}
	if err := p.Submit("a", job); err != nil {
		t.Fatal(err)
	}
	if err := p.Submit("a", job); !errors.Is(err, ErrInFlight) {
		t.Fatalf("duplicate key: %v", err)
	}
	if err := p.Submit("b", job); err != nil {
		t.Fatal(err)
	}
	if err := p.Submit("c", job); err != nil {
		t.Fatal(err)
	}
	if err := p.Submit("d", job); !errors.Is(err, ErrPoolFull) {
		t.Fatalf("full: %v", err)
	}
	if err := p.Submit("e", func(context.Context) { panic("x") }); !errors.Is(err, ErrPoolFull) {
		t.Fatalf("full: %v", err)
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for p.InFlight("a") || p.InFlight("b") || p.InFlight("c") {
		if time.Now().After(deadline) {
			t.Fatal("jobs did not finish")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := p.Submit("e", func(context.Context) { panic("x") }); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ran.Load() != 3 {
		t.Fatalf("ran %d", ran.Load())
	}
	if err := p.Submit("f", job); !errors.Is(err, ErrPoolClosed) {
		t.Fatalf("closed: %v", err)
	}
}
