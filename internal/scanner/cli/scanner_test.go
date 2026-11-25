// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/agentproto"
	"github.com/bomcensus/bomcensus/agentproto/dto"
	"github.com/bomcensus/bomcensus/internal/agent/core"
	"github.com/bomcensus/bomcensus/internal/agent/state"
	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/scanner/hpkebox"
	"github.com/bomcensus/bomcensus/internal/scanner/kube"
	"github.com/bomcensus/bomcensus/internal/scanner/runner"
)

const scannerID = "scanner-1"

type recordingSink struct {
	mu      sync.Mutex
	results map[string]runner.Result
}

func (s *recordingSink) SubmitReport(context.Context, []byte, string) error { return nil }
func (s *recordingSink) SubmitInventory(context.Context, dto.K8sInventory) error {
	return nil
}
func (s *recordingSink) SubmitResult(_ context.Context, jobID string, r runner.Result) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results[jobID] = r
	return nil
}

func (s *recordingSink) result(id string) (runner.Result, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.results[id]
	return r, ok
}

type fakeJobs struct {
	mu    sync.Mutex
	ssh   []runner.SSHJob
	syncs []runner.K8sSyncJob
	execs []runner.K8sExecJob
	gate  chan struct{}
	done  chan struct{}
}

func (f *fakeJobs) RunSSH(ctx context.Context, j runner.SSHJob, _ runner.Deps) (runner.Result, error) {
	f.mu.Lock()
	f.ssh = append(f.ssh, runner.SSHJob{JobID: j.JobID, TargetID: j.TargetID, Address: j.Address, Port: j.Port, User: j.User,
		Sudo: j.Sudo, HostKey: j.HostKey, HostKeyFingerprint: j.HostKeyFingerprint, Sections: j.Sections,
		Credential: runner.SSHCredential{PrivateKey: bytes.Clone(j.Credential.PrivateKey), Password: j.Credential.Password}})
	f.mu.Unlock()
	if f.gate != nil {
		<-f.gate
	}
	f.done <- struct{}{}
	return runner.Result{}, nil
}

func (f *fakeJobs) RunK8sSync(_ context.Context, j runner.K8sSyncJob, _ runner.Deps) (*kube.Inventory, error) {
	f.mu.Lock()
	f.syncs = append(f.syncs, runner.K8sSyncJob{JobID: j.JobID, ClusterID: j.ClusterID, Kubeconfig: bytes.Clone(j.Kubeconfig), Filter: j.Filter})
	f.mu.Unlock()
	f.done <- struct{}{}
	return nil, nil
}

func (f *fakeJobs) RunK8sExec(_ context.Context, j runner.K8sExecJob, _ runner.Deps) (runner.Result, error) {
	f.mu.Lock()
	f.execs = append(f.execs, j)
	f.mu.Unlock()
	f.done <- struct{}{}
	return runner.Result{}, nil
}

type handlerFixture struct {
	sc   *scanner
	sink *recordingSink
	jobs *fakeJobs
	pub  []byte
}

func newHandlerFixture(t *testing.T) *handlerFixture {
	priv, pub, err := hpkebox.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sink := &recordingSink{results: map[string]runner.Result{}}
	jobs := &fakeJobs{done: make(chan struct{}, 8)}
	pool := runner.NewPool(2, 0, nil)
	t.Cleanup(func() { _ = pool.Close(context.Background()) })
	sc := &scanner{agentID: func() string { return scannerID }, key: priv, deps: runner.Deps{Sink: sink},
		pool: pool, run: jobs, log: discard()}
	return &handlerFixture{sc: sc, sink: sink, jobs: jobs, pub: pub}
}

func (f *handlerFixture) wait(t *testing.T) {
	t.Helper()
	select {
	case <-f.jobs.done:
	case <-time.After(5 * time.Second):
		t.Fatal("job did not run")
	}
}

func seal(t *testing.T, pub []byte, scanner, job, field string, v []byte) []byte {
	t.Helper()
	b, err := hpkebox.Seal(pub, v, hpkebox.SecretInfo(scanner, job, field))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func directive(t *testing.T, v any) dto.Directive {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var d dto.Directive
	if err := d.UnmarshalJSON(raw); err != nil {
		t.Fatal(err)
	}
	return d
}

func sshDirective(t *testing.T, pub []byte, scanner, job string) map[string]any {
	pw := "hunter2"
	cred, _ := json.Marshal(dto.SSHCredentialSecret{Kind: dto.SshPassword, Password: &pw})
	return map[string]any{
		"type": "scan_ssh", "id": "d1", "job_id": job, "scan_target_id": "t1", "address": "10.0.0.9", "port": 22,
		"username": "scan", "sudo": true, "policy": map[string]any{"exec_version": true, "collect_cmdline": true, "scan_containers": true},
		"credential":           seal(t, pub, scanner, job, "credential", cred),
		"host_key_fingerprint": "SHA256:abc", "host_key": []byte("wire-key"),
		"sections": []string{"packages"},
	}
}

func TestHandleScanSSH(t *testing.T) {
	f := newHandlerFixture(t)
	if err := f.sc.handleScanSSH(context.Background(), directive(t, sshDirective(t, f.pub, scannerID, "ssh.t1.1"))); err != nil {
		t.Fatal(err)
	}
	f.wait(t)
	j := f.jobs.ssh[0]
	if j.JobID != "ssh.t1.1" || j.TargetID != "t1" || j.User != "scan" || !j.Sudo || j.Credential.Password != "hunter2" ||
		string(j.HostKey) != "wire-key" || j.HostKeyFingerprint != "SHA256:abc" || len(j.Sections) != 1 {
		t.Fatalf("job %+v", j)
	}
}

func TestSealedSecretBoundToScannerAndJob(t *testing.T) {
	f := newHandlerFixture(t)
	cases := map[string]map[string]any{
		"other scanner": sshDirective(t, f.pub, "scanner-2", "ssh.t1.2"),
		"other job": func() map[string]any {
			d := sshDirective(t, f.pub, scannerID, "ssh.t1.other")
			d["job_id"] = "ssh.t1.2"
			return d
		}(),
	}
	_, otherPub, _ := hpkebox.GenerateKey()
	cases["other key"] = sshDirective(t, otherPub, scannerID, "ssh.t1.2")
	for name, d := range cases {
		t.Run(name, func(t *testing.T) {
			if err := f.sc.handleScanSSH(context.Background(), directive(t, d)); err != nil {
				t.Fatal(err)
			}
			r, ok := f.sink.result("ssh.t1.2")
			if !ok || r.Status != dto.ScanJobStatusFailed || runner.ReasonOf(*r.Message) != runner.ReasonSecret {
				t.Fatalf("result %+v", r)
			}
			f.jobs.mu.Lock()
			n := len(f.jobs.ssh)
			f.jobs.mu.Unlock()
			if n != 0 {
				t.Fatal("job ran with an unopenable secret")
			}
		})
	}
}

func TestHandleBusy(t *testing.T) {
	f := newHandlerFixture(t)
	f.jobs.gate = make(chan struct{})
	ctx := context.Background()
	if err := f.sc.handleScanSSH(ctx, directive(t, sshDirective(t, f.pub, scannerID, "ssh.t1.1"))); err != nil {
		t.Fatal(err)
	}
	// The same target again while the first run is in flight.
	if err := f.sc.handleScanSSH(ctx, directive(t, sshDirective(t, f.pub, scannerID, "ssh.t1.2"))); err != nil {
		t.Fatal(err)
	}
	r, ok := f.sink.result("ssh.t1.2")
	if !ok || runner.ReasonOf(*r.Message) != runner.ReasonBusy {
		t.Fatalf("result %+v", r)
	}
	close(f.jobs.gate)
	f.wait(t)
}

func TestHandleK8s(t *testing.T) {
	f := newHandlerFixture(t)
	ctx := context.Background()
	filter := dto.K8sFilter{NamespaceInclude: []string{"prod"}, NamespaceExclude: []string{}, LabelInclude: []string{},
		LabelExclude: []string{}, AnnotationInclude: []string{}, AnnotationExclude: []string{}}
	kc := seal(t, f.pub, scannerID, "sync.c1.1", "kubeconfig", []byte("apiVersion: v1"))
	sync := dto.K8sSyncDirective{Type: dto.K8sSync, Id: "d", JobId: "sync.c1.1", ClusterId: "c1",
		Connection: dto.Kubeconfig, Kubeconfig: &kc, Filter: filter, ExecEnabled: true}
	var d dto.Directive
	_ = d.FromK8sSyncDirective(sync)
	if err := f.sc.handleK8sSync(ctx, d); err != nil {
		t.Fatal(err)
	}
	f.wait(t)
	if s := f.jobs.syncs[0]; string(s.Kubeconfig) != "apiVersion: v1" || s.Filter.NamespaceInclude[0] != "prod" {
		t.Fatalf("sync job %+v", s)
	}
	// In-cluster: no kubeconfig.
	node := "n1"
	exec := dto.K8sExecDirective{Type: dto.K8sExec, Id: "d2", JobId: "exec.c2.1", ClusterId: "c2",
		Connection: dto.InCluster, Policy: dto.Policy{ExecVersion: true},
		Targets: []dto.K8sExecTarget{{Namespace: "prod", Pod: "web-0", Container: "app", Node: &node, Sections: []dto.SectionName{dto.Processes}}}}
	_ = d.FromK8sExecDirective(exec)
	if err := f.sc.handleK8sExec(ctx, d); err != nil {
		t.Fatal(err)
	}
	f.wait(t)
	e := f.jobs.execs[0]
	if e.Kubeconfig != nil || len(e.Targets) != 1 || e.Targets[0].Pod != "web-0" || e.Targets[0].Node != "n1" || e.Targets[0].Sections[0] != "processes" || !e.Policy.ExecVersion {
		t.Fatalf("exec job %+v", e)
	}
	// A kubeconfig connection without the sealed kubeconfig is rejected.
	exec.JobId, exec.Connection = "exec.c2.2", dto.Kubeconfig
	_ = d.FromK8sExecDirective(exec)
	if err := f.sc.handleK8sExec(ctx, d); err != nil {
		t.Fatal(err)
	}
	if r, ok := f.sink.result("exec.c2.2"); !ok || r.Status != dto.ScanJobStatusFailed {
		t.Fatalf("result %+v", r)
	}
}

// ── sink and probe against an HTTP server ───────────────────────────────

type spool struct {
	err  error
	jobs []string
}

func (s *spool) SubmitReport(_ context.Context, _ []byte, m core.ReportMeta) error {
	s.jobs = append(s.jobs, m.JobID)
	return s.err
}

func clientFor(t *testing.T, h http.Handler) func() agentproto.API {
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := agentapi.NewClientWithResponses(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return func() agentproto.API { return unsignedAPI{c: c} }
}

// unsignedAPI is the scanner operations over plain HTTP, for handlers that
// do not sign their responses.
type unsignedAPI struct {
	agentproto.API
	c *agentapi.ClientWithResponses
}

func statusError(resp *http.Response, body []byte, want int) error {
	if resp.StatusCode == want {
		return nil
	}
	e := &agentproto.Error{Status: resp.StatusCode}
	var eb dto.Error
	if json.Unmarshal(body, &eb) == nil {
		e.Code, e.Message = eb.Code, eb.Message
	}
	return e
}

func (u unsignedAPI) UploadK8sInventory(ctx context.Context, inv *dto.K8sInventory) error {
	resp, err := u.c.UploadK8sInventoryWithResponse(ctx, *inv)
	if err != nil {
		return err
	}
	return statusError(resp.HTTPResponse, resp.Body, http.StatusNoContent)
}

func (u unsignedAPI) SubmitScanJobResult(ctx context.Context, jobID string, res *dto.ScanJobResult) error {
	resp, err := u.c.SubmitScanJobResultWithResponse(ctx, jobID, *res)
	if err != nil {
		return err
	}
	return statusError(resp.HTTPResponse, resp.Body, http.StatusNoContent)
}

func (u unsignedAPI) DownloadProbe(ctx context.Context, os dto.TargetOs, arch dto.TargetArch) (*agentproto.Download, error) {
	resp, err := u.c.DownloadProbeWithResponse(ctx, os, arch)
	if err != nil {
		return nil, err
	}
	if err := statusError(resp.HTTPResponse, resp.Body, http.StatusOK); err != nil {
		return nil, err
	}
	return &agentproto.Download{Body: io.NopCloser(bytes.NewReader(resp.Body)), Size: int64(len(resp.Body)),
		Version: resp.HTTPResponse.Header.Get("Bomcensus-Probe-Version")}, nil
}

func TestClientSink(t *testing.T) {
	var mu sync.Mutex
	var bodies = map[string][]byte{}
	var attempts atomic.Int64
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies[r.URL.Path] = b
		mu.Unlock()
		switch {
		case r.URL.Path == "/scan-jobs/flaky/result" && attempts.Add(1) == 1:
			w.WriteHeader(http.StatusServiceUnavailable)
		case r.URL.Path == "/scan-jobs/gone/result":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"code":"not_found","message":"unknown scan job"}`))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	})
	sp := &spool{err: errors.New("upload failed")}
	s := &clientSink{reports: sp, client: clientFor(t, h), log: discard(), retryWait: time.Millisecond}
	ctx := context.Background()
	if err := s.SubmitReport(ctx, []byte("r"), "j1"); err != nil || sp.jobs[0] != "j1" {
		t.Fatalf("report: %v", err)
	}
	if err := s.SubmitInventory(ctx, dto.K8sInventory{ClusterId: "c1"}); err != nil {
		t.Fatal(err)
	}
	fp := "SHA256:x"
	key := []byte{1, 2}
	res := runner.Result{ScanJobResult: dto.ScanJobResult{Status: dto.ScanJobStatusOk, HostKeyFingerprint: &fp, HostKey: &key}}
	if err := s.SubmitResult(ctx, "flaky", res); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	_ = json.Unmarshal(bodies["/scan-jobs/flaky/result"], &got)
	if got["status"] != "ok" || got["host_key_fingerprint"] != fp || got["host_key"] != "AQI=" {
		t.Fatalf("result body %v", got)
	}
	if err := s.SubmitResult(ctx, "gone", res); err == nil || !core.IsStatus(err, http.StatusNotFound) {
		t.Fatalf("404 not reported: %v", err)
	}
	if !strings.Contains(string(bodies["/k8s/inventory"]), `"cluster_id":"c1"`) {
		t.Fatal("inventory not sent")
	}
}

func TestProbeCache(t *testing.T) {
	var downloads atomic.Int64
	version := "1.0.0"
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/probe/linux/amd64" {
			http.NotFound(w, r)
			return
		}
		downloads.Add(1)
		w.Header().Set("Bomcensus-Probe-Version", version)
		_, _ = w.Write([]byte("probe-" + version))
	})
	now := time.Unix(1000, 0)
	p := newProbeCache(clientFor(t, h))
	p.now = func() time.Time { return now }
	verified := 0
	p.verify = func(b []byte) error {
		verified++
		if string(b) == "probe-bad" {
			return errors.New("bad signature")
		}
		return nil
	}
	ctx := context.Background()
	for range 3 {
		b, err := p.Get(ctx, "linux", "amd64")
		if err != nil || string(b) != "probe-1.0.0" {
			t.Fatal(string(b), err)
		}
	}
	if downloads.Load() != 1 || verified != 1 {
		t.Fatalf("downloads %d verified %d", downloads.Load(), verified)
	}
	now = now.Add(time.Hour)
	if b, _ := p.Get(ctx, "linux", "amd64"); string(b) != "probe-1.0.0" || verified != 1 {
		t.Fatal("same version re-verified or replaced")
	}
	version = "bad"
	now = now.Add(time.Hour)
	if _, err := p.Get(ctx, "linux", "amd64"); err == nil {
		t.Fatal("unverified probe returned")
	}
	version = "2.0.0"
	if b, _ := p.Get(ctx, "linux", "amd64"); string(b) != "probe-2.0.0" {
		t.Fatalf("new version not loaded: %s", b)
	}
	if _, err := p.Get(ctx, "linux", "arm64"); err == nil {
		t.Fatal("missing probe returned")
	}
}

func TestEnsureHPKEKey(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	pub, err := ensureHPKEKey(st)
	if err != nil {
		t.Fatal(err)
	}
	again, err := ensureHPKEKey(st)
	if err != nil || !bytes.Equal(pub, again) {
		t.Fatal("key regenerated")
	}
	priv, err := loadHPKEKey(st)
	if err != nil {
		t.Fatal(err)
	}
	sealed, _ := hpkebox.Seal(pub, []byte("x"), nil)
	if _, err := hpkebox.Open(priv, sealed, nil); err != nil {
		t.Fatal(err)
	}
}

func TestVersionCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"version"}, &out, &errb); code != 0 || out.Len() == 0 {
		t.Fatalf("code %d", code)
	}
	if code := run([]string{"bogus"}, &out, &errb); code != 2 {
		t.Fatalf("code %d", code)
	}
}

func discard() *slog.Logger { return slog.New(slog.DiscardHandler) }
