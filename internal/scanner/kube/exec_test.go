// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package kube

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	utilexec "k8s.io/client-go/util/exec"

	"github.com/bomcensus/bomcensus/agentproto/dto"
	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/sign/signtest"
)

const testDigest = "sha256:" + "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12"

func execPod(dir string, readOnlyRoot bool) *corev1.Pod {
	ro := readOnlyRoot
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "app", UID: "p1"},
		Spec: corev1.PodSpec{
			NodeName: "n1",
			Volumes:  []corev1.Volume{{Name: "scratch", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}},
			Containers: []corev1.Container{{
				Name: "main", Image: "alpine:3.20",
				VolumeMounts:    []corev1.VolumeMount{{Name: "scratch", MountPath: dir}},
				SecurityContext: &corev1.SecurityContext{ReadOnlyRootFilesystem: &ro},
			}},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "main", Ready: true, ImageID: "docker.io/library/alpine@" + testDigest,
				State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.Now()}},
			}},
		},
	}
}

func execNode(arch string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1", Labels: map[string]string{labelArch: arch, labelOS: "linux"}}}
}

type probeSource struct {
	mu    sync.Mutex
	data  []byte
	calls []string
}

func (p *probeSource) get(_ context.Context, goos, arch string) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, goos+"/"+arch)
	if p.data == nil {
		return nil, errors.New("no probe")
	}
	return p.data, nil
}

type execEnv struct {
	dir   string
	ex    *localExecutor
	c     *Client
	probe *probeSource
	deps  Deps
	tgt   ExecTarget
}

// newExecEnv sets up a pod whose only candidate directory is a temporary
// emptyDir path, a local /bin/sh executor and a signed fake probe.
func newExecEnv(t *testing.T, objs ...k8sruntime.Object) *execEnv {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	tr := signtest.Install(t)
	prev := baseDirs
	baseDirs = nil
	t.Cleanup(func() { baseDirs = prev })

	e := &execEnv{dir: t.TempDir(), ex: &localExecutor{shell: []string{"/bin/sh"}}}
	if objs == nil {
		objs = []k8sruntime.Object{execPod(e.dir, false), execNode(runtime.GOARCH)}
	}
	for _, o := range objs {
		if p, ok := o.(*corev1.Pod); ok && p.Spec.Containers[0].VolumeMounts[0].MountPath == "" {
			p.Spec.Containers[0].VolumeMounts[0].MountPath = e.dir
		}
	}
	e.c = NewClientWith(fake.NewClientset(objs...), e.ex)
	e.probe = &probeSource{data: tr.SignELF(t, fakeProbeELF(t, runtime.GOARCH))}
	e.deps = Deps{ClusterID: "c1", Probe: e.probe.get, MemoryLimitMB: 64, MaxRuntime: 30 * time.Second, Timeout: 60 * time.Second}
	e.tgt = ExecTarget{Namespace: "app", Pod: "web-1", Container: "main"}
	return e
}

func (e *execEnv) run(t *testing.T) (*report.Report, ContainerOutcome, error) {
	t.Helper()
	r, o, err := CollectContainer(context.Background(), e.c, e.tgt, e.deps)
	t.Logf("outcome %+v err %v", o, err)
	return r, o, err
}

func (e *execEnv) assertClean(t *testing.T) {
	t.Helper()
	if !waitFor(5*time.Second, func() bool { return len(dirEntries(t, e.dir)) == 0 }) {
		t.Errorf("left behind: %v", dirEntries(t, e.dir))
	}
	if !waitFor(5*time.Second, func() bool { return len(processesRunningFrom(e.dir)) == 0 }) {
		t.Errorf("still running: %v", processesRunningFrom(e.dir))
	}
}

func TestCollectFull(t *testing.T) {
	e := newExecEnv(t)
	r, o, err := e.run(t)
	if err != nil || r == nil || o.Coverage != dto.CoverageFull {
		t.Fatalf("report %v outcome %+v err %v", r != nil, o, err)
	}
	wantSubject := report.K8sSubject{ClusterID: "c1", Namespace: "app", Pod: "web-1", Container: "main", ImageRef: "alpine:3.20", ImageDigest: testDigest}
	if r.Subject == nil || r.Subject.Kind != report.SubjectK8sContainer || r.Subject.K8s == nil || *r.Subject.K8s != wantSubject {
		t.Errorf("subject %+v", r.Subject)
	}
	if r.Host == nil || r.Packages == nil || r.Artifacts == nil || r.Processes == nil || r.Containers != nil {
		t.Errorf("sections host=%v packages=%v artifacts=%v processes=%v containers=%v",
			r.Host != nil, r.Packages != nil, r.Artifacts != nil, r.Processes != nil, r.Containers != nil)
	}
	if want := "GOMEMLIMIT=64MiB GOMAXPROCS=1 mem=64 runtime=30 scan_containers=false"; r.Host == nil || r.Host.Kernel != want {
		t.Errorf("limits seen by the probe: %q, want %q", r.Host.Kernel, want)
	}
	if r.Artifacts != nil && !slices.Equal(r.Artifacts.WalkPaths, []string{"/"}) {
		t.Errorf("walk paths seen by the probe: %v", r.Artifacts.WalkPaths)
	}
	if o.Dir != e.dir || o.ExitCode != 0 || o.Arch != runtime.GOARCH {
		t.Errorf("outcome %+v", o)
	}
	if len(e.probe.calls) != 1 || e.probe.calls[0] != "linux/"+runtime.GOARCH {
		t.Errorf("probe calls %v", e.probe.calls)
	}
	e.assertClean(t)
}

func TestCollectProcessOnly(t *testing.T) {
	e := newExecEnv(t)
	e.tgt.Sections = ProcessSections
	r, o, err := e.run(t)
	if err != nil || o.Coverage != dto.CoverageProcessOnly || r.Processes == nil || r.Packages != nil {
		t.Fatalf("outcome %+v err %v", o, err)
	}
}

func TestCollectPartial(t *testing.T) {
	e := newExecEnv(t)
	e.deps.Policy.ExcludePaths = []string{"fake:partial"}
	_, o, err := e.run(t)
	if err != nil || o.Coverage != dto.CoveragePartial || !strings.Contains(o.Reason, "packages: partial") {
		t.Fatalf("outcome %+v err %v", o, err)
	}
}

func TestCollectArchFromUname(t *testing.T) {
	e := newExecEnv(t, execPod("", false))
	r, o, err := e.run(t)
	if err != nil || r == nil {
		t.Fatalf("outcome %+v err %v", o, err)
	}
	if len(e.probe.calls) != 1 || e.probe.calls[0] != "linux/"+runtime.GOARCH {
		t.Errorf("probe calls %v", e.probe.calls)
	}
}

func TestCollectUnsignedProbe(t *testing.T) {
	e := newExecEnv(t)
	e.probe.data = fakeProbeELF(t, runtime.GOARCH)
	r, o, err := e.run(t)
	if err == nil || r != nil || o.Coverage != dto.CoverageFailed || o.Reason != "probe signature verification failed" {
		t.Fatalf("outcome %+v err %v", o, err)
	}
	if _, n := e.ex.counts(); n != 0 {
		t.Errorf("%d bytes sent to the container", n)
	}
	e.assertClean(t)
}

func TestCollectNoProbe(t *testing.T) {
	e := newExecEnv(t)
	e.probe.data = nil
	_, o, err := e.run(t)
	if err == nil || o.Coverage != dto.CoverageFailed {
		t.Fatalf("outcome %+v err %v", o, err)
	}
	if calls, _ := e.ex.counts(); calls != 0 {
		t.Errorf("%d exec sessions without a probe", calls)
	}
}

func TestCollectNoShell(t *testing.T) {
	e := newExecEnv(t)
	e.ex.shell = []string{"/nonexistent/sh"}
	_, o, err := e.run(t)
	if err != nil || o.Coverage != dto.CoverageUnsupported || o.Reason != "no shell in image" {
		t.Fatalf("outcome %+v err %v", o, err)
	}
}

func TestCollectNotRunning(t *testing.T) {
	p := execPod("", false)
	p.Status.ContainerStatuses[0].State = corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}
	e := newExecEnv(t, p, execNode(runtime.GOARCH))
	_, o, err := e.run(t)
	if err != nil || o.Coverage != dto.CoverageFailed || o.Reason != "container not running" {
		t.Fatalf("outcome %+v err %v", o, err)
	}
	if calls, _ := e.ex.counts(); calls != 0 {
		t.Errorf("%d exec sessions", calls)
	}
}

func TestCollectReadOnlyRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not apply to root")
	}
	p := execPod("", true)
	e := newExecEnv(t, p, execNode(runtime.GOARCH))
	os.Chmod(e.dir, 0o555)
	t.Cleanup(func() { os.Chmod(e.dir, 0o755) })
	_, o, err := e.run(t)
	if err != nil || o.Coverage != dto.CoverageFailed || !strings.HasPrefix(o.Reason, "read-only root file system") {
		t.Fatalf("outcome %+v err %v", o, err)
	}
}

func TestCollectTimeoutCleansUp(t *testing.T) {
	e := newExecEnv(t)
	e.deps.Policy.ExcludePaths = []string{"fake:sleep=60"}
	e.deps.Timeout = 3 * time.Second
	start := time.Now()
	r, o, err := e.run(t)
	if err != nil || r != nil || o.Coverage != dto.CoverageFailed || !strings.HasPrefix(o.Reason, "timeout") {
		t.Fatalf("outcome %+v err %v", o, err)
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Errorf("took %v", d)
	}
	if calls, _ := e.ex.counts(); calls != 2 {
		t.Errorf("%d exec sessions, want the collection and a cleanup", calls)
	}
	e.assertClean(t)
}

func TestCollectProbeExit(t *testing.T) {
	e := newExecEnv(t)
	e.deps.Policy.ExcludePaths = []string{"fake:exit=3"}
	_, o, err := e.run(t)
	if err != nil || o.Coverage != dto.CoverageFailed || o.ExitCode != 3 || !strings.Contains(o.Reason, "exit code 3: fakeprobe: exiting as asked") {
		t.Fatalf("outcome %+v err %v", o, err)
	}
	e.assertClean(t)
}

func TestCollectBadOutput(t *testing.T) {
	for _, c := range []struct {
		behavior, reason string
	}{
		{"fake:big=3000000", "report larger than"},
		{"fake:garbage", "invalid report"},
	} {
		t.Run(c.behavior, func(t *testing.T) {
			e := newExecEnv(t)
			e.deps.MaxReportBytes = 1 << 20
			e.deps.Policy.ExcludePaths = []string{c.behavior}
			_, o, err := e.run(t)
			if err != nil || o.Coverage != dto.CoverageFailed || !strings.HasPrefix(o.Reason, c.reason) {
				t.Fatalf("outcome %+v err %v", o, err)
			}
			e.assertClean(t)
		})
	}
}

func TestCollectPodForbidden(t *testing.T) {
	e := newExecEnv(t)
	e.c.Kube.(*fake.Clientset).PrependReactor("get", "pods", func(k8stesting.Action) (bool, k8sruntime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "web-1", errors.New("denied"))
	})
	_, o, err := e.run(t)
	if err != nil || o.Coverage != dto.CoverageFailed || !strings.Contains(o.Reason, "forbidden") {
		t.Fatalf("outcome %+v err %v", o, err)
	}
}

func TestCollectCanceled(t *testing.T) {
	e := newExecEnv(t)
	e.deps.Policy.ExcludePaths = []string{"fake:sleep=60"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, o, err := CollectContainer(ctx, e.c, e.tgt, e.deps)
	if !errors.Is(err, context.DeadlineExceeded) || o.Coverage != dto.CoverageFailed {
		t.Fatalf("outcome %+v err %v", o, err)
	}
	e.assertClean(t)
}

func TestClassifyStartError(t *testing.T) {
	for _, c := range []struct {
		err  error
		cov  dto.Coverage
		want string
	}{
		{errors.New(`OCI runtime exec failed: exec failed: unable to start container process: exec: "sh": executable file not found in $PATH: unknown`), dto.CoverageUnsupported, "no shell in image"},
		{utilexec.CodeExitError{Err: errors.New("command terminated with exit code 127"), Code: 127}, dto.CoverageUnsupported, "no shell in image"},
		{utilexec.CodeExitError{Err: errors.New("command terminated with exit code 126"), Code: 126}, dto.CoverageUnsupported, "no shell in image"},
		{apierrors.NewForbidden(schema.GroupResource{Resource: "pods/exec"}, "x", errors.New("no")), dto.CoverageFailed, "exec forbidden by RBAC"},
		{errors.New(`pods "x" is forbidden: User "y" cannot create resource "pods/exec"`), dto.CoverageFailed, "exec forbidden by RBAC"},
		{errors.New(`container not found ("main")`), dto.CoverageFailed, "container not running"},
		{errors.New("cannot exec in a stopped state: unknown, container is not running"), dto.CoverageFailed, "container not running"},
		{fmt.Errorf("dial: %w", errors.New("connection refused")), dto.CoverageFailed, "exec failed: dial: connection refused"},
	} {
		cov, reason := classifyStartError(c.err)
		if cov != c.cov || reason != c.want {
			t.Errorf("%v: got %s %q, want %s %q", c.err, cov, reason, c.cov, c.want)
		}
	}
}

func TestOutcomeResult(t *testing.T) {
	tgt := ExecTarget{Namespace: "a", Pod: "p", Container: "c"}
	for cov, status := range map[dto.Coverage]string{
		dto.CoverageFull: "ok", dto.CoverageProcessOnly: "ok", dto.CoveragePartial: "partial",
		dto.CoverageUnsupported: "failed", dto.CoverageFailed: "failed",
	} {
		r := ContainerOutcome{Coverage: cov, Reason: "x"}.Result(tgt, "r1")
		if string(r.Status) != status || r.Coverage != cov || *r.Reason != "x" || *r.ReportId != "r1" || r.Pod != "p" {
			t.Errorf("%s: %+v", cov, r)
		}
	}
}

func TestTargetAPIRoundTrip(t *testing.T) {
	in := ExecTarget{Namespace: "ns", Pod: "p", Container: "c", Sections: []string{report.SectionProcesses},
		GoSymbols: &report.GoSymbolQuery{Files: []report.GoSymbolFile{{Path: "/app", SHA256: strings.Repeat("a", 64),
			Names: []string{"net/http.Serve"}}}}}
	out := TargetFromAPI(in.API())
	if !reflect.DeepEqual(out.GoSymbols, in.GoSymbols) || out.Container != "c" || len(out.Sections) != 1 {
		t.Fatalf("round trip: %+v", out)
	}
	if TargetFromAPI(ExecTarget{Pod: "p"}.API()).GoSymbols != nil {
		t.Fatal("query out of nothing")
	}
}
