// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/bomcensus/bomcensus/internal/collect"
	"github.com/bomcensus/bomcensus/internal/collect/artifact"
	"github.com/bomcensus/bomcensus/internal/report"
)

// The sandbox cannot be undone, so every test applies it in a child: the
// test binary started again with sandboxChildEnv naming the program to run.
//
//	restricted  apply the sandbox, try what it must deny and what the
//	            collectors need, print a childResult as JSON
//	inherit     do not apply anything; report what a child of a sandboxed
//	            process can do
//
// Environment of the restricted child:
//
//	BOMCENSUS_PROBE_TEST_DIR   a directory the test user can write, holding
//	                           a file named "existing"
//	BOMCENSUS_PROBE_TEST_PIDS  running runtimes as pid=path,…, whose version
//	                           commands the artifact collector runs
//	BOMCENSUS_PROBE_TEST_RUN   runtimes as name=path,… whose version
//	                           commands are run through the exec helper

const (
	envTestDir  = "BOMCENSUS_PROBE_TEST_DIR"
	envTestPIDs = "BOMCENSUS_PROBE_TEST_PIDS"
	envTestRun  = "BOMCENSUS_PROBE_TEST_RUN"
	envRootTest = "BOMCENSUS_PROBE_ROOT_TEST"
)

type inheritResult struct {
	Create  string `json:"create"`
	TCP     string `json:"tcp"`
	Seccomp string `json:"seccomp"`
	NNP     string `json:"nnp"`
}

type versionRun struct {
	Path     string `json:"path"`
	Method   string `json:"method,omitempty"`
	Version  string `json:"version,omitempty"`
	ExitCode int    `json:"exit_code"`
	Output   string `json:"output,omitempty"`
	Err      string `json:"err,omitempty"`
}

type childResult struct {
	Sandbox *SandboxResult `json:"sandbox"`
	Summary string         `json:"summary"`

	// Errors of operations that must fail; empty means it worked.
	Create, Mkdir, Remove, Rename, Truncate, OpenWrite string
	Symlink, Chmod                                     string
	TCP, UDP, Ptrace, ProcMemWrite                     string

	// Errors of operations that must work.
	Read, Unix, Memfd, Exec, ParentExe string

	Inherit inheritResult

	// Root runs only.
	ProcOneExe, Shadow string
	// SelfExe is the child's executable: a memfd after a re-execution.
	SelfExe string

	Artifacts []versionRun
	// Helper maps a path to the result of its version command.
	Helper map[string]versionRun
	// Privilege is what DetectPrivilege reports after the sandbox.
	Privilege report.Privilege
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func runSandboxChild(name string) int {
	switch name {
	case "inherit":
		var r inheritResult
		dir := os.Getenv(envTestDir)
		r.Create = errString(createFile(filepath.Join(dir, "from-child")))
		r.TCP = errString(socketErr(unix.AF_INET, unix.SOCK_STREAM))
		status, _ := os.ReadFile("/proc/self/status")
		r.Seccomp = statusField(string(status), "Seccomp")
		r.NNP = statusField(string(status), "NoNewPrivs")
		json.NewEncoder(os.Stdout).Encode(r)
		return 0
	case "restricted":
		EnsureExecutableAfterDrop(nil)
		res := ApplySandbox(nil)
		out := restrictedChecks()
		out.Sandbox = res
		out.Summary = res.String()
		json.NewEncoder(os.Stdout).Encode(out)
		return 0
	}
	fmt.Fprintln(os.Stderr, "unknown sandbox child", name)
	return 2
}

func restrictedChecks() childResult {
	var r childResult
	dir := os.Getenv(envTestDir)
	existing := filepath.Join(dir, "existing")
	r.Create = errString(createFile(filepath.Join(dir, "new")))
	r.Mkdir = errString(os.Mkdir(filepath.Join(dir, "newdir"), 0o700))
	r.Remove = errString(os.Remove(existing))
	r.Rename = errString(os.Rename(existing, filepath.Join(dir, "renamed")))
	r.Truncate = errString(os.Truncate(existing, 0))
	r.OpenWrite = errString(func() error {
		f, err := os.OpenFile(existing, os.O_WRONLY|os.O_APPEND, 0)
		if err == nil {
			f.Close()
		}
		return err
	}())
	r.Symlink = errString(os.Symlink(existing, filepath.Join(dir, "link")))
	r.Chmod = errString(os.Chmod(existing, 0o777))
	r.TCP = errString(socketErr(unix.AF_INET, unix.SOCK_STREAM))
	r.UDP = errString(socketErr(unix.AF_INET6, unix.SOCK_DGRAM))
	r.Ptrace = errString(ptraceErr())
	r.ProcMemWrite = errString(func() error {
		f, err := os.OpenFile("/proc/self/mem", os.O_RDWR, 0)
		if err == nil {
			f.Close()
		}
		return err
	}())

	_, err := os.ReadFile(existing)
	r.Read = errString(err)
	// The parent runs as the same user; its executable link must stay
	// readable (a Landlock domain would hide it).
	_, err = os.Readlink(fmt.Sprintf("/proc/%d/exe", os.Getppid()))
	r.ParentExe = errString(err)
	r.Unix = errString(socketErr(unix.AF_UNIX, unix.SOCK_STREAM))
	r.Memfd = errString(func() error {
		fd, err := unix.MemfdCreate("check", unix.MFD_CLOEXEC)
		if err == nil {
			_, err = unix.Write(fd, []byte("x"))
			unix.Close(fd)
		}
		return err
	}())

	cmd := exec.Command("/proc/self/exe")
	cmd.Env = []string{sandboxChildEnv + "=inherit", envTestDir + "=" + dir}
	if outb, err := cmd.Output(); err != nil {
		r.Exec = err.Error()
	} else if err := json.Unmarshal(outb, &r.Inherit); err != nil {
		r.Exec = "inherit output: " + err.Error()
	}

	_, err = os.Readlink("/proc/1/exe")
	r.ProcOneExe = errString(err)
	r.SelfExe, _ = os.Readlink("/proc/self/exe")
	_, err = os.ReadFile("/etc/shadow")
	r.Shadow = errString(err)

	r.Artifacts = versionsThroughCollector(os.Getenv(envTestPIDs))
	r.Helper = map[string]versionRun{}
	for _, kv := range splitList(os.Getenv(envTestRun)) {
		name, p, _ := strings.Cut(kv, "=")
		r.Helper[p] = versionThroughHelper(name, p)
	}
	r.Privilege = DetectPrivilege("/proc")
	return r
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// versionsThroughCollector runs the artifact collector over running
// processes only: every top-level directory is excluded from the walk.
func versionsThroughCollector(spec string) []versionRun {
	var running []artifact.RunningExe
	for _, kv := range splitList(spec) {
		pid, p, _ := strings.Cut(kv, "=")
		n, _ := strconv.Atoi(pid)
		running = append(running, artifact.RunningExe{PID: n, Path: p, State: report.ExeNormal})
	}
	if len(running) == 0 {
		return nil
	}
	env := collect.NewEnv()
	env.Log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	entries, _ := os.ReadDir("/")
	for _, e := range entries {
		env.Policy.ExcludePaths = append(env.Policy.ExcludePaths, "/"+e.Name())
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	sec := artifact.Collect(ctx, env, artifact.Inputs{Running: running})
	var out []versionRun
	for _, a := range sec.Artifacts {
		if a.Kind != report.ArtifactSoftware {
			continue
		}
		v := versionRun{Path: a.Path, Method: a.Method, Version: a.Version}
		if a.VersionOutput != nil {
			v.ExitCode = a.VersionOutput.ExitCode
			v.Output = a.VersionOutput.Stdout + a.VersionOutput.Stderr
		}
		out = append(out, v)
	}
	return out
}

// versionThroughHelper runs the detector's version command for the file at
// p through the exec helper of the artifact package, the way its version
// execution does (exechelper.go): the binary re-executed with the helper
// argument, limits, the file on fd 3 and a status pipe on fd 4.
func versionThroughHelper(detector, p string) versionRun {
	v := versionRun{Path: p}
	var det *artifact.Detector
	for _, d := range artifact.Detectors {
		if d.ID == detector {
			det = d
		}
	}
	if det == nil {
		v.Err = "no detector " + detector
		return v
	}
	exe, err := os.Open(p)
	if err != nil {
		v.Err = err.Error()
		return v
	}
	defer exe.Close()
	statusR, statusW, err := os.Pipe()
	if err != nil {
		v.Err = err.Error()
		return v
	}
	defer statusR.Close()
	as := uint64(2 << 30)
	if det.AddressSpaceMB > 0 {
		as = uint64(det.AddressSpaceMB) << 20
	}
	var nproc unix.Rlimit
	unix.Getrlimit(unix.RLIMIT_NPROC, &nproc)
	args := []string{"__bomcensus_exec_helper", "10", strconv.FormatUint(as, 10), "64", strconv.FormatUint(nproc.Max, 10), "--", p}
	args = append(args, det.Exec...)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/proc/self/exe", args...)
	cmd.Env = []string{}
	for _, e := range det.Env {
		cmd.Env = append(cmd.Env, e.Name+"="+parentN(p, e.Up))
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.ExtraFiles = []*os.File{exe, statusW}
	err = cmd.Start()
	statusW.Close()
	if err != nil {
		v.Err = err.Error()
		return v
	}
	msg, _ := io.ReadAll(statusR)
	err = cmd.Wait()
	v.Output = stdout.String() + stderr.String()
	if cmd.ProcessState != nil {
		v.ExitCode = cmd.ProcessState.ExitCode()
	}
	if len(msg) > 0 {
		v.Err = "helper: " + string(msg)
	} else if err != nil && v.ExitCode < 0 {
		v.Err = err.Error()
	}
	return v
}

func parentN(p string, n int) string {
	for range n {
		p = filepath.Dir(p)
	}
	return p
}

func statusField(status, key string) string {
	for line := range strings.SplitSeq(status, "\n") {
		if v, ok := strings.CutPrefix(line, key+":"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// runtime is a version-command target found on this system.
type runtimeTarget struct {
	detector string
	path     string
	// sleep makes the runtime run long enough to be inspected as a
	// running process; nil when there is no simple way.
	sleep []string
}

func findRuntimes(t *testing.T) []runtimeTarget {
	var out []runtimeTarget
	for _, c := range []struct {
		name, detector string
		sleep          []string
	}{
		{"java", "openjdk", nil},
		{"node", "nodejs", []string{"-e", "setTimeout(() => {}, 120000)"}},
		{"php", "php", []string{"-r", "sleep(120);"}},
		{"python3", "python", []string{"-c", "import time; time.sleep(120)"}},
	} {
		p, err := exec.LookPath(c.name)
		if err != nil {
			continue
		}
		if real, err := filepath.EvalSymlinks(p); err == nil {
			p = real
		}
		out = append(out, runtimeTarget{detector: c.detector, path: p, sleep: c.sleep})
	}
	return out
}

// startSleepers starts the runtimes that can idle and returns pid=path
// pairs of the running processes.
func startSleepers(t *testing.T, rts []runtimeTarget) []string {
	var out []string
	for _, rt := range rts {
		if rt.sleep == nil {
			continue
		}
		cmd := exec.Command(rt.path, rt.sleep...)
		if err := cmd.Start(); err != nil {
			t.Logf("start %s: %v", rt.path, err)
			continue
		}
		t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
		exe := ""
		for range 50 {
			if l, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", cmd.Process.Pid)); err == nil && l == rt.path {
				exe = l
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if exe == "" {
			continue
		}
		out = append(out, fmt.Sprintf("%d=%s", cmd.Process.Pid, exe))
	}
	return out
}

func runRestrictedChild(t *testing.T) (childResult, string) {
	t.Helper()
	// Not t.TempDir: its parent is private to the test user, and the root
	// run drops to nobody.
	dir, err := os.MkdirTemp("", "probe-sandbox-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	os.Chmod(dir, 0o777)
	existing := filepath.Join(dir, "existing")
	if err := os.WriteFile(existing, []byte("content"), 0o666); err != nil {
		t.Fatal(err)
	}
	os.Chmod(existing, 0o666)
	rts := findRuntimes(t)
	if fake := fakeNode(t); fake != "" {
		p := filepath.Join(dir, "bin", "node")
		os.MkdirAll(filepath.Dir(p), 0o755)
		data, err := os.ReadFile(fake)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o755); err != nil {
			t.Fatal(err)
		}
		os.Chmod(p, 0o755)
		rts = append(rts, runtimeTarget{detector: "nodejs", path: p, sleep: []string{}})
	}
	var run []string
	for _, rt := range rts {
		run = append(run, rt.detector+"="+rt.path)
	}
	pids := startSleepers(t, rts)
	t.Logf("running runtimes: %v", pids)

	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), sandboxChildEnv+"=restricted", envTestDir+"="+dir,
		envTestPIDs+"="+strings.Join(pids, ","), envTestRun+"="+strings.Join(run, ","))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, stderr.String())
	}
	var r childResult
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("child output: %v\n%s\n%s", err, out, stderr.String())
	}
	t.Logf("sandbox:\n%s", r.Summary)
	if os.Getenv(envRootTest) != "" {
		t.Logf("child log:\n%s", stderr.String())
	}
	if b, err := os.ReadFile(existing); err != nil || string(b) != "content" {
		t.Errorf("existing file changed: %q, %v", b, err)
	}
	for _, name := range []string{"new", "newdir", "renamed", "link", "from-child"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			t.Errorf("%s was created", name)
		}
	}
	return r, dir
}

func TestSandboxRestrictions(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: TestSandboxRoot covers this")
	}
	r, _ := runRestrictedChild(t)
	if r.Sandbox.Seccomp != 2 {
		t.Skip("seccomp filters not available")
	}
	checkDenied(t, r)
	for name, e := range map[string]string{"read": r.Read, "unix socket": r.Unix, "memfd": r.Memfd, "exec": r.Exec, "parent exe": r.ParentExe} {
		if e != "" {
			t.Errorf("%s failed: %s", name, e)
		}
	}
	checkVersions(t, r, false)
}

// checkDenied verifies that everything the sandbox forbids failed.
func checkDenied(t *testing.T, r childResult) {
	t.Helper()
	for _, s := range r.Sandbox.Steps {
		if s.Status == StepFailed {
			t.Errorf("step %s failed: %s", s.Name, s.Detail)
		}
	}
	for name, e := range map[string]string{
		"create": r.Create, "mkdir": r.Mkdir, "remove": r.Remove, "rename": r.Rename, "truncate": r.Truncate,
		"open for writing": r.OpenWrite, "symlink": r.Symlink, "chmod": r.Chmod,
		"tcp socket": r.TCP, "udp socket": r.UDP, "ptrace": r.Ptrace, "write /proc/self/mem": r.ProcMemWrite,
		"create in child": r.Inherit.Create, "tcp socket in child": r.Inherit.TCP,
	} {
		if e == "" {
			t.Errorf("%s was allowed", name)
		}
	}
	if r.Inherit.Seccomp != "2" || r.Inherit.NNP != "1" {
		t.Errorf("child seccomp=%s no_new_privs=%s", r.Inherit.Seccomp, r.Inherit.NNP)
	}
}

func checkVersions(t *testing.T, r childResult, allowStatic bool) {
	t.Helper()
	for name, v := range r.Helper {
		if v.Err != "" || v.ExitCode != 0 || v.Output == "" {
			t.Errorf("%s through the exec helper: exit %d err %q output %q", name, v.ExitCode, v.Err, v.Output)
		} else {
			t.Logf("%s through the exec helper: %s%s", name, firstLine(v.Output), fakeIdentity(v.Output))
		}
	}
	for _, v := range r.Artifacts {
		if v.Method != report.MethodExec || v.Version == "" {
			if !allowStatic {
				t.Errorf("version command of running %s: method %s version %q output %q", v.Path, v.Method, v.Version, v.Output)
			} else {
				t.Logf("running %s: version %q by %s (no exec)", v.Path, v.Version, v.Method)
			}
		} else {
			t.Logf("running %s: version %s by %s%s", v.Path, v.Version, v.Method, fakeIdentity(v.Output))
		}
	}
	if len(r.Helper) == 0 {
		t.Log("no runtime (java, node, php, python3) found; version commands not checked")
	}
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return l
}

// TestSandboxRoot checks the privilege drop. It runs only as root and only
// when asked to, for example inside a container:
//
//	CGO_ENABLED=0 go test -c -o probe.test ./internal/probe
//	docker run --rm -v $PWD/probe.test:/probe.test -e BOMCENSUS_PROBE_ROOT_TEST=1 IMAGE \
//	    /probe.test -test.run 'TestSandbox' -test.v
func TestSandboxRoot(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv(envRootTest) == "" {
		t.Skip("needs root and " + envRootTest + "=1")
	}
	before, err := currentCaps()
	if err != nil {
		t.Fatal(err)
	}
	r, _ := runRestrictedChild(t)
	s := r.Sandbox
	drop := before.permitted.has(unix.CAP_DAC_READ_SEARCH) && before.permitted.has(unix.CAP_SYS_PTRACE)
	var step SandboxStep
	for _, st := range s.Steps {
		if st.Name == "privileges" {
			step = st
		}
	}
	if drop {
		want := []string{"CAP_DAC_READ_SEARCH", "CAP_SYS_PTRACE"}
		if step.Status != StepApplied || s.UID != unprivilegedID || s.GID != unprivilegedID || len(s.Groups) != 0 {
			t.Errorf("drop: step %s, uid=%d gid=%d groups=%v", step.Status, s.UID, s.GID, s.Groups)
		}
		if !reflect.DeepEqual(s.Capabilities, want) {
			t.Errorf("capabilities = %v, want %v", s.Capabilities, want)
		}
		if before.effective.has(unix.CAP_SETPCAP) && !reflect.DeepEqual(s.Bounding, want) {
			t.Errorf("bounding set = %v", s.Bounding)
		}
		if len(s.Ambient) != 0 {
			t.Errorf("ambient = %v", s.Ambient)
		}
		if r.ProcOneExe != "" || r.ParentExe != "" {
			t.Errorf("other process unreadable with CAP_SYS_PTRACE: %s %s", r.ProcOneExe, r.ParentExe)
		}
		if r.Shadow != "" && !strings.Contains(r.Shadow, "no such file") {
			t.Errorf("/etc/shadow unreadable with CAP_DAC_READ_SEARCH: %s", r.Shadow)
		}
	} else {
		// Root without the two capabilities stays root with what it had.
		if step.Status != StepKept || s.UID != 0 {
			t.Errorf("keep: step %s (%s), uid=%d", step.Status, step.Detail, s.UID)
		}
		if got := capSetOf(s.Capabilities); got != before.effective {
			t.Errorf("capabilities changed: %v, before %v", s.Capabilities, before.effective.names())
		}
		if got := capSetOf(s.Bounding); got != before.bounding {
			t.Errorf("bounding set changed: %v", s.Bounding)
		}
		// The parent holds the same capabilities, so its link is readable.
		if r.ParentExe != "" {
			t.Errorf("parent exe unreadable as root with the same capabilities: %s", r.ParentExe)
		}
	}
	files := slices.Contains(r.Privilege.Capabilities, "CAP_DAC_READ_SEARCH") || slices.Contains(r.Privilege.Capabilities, "CAP_DAC_OVERRIDE")
	wantLevel := report.PrivilegeNonRoot
	if files && r.ProcOneExe == "" {
		wantLevel = report.PrivilegePrivileged
	}
	if r.Privilege.Level != wantLevel {
		t.Errorf("privilege level %s, want %s (%+v)", r.Privilege.Level, wantLevel, r.Privilege)
	}
	t.Logf("privileges: %s %s", step.Status, step.Detail)
	t.Logf("reported privilege: %+v", r.Privilege)
	t.Logf("/proc/1/exe: %q, /etc/shadow: %q, own executable %s", r.ProcOneExe, r.Shadow, r.SelfExe)
	var st unix.Stat_t
	if unix.Stat("/proc/self/exe", &st) == nil && st.Mode&0o001 == 0 && !strings.HasPrefix(r.SelfExe, "/memfd:") {
		t.Errorf("binary not executable by others, but the child was not re-executed from memory: %s", r.SelfExe)
	}
	if r.Sandbox.Seccomp != 2 {
		t.Skip("seccomp filters not available")
	}
	checkDenied(t, r)
	for name, e := range map[string]string{"read": r.Read, "unix socket": r.Unix, "memfd": r.Memfd, "exec": r.Exec} {
		if e != "" {
			t.Errorf("%s failed: %s", name, e)
		}
	}

	// Version commands run by the collector must run as nobody without
	// capabilities. Without CAP_SETUID the collector cannot switch and the
	// command does not run (static extraction is used instead).
	canSwitch := drop || (before.effective.has(unix.CAP_SETUID) && before.effective.has(unix.CAP_SETGID))
	checkVersions(t, r, !canSwitch)
	for _, v := range r.Artifacts {
		uid := strings.Fields(statusField(v.Output, "Uid"))
		if len(uid) > 0 && (uid[0] != strconv.Itoa(unprivilegedID) || statusField(v.Output, "CapEff") != "0000000000000000") {
			t.Errorf("version command of %s ran as %s", v.Path, fakeIdentity(v.Output))
		}
	}
}

func capSetOf(names []string) capSet {
	var s capSet
	for _, n := range names {
		if i := slices.Index(capNames, n); i >= 0 {
			s |= 1 << uint(i)
		}
	}
	return s
}

// fakeNodeSource is a program detected as node. Run without arguments it
// sleeps; with --version it prints a version and, on stderr, its own
// credentials, so that tests see whom a version command ran as.
const fakeNodeSource = `#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
	if (argc > 1 && strcmp(argv[1], "--version") == 0) {
		char line[256];
		FILE *f = fopen("/proc/self/status", "r");
		printf("v1.2.3\n");
		while (f && fgets(line, sizeof line, f))
			if (!strncmp(line, "Uid:", 4) || !strncmp(line, "CapEff:", 7) || !strncmp(line, "CapPrm:", 7) ||
			    !strncmp(line, "NoNewPrivs:", 11) || !strncmp(line, "Seccomp:", 8))
				fputs(line, stderr);
		return 0;
	}
	sleep(120);
	return 0;
}
`

// envFakeNode names a prebuilt fake node, for runs without a C compiler.
const envFakeNode = "BOMCENSUS_PROBE_TEST_FAKE_NODE"

// fakeNode returns a static build of fakeNodeSource, or "" when none can
// be built.
func fakeNode(t *testing.T) string {
	if p := os.Getenv(envFakeNode); p != "" {
		return p
	}
	cc, err := exec.LookPath("cc")
	if err != nil {
		return ""
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "node.c")
	os.WriteFile(src, []byte(fakeNodeSource), 0o644)
	out := filepath.Join(dir, "node")
	if b, err := exec.Command(cc, "-static", "-O2", "-o", out, src).CombinedOutput(); err != nil {
		t.Logf("fake node not built: %v %s", err, b)
		return ""
	}
	return out
}

// fakeIdentity extracts the credentials the fake node printed.
func fakeIdentity(out string) string {
	uid := statusField(out, "Uid")
	if uid == "" {
		return ""
	}
	return fmt.Sprintf(" [ran with Uid %s, CapEff %s, NoNewPrivs %s, Seccomp %s]",
		strings.Join(strings.Fields(uid), "/"), statusField(out, "CapEff"), statusField(out, "NoNewPrivs"), statusField(out, "Seccomp"))
}
