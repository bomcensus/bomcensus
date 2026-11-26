// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package artifact

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/bomcensus/bomcensus/internal/detectors"
	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/sandbox"
)

func runHelper(t *testing.T, lim execLimits, env []string, args ...string) execResult {
	t.Helper()
	bin := testHelperBinary(t)
	f, err := os.Open(bin)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	return runVersion(context.Background(), f, append([]string{bin}, args...), env, lim)
}

func TestRunVersionCapturesStreams(t *testing.T) {
	res := runHelper(t, defaultExecLimits, nil, "version")
	if !res.Ran {
		t.Fatalf("not run: %s", res.Err)
	}
	o := res.Output
	if o.Stdout != "fakesw version 1.2.3\n" || o.Stderr != "some warning\n" || o.ExitCode != 3 || o.Truncated {
		t.Fatalf("output = %+v", o)
	}
	if o.Command[1] != "version" {
		t.Fatalf("command = %v", o.Command)
	}
}

func TestRunVersionTruncates(t *testing.T) {
	res := runHelper(t, defaultExecLimits, nil, "big")
	if !res.Ran {
		t.Fatalf("not run: %s", res.Err)
	}
	o := res.Output
	if len(o.Stdout) != 64<<10 || len(o.Stderr) != 64<<10 || !o.Truncated {
		t.Fatalf("stdout %d, stderr %d, truncated %v", len(o.Stdout), len(o.Stderr), o.Truncated)
	}
}

func TestRunVersionTimeout(t *testing.T) {
	lim := defaultExecLimits
	lim.Timeout = 500 * time.Millisecond
	for _, mode := range []string{"sleep", "flood"} {
		start := time.Now()
		res := runHelper(t, lim, nil, mode)
		if res.Ran || !strings.Contains(res.Err, "timed out") {
			t.Fatalf("%s: result = %+v", mode, res)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("%s: took %v", mode, d)
		}
	}
}

// helperLines parses the name=result lines of the hostile helper modes.
func helperLines(t *testing.T, res execResult) map[string]string {
	t.Helper()
	if !res.Ran {
		t.Fatalf("not run: %s", res.Err)
	}
	out := map[string]string{}
	for line := range strings.SplitSeq(res.Output.Stdout, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			out[k] = v
		}
	}
	return out
}

// requireDenied fails for every name whose attempt was not denied.
func requireDenied(t *testing.T, got map[string]string, names ...string) {
	t.Helper()
	for _, n := range names {
		if v, ok := got[n]; !ok || !strings.HasPrefix(v, "denied") {
			t.Errorf("%s: %q", n, v)
		}
	}
}

// requireGone fails when a child the command reported is still running.
func requireGone(t *testing.T, res execResult) {
	t.Helper()
	for _, m := range regexp.MustCompile(`child=(\d+)`).FindAllStringSubmatch(res.Output.Stdout, -1) {
		pid, _ := strconv.Atoi(m[1])
		deadline := time.Now().Add(3 * time.Second)
		for {
			b, err := os.ReadFile("/proc/" + m[1] + "/stat")
			if err != nil || strings.Contains(string(b), ") Z ") {
				break
			}
			if time.Now().After(deadline) {
				syscall.Kill(pid, syscall.SIGKILL)
				t.Errorf("child %d still running", pid)
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}

func TestRunVersionNoNewProcesses(t *testing.T) {
	for _, mode := range []string{"fork", "forkbomb", "daemon"} {
		start := time.Now()
		res := runHelper(t, defaultExecLimits, nil, mode)
		got := helperLines(t, res)
		requireGone(t, res)
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s: waited %v", mode, d)
		}
		switch mode {
		case "fork":
			requireDenied(t, got, "fork")
		case "forkbomb":
			requireDenied(t, got, "forkbomb")
			if got["forks"] != "0" {
				t.Errorf("forkbomb: %s processes started", got["forks"])
			}
		case "daemon":
			requireDenied(t, got, "setsid", "setpgid", "daemon")
		}
	}
}

// startSibling starts a process that runs as the user version commands run
// as: nobody when the test is root, else the test user.
func startSibling(t *testing.T) int {
	t.Helper()
	cmd := exec.Command(testHelperBinary(t), "sleep")
	if os.Geteuid() == 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: nobodyID, Gid: nobodyID, Groups: []uint32{}}}
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	return cmd.Process.Pid
}

func alive(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	// State after the command name: R, S, D are fine; T means stopped.
	_, rest, _ := strings.Cut(string(b), ") ")
	return strings.HasPrefix(rest, "R") || strings.HasPrefix(rest, "S") || strings.HasPrefix(rest, "D")
}

func TestRunVersionCannotReachOthers(t *testing.T) {
	landlock := sandbox.LandlockABI() > 0
	sibling := startSibling(t)
	for name, pid := range map[string]int{"sibling": sibling, "caller": os.Getpid()} {
		got := helperLines(t, runHelper(t, defaultExecLimits, nil, "attack", strconv.Itoa(pid)))
		t.Logf("%s: %v", name, got)
		requireDenied(t, got, "kill0", "kill", "killgroup", "killall", "tgkill", "ptrace", "prlimit", "setpriority", "setpriority_user", "mem")
		if landlock {
			requireDenied(t, got, "environ")
		} else if os.Geteuid() != 0 {
			// Without Landlock only the kernel's ptrace access rules
			// protect another dumpable process of the same user.
			t.Logf("%s: no Landlock; environ %s", name, got["environ"])
		}
		if !alive(pid) {
			t.Fatalf("%s %d was killed or stopped", name, pid)
		}
	}
}

func TestRunVersionNetwork(t *testing.T) {
	got := helperLines(t, runHelper(t, defaultExecLimits, nil, "net"))
	requireDenied(t, got, "tcp", "udp6", "unix", "netlink")
	if got["socketpair"] != "allowed" {
		t.Errorf("socketpair: %q", got["socketpair"])
	}
}

func TestRunVersionEnvironment(t *testing.T) {
	t.Setenv("BOMCENSUS_TEST_SECRET", "leak")
	res := runHelper(t, defaultExecLimits, []string{"JAVA_HOME=/opt/jdk"}, "env")
	if !res.Ran {
		t.Fatalf("not run: %s", res.Err)
	}
	if res.Output.Stdout != "JAVA_HOME=/opt/jdk\n" {
		t.Fatalf("environment = %q", res.Output.Stdout)
	}
}

func TestRunVersionRestrictions(t *testing.T) {
	target := filepath.Join(t.TempDir(), "written")
	// A descriptor without close-on-exec, as a parent of the probe may
	// leave one: it must not reach the command.
	leak, err := syscall.Open("/proc/self/status", syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(leak)
	res := runHelper(t, defaultExecLimits, nil, "status", target)
	if !res.Ran {
		t.Fatalf("not run: %s", res.Err)
	}
	out := res.Output.Stdout
	if v := statusField(out, "NoNewPrivs"); v != "1" {
		t.Errorf("NoNewPrivs = %q", v)
	}
	if v := statusField(out, "Seccomp"); v != "2" {
		t.Errorf("Seccomp = %q", v)
	}
	for _, k := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb"} {
		if v := statusField(out, k); v != "0000000000000000" {
			t.Errorf("%s = %q", k, v)
		}
	}
	if os.Geteuid() == 0 {
		if v := statusField(out, "Uid"); !strings.HasPrefix(v, "65534") {
			t.Errorf("Uid = %q", v)
		}
		if v := statusField(out, "Groups"); v != "" {
			t.Errorf("Groups = %q", v)
		}
	}
	for _, want := range []string{
		`Max cpu time\s+10\s+10 `,
		`Max file size\s+0\s+0 `,
		`Max open files\s+64\s+64 `,
		`Max address space\s+2147483648\s+2147483648 `,
		`Max core file size\s+0\s+0 `,
		`Max processes\s+\d+\s+\d+ `,
	} {
		if !regexp.MustCompile(want).MatchString(out) {
			t.Errorf("limits do not match %q", want)
		}
	}
	if !strings.Contains(out, "stdin=/dev/null\n") {
		t.Errorf("stdin is not /dev/null")
	}
	if v := statusField(out, "fds"); v != "0,1,2" {
		t.Errorf("open descriptors %q, want 0,1,2", v)
	}
	if v := statusField(out, "cwd"); v != "/" {
		t.Errorf("cwd %q", v)
	}
	if !strings.Contains(out, "write=") || strings.Contains(out, "write=<nil>") {
		t.Errorf("write not denied: %q", out[strings.LastIndex(out, "write"):])
	}
	if b, _ := os.ReadFile(target); len(b) != 0 {
		t.Errorf("command wrote %q", b)
	}
	if os.Geteuid() == 0 {
		ours, _ := os.Readlink("/proc/self/ns/net")
		t.Logf("network namespace: ours %s, command %s", ours, statusField(out, "netns"))
	}
	pg, sid := statusField(out, "NSpgid"), statusField(out, "sid")
	if pg == "" || pg == strconv.Itoa(syscall.Getpgrp()) || sid != pg {
		t.Errorf("process group %q, session %q, ours %d", pg, sid, syscall.Getpgrp())
	}
}

func TestCommandSandboxCheck(t *testing.T) {
	self, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	checks, err := CheckCommandSandbox(context.Background(), self)
	if err != nil {
		t.Fatal(err)
	}
	landlock := sandbox.LandlockABI() > 0
	for _, c := range checks {
		switch {
		case c.OK:
			t.Logf("%-40s ok %s", c.Name, c.Detail)
		case !landlock && c.Name == "read another process's environment":
			t.Logf("%-40s allowed without Landlock: %s", c.Name, c.Detail)
		default:
			t.Errorf("%s: %s", c.Name, c.Detail)
		}
	}
	if len(checks) < 20 {
		t.Errorf("only %d checks", len(checks))
	}
}

func TestExecutable(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) *os.File {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o755); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		return f
	}
	native := tinyELF(t, "x\n", "", 0)
	if err := executable(write("native", native)); err != nil {
		t.Errorf("native ELF refused: %v", err)
	}
	class32 := slices.Clone(native)
	class32[4] = 1 // ELFCLASS32
	for name, data := range map[string][]byte{
		"foreign":  tinyELF(t, "x\n", "", 0x28),
		"32-bit":   class32,
		"script":   []byte("#!/bin/sh\necho 1.0\n"),
		"short":    []byte("\x7fELF"),
		"big end":  append(slices.Clone(native[:5]), append([]byte{2}, native[6:]...)...),
		"not elf":  []byte(strings.Repeat("x", 64)),
		"x32 like": append(slices.Clone(class32[:18]), class32[18:]...),
	} {
		if err := executable(write(name, data)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}

	// A memory file is on a kernel-internal mount, outside the mount
	// namespace, like the executable of a container process.
	fd, err := unix.MemfdCreate("exec-test", unix.MFD_CLOEXEC)
	if err != nil {
		t.Skip("memfd_create:", err)
	}
	mem := os.NewFile(uintptr(fd), "memfd")
	defer mem.Close()
	mem.Write(native)
	if err := executable(mem); err == nil || !strings.Contains(err.Error(), "mount namespace") {
		t.Errorf("memory file: %v", err)
	}
}

func TestRunVersionExecFailure(t *testing.T) {
	// Text without an interpreter line cannot be executed.
	p := filepath.Join(t.TempDir(), "notexec")
	if err := os.WriteFile(p, []byte("not a program\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	res := runVersion(context.Background(), f, []string{p, "-v"}, nil, defaultExecLimits)
	if res.Ran || !strings.Contains(res.Err, "exec helper") {
		t.Fatalf("result = %+v", res)
	}
}

// fakeDetector matches the tiny ELF.
func fakeDetector() *Detector {
	return &Detector{
		ID:    "fakesw",
		Name:  "fakesw",
		Names: []string{"fakesw"},
		Exec:  []string{"--version"},
		Env:   []EnvVar{{Name: "FAKE_HOME", Up: 2}},
		Parse: []Rule{{Pattern: re(`fakesw (\d+\.\d+\.\d+)`)}},
		Static: []StaticRule{
			{Rules: []Rule{{Pattern: re(`FAKESW_STATIC=(\d+\.\d+\.\d+)`)}}},
		},
		PURL: "pkg:generic/fakesw@{version}",
		CPE:  "cpe:2.3:a:fake:fakesw:{version}:*:*:*:*:*:*:*",
	}
}

func writeTinyELF(t *testing.T, dir string, machine uint16) string {
	t.Helper()
	bin := filepath.Join(dir, "opt", "fake", "bin", "fakesw")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, tinyELF(t, "fakesw 4.5.6\n", "\x00FAKESW_STATIC=4.5.0\x00", machine), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func findSoftware(t *testing.T, sec *report.ArtifactsSection, id string) report.Artifact {
	t.Helper()
	for _, a := range sec.Artifacts {
		if a.Kind == report.ArtifactSoftware && a.Detector == id {
			return a
		}
	}
	t.Fatalf("no %s artifact in %+v", id, sec.Artifacts)
	return report.Artifact{}
}

func TestCollectExecAndStatic(t *testing.T) {
	dir := t.TempDir()
	bin := writeTinyELF(t, dir, 0)
	env := testEnv("/")
	c := testCollector(env, Inputs{}, dir, fakeDetector())
	a := findSoftware(t, c.run(context.Background()), "fakesw")
	if a.Method != report.MethodExec || a.Version != "4.5.6" || a.StaticVersion != "4.5.0" {
		t.Fatalf("artifact = %+v", a)
	}
	if a.Path != bin || a.SHA256 == "" || a.PURL != "pkg:generic/fakesw@4.5.6" ||
		a.CPE != "cpe:2.3:a:fake:fakesw:4.5.6:*:*:*:*:*:*:*" {
		t.Fatalf("artifact = %+v", a)
	}
	if o := a.VersionOutput; o == nil || o.Stdout != "fakesw 4.5.6\n" || o.Command[0] != bin || o.Command[1] != "--version" {
		t.Fatalf("version output = %+v", a.VersionOutput)
	}

	// The second run uses the cached result even if execution is now
	// impossible.
	c2 := testCollector(env, Inputs{}, dir, fakeDetector())
	c2.exec.Timeout = 0
	if b := findSoftware(t, c2.run(context.Background()), "fakesw"); b.Method != report.MethodExec || b.Version != "4.5.6" {
		t.Fatalf("cached artifact = %+v", b)
	}
}

func TestCollectExecDisabled(t *testing.T) {
	dir := t.TempDir()
	writeTinyELF(t, dir, 0)
	env := testEnv("/")
	env.Policy.ExecVersion = false
	a := findSoftware(t, testCollector(env, Inputs{}, dir, fakeDetector()).run(context.Background()), "fakesw")
	if a.Method != report.MethodStatic || a.Version != "4.5.0" || a.VersionOutput != nil || a.StaticVersion != "" {
		t.Fatalf("artifact = %+v", a)
	}
}

func TestCollectExecNotOnContainerRoot(t *testing.T) {
	dir := t.TempDir()
	writeTinyELF(t, dir, 0)
	env := testEnv(dir)
	a := findSoftware(t, testCollector(env, Inputs{}, "/", fakeDetector()).run(context.Background()), "fakesw")
	if a.Method != report.MethodStatic || a.Version != "4.5.0" || a.Path != "/opt/fake/bin/fakesw" {
		t.Fatalf("artifact = %+v", a)
	}
}

func TestCollectExecFailureFallsBack(t *testing.T) {
	dir := t.TempDir()
	// An ELF for another machine cannot be executed here.
	writeTinyELF(t, dir, 0x28)
	env := testEnv("/")
	a := findSoftware(t, testCollector(env, Inputs{}, dir, fakeDetector()).run(context.Background()), "fakesw")
	if a.Method != report.MethodStatic || a.Version != "4.5.0" || a.VersionOutput != nil {
		t.Fatalf("artifact = %+v", a)
	}
}

func TestDetectorEnv(t *testing.T) {
	if got := parentDir("/opt/jdk-17/bin/java", 2); got != "/opt/jdk-17" {
		t.Fatalf("parentDir = %q", got)
	}
}

func TestInitPIDNamespace(t *testing.T) {
	proc := t.TempDir()
	if initPIDNamespace(proc) {
		t.Error("no pid 2: initial namespace")
	}
	os.MkdirAll(filepath.Join(proc, "2"), 0o755)
	os.WriteFile(filepath.Join(proc, "2", "status"), []byte("Name:\tsleep\nPPid:\t1\n"), 0o644)
	if initPIDNamespace(proc) {
		t.Error("pid 2 is not kthreadd: initial namespace")
	}
	os.WriteFile(filepath.Join(proc, "2", "status"), []byte("Name:\tkthreadd\nPPid:\t0\n"), 0o644)
	if !initPIDNamespace(proc) {
		t.Error("kthreadd as pid 2: not the initial namespace")
	}
}

func TestCollectExecFileChanged(t *testing.T) {
	dir := t.TempDir()
	bin := writeTinyELF(t, dir, 0)
	f, err := os.Open(bin)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	before, _ := f.Stat()
	// Written to after it was inspected: the output may belong to other
	// content than the hash.
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(bin, tinyELF(t, "fakesw 9.9.9\n", "", 0), 0o755); err != nil {
		t.Fatal(err)
	}
	c := testCollector(testEnv("/"), Inputs{}, dir, fakeDetector())
	res := c.versionCommand(context.Background(), fakeDetector(), bin, f, before)
	if res.Ran || !strings.Contains(res.Err, "changed") {
		t.Fatalf("result = %+v", res)
	}
	after, _ := f.Stat()
	if changedSince(after, after) {
		t.Error("unchanged file reported as changed")
	}
}

// TestCollectExecSuppliedTable: a detector of a server table whose exec
// fields equal the built-in entry runs its version command through the same
// helper and checks as a built-in one; with other exec arguments it is
// static only.
func TestCollectExecSuppliedTable(t *testing.T) {
	var spec report.DetectorSpec
	for _, d := range detectors.Builtin().Detectors {
		if d.ID == "nodejs" {
			spec = d
		}
	}
	if len(spec.Exec) == 0 {
		t.Fatal("no built-in nodejs detector with a version command")
	}
	// Parse and static rules may differ; they only read data.
	spec.Parse = []report.DetectorRule{{Pattern: `fakesw (\d+\.\d+\.\d+)`}}
	spec.Static = []report.DetectorStatic{{Rules: []report.DetectorRule{{Pattern: `FAKESW_STATIC=(\d+\.\d+\.\d+)`}}}}

	dir := t.TempDir()
	bin := filepath.Join(dir, "opt", "node", "bin", "node")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, tinyELF(t, "fakesw 4.5.6\n", "\x00FAKESW_STATIC=4.5.0\x00", 0), 0o755); err != nil {
		t.Fatal(err)
	}

	dets := loadOne(t, spec)
	if len(dets) != 1 || !dets[0].constrained || len(dets[0].Exec) == 0 {
		t.Fatalf("detectors = %+v", dets)
	}
	a := findSoftware(t, testCollector(testEnv("/"), Inputs{}, dir, dets...).run(context.Background()), "nodejs")
	if a.Method != report.MethodExec || a.Version != "4.5.6" || a.VersionOutput == nil {
		t.Fatalf("artifact = %+v", a)
	}

	// Other exec arguments: the command does not run.
	spec.Exec = []string{"--eval", "1"}
	r := detectors.Resolve(&report.DetectorTable{SchemaVersion: report.DetectorSchemaVersion, Detectors: []report.DetectorSpec{spec}})
	if !slices.Equal(r.Use.StaticOnly, []string{"nodejs"}) {
		t.Fatalf("use = %+v", r.Use)
	}
	dets = Load(r)
	if len(dets) != 1 || len(dets[0].Exec) != 0 {
		t.Fatalf("detectors = %+v", dets)
	}
	a = findSoftware(t, testCollector(testEnv("/"), Inputs{}, dir, dets...).run(context.Background()), "nodejs")
	if a.Method != report.MethodStatic || a.Version != "4.5.0" || a.VersionOutput != nil {
		t.Fatalf("artifact = %+v", a)
	}
}
