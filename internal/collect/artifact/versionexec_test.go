// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package artifact

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/report"
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
	start := time.Now()
	res := runHelper(t, lim, nil, "sleep")
	if res.Ran || !strings.Contains(res.Err, "timed out") {
		t.Fatalf("result = %+v", res)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("took %v", d)
	}
}

func TestRunVersionKillsGroup(t *testing.T) {
	start := time.Now()
	res := runHelper(t, defaultExecLimits, nil, "fork")
	if !res.Ran {
		t.Fatalf("not run: %s", res.Err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("waited %v for the left-behind child", d)
	}
	m := regexp.MustCompile(`child=(\d+)`).FindStringSubmatch(res.Output.Stdout)
	if m == nil {
		t.Fatalf("stdout = %q", res.Output.Stdout)
	}
	pid, _ := strconv.Atoi(m[1])
	deadline := time.Now().Add(3 * time.Second)
	for {
		b, err := os.ReadFile("/proc/" + m[1] + "/stat")
		if err != nil || strings.Contains(string(b), ") Z ") {
			return
		}
		if time.Now().After(deadline) {
			syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("child %d still running", pid)
		}
		time.Sleep(50 * time.Millisecond)
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
	res := runHelper(t, defaultExecLimits, nil, "status", target)
	if !res.Ran {
		t.Fatalf("not run: %s", res.Err)
	}
	out := res.Output.Stdout
	if v := statusField(out, "NoNewPrivs"); v != "1" {
		t.Errorf("NoNewPrivs = %q", v)
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
	if b, _ := os.ReadFile(target); len(b) != 0 {
		t.Errorf("command wrote %q", b)
	}
	if os.Geteuid() == 0 {
		ours, _ := os.Readlink("/proc/self/ns/net")
		t.Logf("network namespace: ours %s, command %s", ours, statusField(out, "netns"))
	}
	if pg := statusField(out, "NSpgid"); pg == "" || pg == strconv.Itoa(syscall.Getpgrp()) {
		t.Errorf("process group = %q, ours %d", pg, syscall.Getpgrp())
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
