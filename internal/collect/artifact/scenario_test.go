// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package artifact

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/sandbox/sandboxtest"
)

// TestSandboxScenario checks what the scenario of scripts/sandbox-matrix.sh
// promises for version commands: whom they run as, with which restrictions
// and network namespace, or that none runs and static extraction is used.
func TestSandboxScenario(t *testing.T) {
	sc, ok := sandboxtest.Current(t)
	if !ok {
		t.Skip("runs in scripts/sandbox-matrix.sh only (" + sandboxtest.EnvScenario + ")")
	}
	if sc.Root() != (os.Geteuid() == 0) {
		t.Fatalf("scenario %s, running as uid %d", sc.Name, os.Geteuid())
	}
	abi := sandboxtest.LandlockABI(t)

	res := runHelper(t, defaultExecLimits, nil, "status")
	if !sc.CommandsRun() {
		if res.Ran || !strings.Contains(res.Err, "operation not permitted") {
			t.Fatalf("version command started as root without CAP_SETUID: %+v", res)
		}
		t.Logf("not run: %s", res.Err)
		// The collector falls back to static extraction.
		dir := t.TempDir()
		writeTinyELF(t, dir, 0)
		a := findSoftware(t, testCollector(testEnv("/"), Inputs{}, dir, fakeDetector()).run(context.Background()), "fakesw")
		if a.Method != report.MethodStatic || a.Version != "4.5.0" || a.VersionOutput != nil {
			t.Fatalf("artifact = %+v", a)
		}
		return
	}
	if !res.Ran {
		t.Fatalf("not run: %s", res.Err)
	}
	out := res.Output.Stdout
	uid := strconv.Itoa(sc.CommandUID())
	if v := strings.Fields(statusField(out, "Uid")); len(v) != 4 || strings.Join(v, " ") != strings.Repeat(uid+" ", 3)+uid {
		t.Errorf("Uid %v, want %s", v, uid)
	}
	if v := strings.Fields(statusField(out, "Gid")); sc.Root() && (len(v) != 4 || v[0] != uid) {
		t.Errorf("Gid %v, want %s", v, uid)
	}
	if v := statusField(out, "Groups"); sc.Root() && v != "" {
		t.Errorf("Groups %q", v)
	}
	for _, k := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb"} {
		if v := statusField(out, k); v != "0000000000000000" {
			t.Errorf("%s = %q", k, v)
		}
	}
	if v := statusField(out, "NoNewPrivs"); v != "1" {
		t.Errorf("NoNewPrivs = %q", v)
	}
	if v := statusField(out, "Seccomp"); v != "2" {
		t.Errorf("Seccomp = %q", v)
	}
	ours, _ := os.Readlink("/proc/self/ns/net")
	theirs := statusField(out, "netns")
	if (theirs != ours) != sc.NetNS {
		t.Errorf("network namespace: ours %s, command %s; new namespace expected: %v", ours, theirs, sc.NetNS)
	}
	t.Logf("command: uid %s, network namespace %s (ours %s), Landlock ABI %d", uid, theirs, ours, abi)

	// Landlock is what keeps a command from another process of its own
	// uid (the sibling); the uid change alone protects the caller.
	if abi > 0 {
		got := helperLines(t, runHelper(t, defaultExecLimits, nil, "attack", strconv.Itoa(startSibling(t))))
		requireDenied(t, got, "environ", "mem", "ptrace", "kill", "kill0", "tgkill")
	}
}

// TestRunVersionEnvironmentNotInherited: variables of the probe's own
// environment reach neither the version command nor the exec helper, a Go
// program that runs before its restrictions. GODEBUG=inittrace=1 makes any
// Go runtime that inherits it print a line per package on standard error,
// which is the command's captured standard error.
func TestRunVersionEnvironmentNotInherited(t *testing.T) {
	for k, v := range map[string]string{
		"GODEBUG":               "inittrace=1",
		"GOTRACEBACK":           "crash",
		"LD_PRELOAD":            "/nonexistent/libbomcensus-test.so",
		"LD_LIBRARY_PATH":       "/nonexistent",
		"BOMCENSUS_TEST_SECRET": "leak",
	} {
		t.Setenv(k, v)
	}
	if os.Getenv("LD_PRELOAD") == "" {
		t.Fatal("environment not set")
	}

	// Through the collector, with a detector variable.
	dir := t.TempDir()
	bin := filepath.Join(dir, "opt", "fake", "bin", "fakesw")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(testHelperBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, data, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(bin)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	d := &Detector{ID: "fakesw-env", Name: "fakesw", Names: []string{"fakesw"}, Exec: []string{"env"},
		Env: []EnvVar{{Name: "FAKE_HOME", Up: 2}}}
	c := testCollector(testEnv("/"), Inputs{}, dir, d)
	res := c.versionCommand(context.Background(), d, bin, f, fi)
	if !res.Ran {
		t.Fatalf("not run: %s", res.Err)
	}
	want := "FAKE_HOME=" + filepath.Join(dir, "opt", "fake") + "\n"
	if res.Output.Stdout != want {
		t.Errorf("environment = %q, want %q", res.Output.Stdout, want)
	}
	if res.Output.Stderr != "" {
		t.Errorf("standard error %q: the helper or the command saw the probe's environment", res.Output.Stderr)
	}

	// Without detector variables the environment is empty.
	res = runHelper(t, defaultExecLimits, nil, "env")
	if !res.Ran || res.Output.Stdout != "" || res.Output.Stderr != "" {
		t.Errorf("empty environment: %+v %+v", res, res.Output)
	}

	// The control: the same command with GODEBUG passed explicitly prints
	// the trace, so an empty standard error above means it was not there.
	res = runHelper(t, defaultExecLimits, []string{"GODEBUG=inittrace=1"}, "env")
	if !res.Ran || !strings.Contains(res.Output.Stderr, "init ") {
		t.Errorf("GODEBUG=inittrace=1 passed explicitly left no trace: %+v", res.Output)
	}
}
