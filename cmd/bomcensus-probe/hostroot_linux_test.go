// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/sandbox/sandboxtest"
)

// Environment of TestCollectHostRoot (scripts/sandbox-matrix.sh host).
const (
	envHostRoot = "BOMCENSUS_TEST_HOST_ROOT"       // a read-only bind of /, with /proc below it
	envFakeNode = "BOMCENSUS_PROBE_TEST_FAKE_NODE" // internal/probe/testdata/fakenode
)

// TestCollectHostRoot runs collect --host-root as the node agent does,
// against the host's root file system mounted read-only: the probe must end
// up as uid 65534 with the two read capabilities, and the version command
// of a fake node that the walk finds in the host root must run as 65534
// without capabilities. A running process's executable reached through
// /proc/<pid>/exe is on a mount outside the host root and is identified
// statically only (SECURITY.md 6.6); the fake node runs as well, so the
// walk's result must replace that one.
func TestCollectHostRoot(t *testing.T) {
	root := os.Getenv(envHostRoot)
	if root == "" {
		t.Skip("needs " + envHostRoot + " (scripts/sandbox-matrix.sh host)")
	}
	if os.Geteuid() != 0 {
		t.Fatalf("needs root, running as uid %d", os.Geteuid())
	}
	fake := os.Getenv(envFakeNode)
	if fake == "" {
		t.Fatal("needs " + envFakeNode)
	}
	dir, err := os.MkdirTemp("", "hostroot-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	node := filepath.Join(dir, "bin", "node")
	if err := os.MkdirAll(filepath.Dir(node), 0o755); err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0o755)
	data, err := os.ReadFile(fake)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(node, sandboxtest.HideGoBuildInfo(data), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	for i := 0; ; i++ {
		if l, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", cmd.Process.Pid)); l == node {
			break
		}
		if i == 100 {
			t.Fatal("fake node did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}

	req := fmt.Sprintf(`{"sections":["host","processes","artifacts"],"policy":{"exec_version":true,"walk_paths":[%q]}}`, dir)
	out, stderr, code := runProbe(t, req, "collect", "--host-root", root, "--log-level", "debug")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	for _, want := range []string{"step=privileges status=applied", "step=seccomp status=applied"} {
		if !bytes.Contains(stderr, []byte(want)) {
			t.Errorf("log has no %q", want)
		}
	}
	rep, err := report.Decode(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("decode: %v\n%s", err, stderr)
	}
	if rep.Host == nil || rep.Host.Hostname == "" || rep.Artifacts == nil {
		t.Fatalf("report: host %+v, artifacts %v", rep.Host, rep.Artifacts != nil)
	}
	var found *report.Artifact
	for i, a := range rep.Artifacts.Artifacts {
		if a.Kind == report.ArtifactSoftware && a.Path == node {
			found = &rep.Artifacts.Artifacts[i]
		}
	}
	if found == nil {
		t.Fatalf("no artifact for the running %s\n%s", node, stderr)
	}
	if found.Method != report.MethodExec || found.Version != "1.2.3" || found.VersionOutput == nil {
		t.Fatalf("artifact = %+v\n%s", found, stderr)
	}
	ran := found.VersionOutput.Stderr
	field := func(k string) string {
		for line := range strings.SplitSeq(ran, "\n") {
			if v, ok := strings.CutPrefix(line, k+":"); ok {
				return strings.Join(strings.Fields(v), " ")
			}
		}
		return ""
	}
	if field("Uid") != "65534 65534 65534 65534" || field("CapEff") != "0000000000000000" ||
		field("CapPrm") != "0000000000000000" || field("NoNewPrivs") != "1" || field("Seccomp") != "2" {
		t.Errorf("version command ran with %q", ran)
	}
	t.Logf("%s: version %s by %s, %s", node, found.Version, found.Method, strings.ReplaceAll(strings.TrimSpace(ran), "\n", ", "))
}
