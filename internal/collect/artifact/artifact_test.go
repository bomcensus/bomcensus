// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package artifact

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/collect"
	"github.com/bomcensus/bomcensus/internal/report"
)

// TestCollectSystem runs a full collection of the real root when
// BOMCENSUS_TEST_SYSTEM is set, and logs the software found. It is meant to
// be run inside a container image while writing detectors.
func TestCollectSystem(t *testing.T) {
	if os.Getenv("BOMCENSUS_TEST_SYSTEM") == "" {
		t.Skip("BOMCENSUS_TEST_SYSTEM is not set")
	}
	env := collect.NewEnv()
	sec := Collect(context.Background(), env, Inputs{})
	t.Logf("coverage %s %q, %d artifacts, %d ms", sec.Coverage, sec.Reason, len(sec.Artifacts), sec.DurationMs)
	for _, a := range sec.Artifacts {
		if a.Kind == "go_module" {
			continue
		}
		a.Nested = a.Nested[:min(len(a.Nested), 2)]
		b, _ := json.Marshal(a)
		t.Logf("%s", b)
	}
}

// TestCollectRunningPackageFile checks that a running executable which no
// detector recognizes is reported for its owning package, and that idle
// files of the package are not.
func TestCollectRunningPackageFile(t *testing.T) {
	src, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary")
	}
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	daemon := filepath.Join(dir, "sbin", "fake-sshd")
	idle := filepath.Join(dir, "sbin", "fake-ssh-keygen")
	os.MkdirAll(filepath.Dir(daemon), 0o755)
	for _, p := range []string{daemon, idle} {
		if err := os.WriteFile(p, data, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(daemon, "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if p, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid), "exe")); err == nil && p == daemon {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("process did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	in := Inputs{
		Owner: func(p string) (string, bool) {
			return "openssh-server", p == daemon || p == idle
		},
		Running: []RunningExe{{PID: cmd.Process.Pid, Path: daemon, State: report.ExeNormal}},
	}
	empty := t.TempDir()
	// Found by the walk, and, when the walk does not reach it, through /proc.
	for _, walk := range []string{dir, empty} {
		sec := testCollector(testEnv("/"), in, walk).run(context.Background())
		if len(sec.Artifacts) != 1 {
			t.Fatalf("walk %s: artifacts = %+v", walk, sec.Artifacts)
		}
		a := sec.Artifacts[0]
		if a.Kind != report.ArtifactPackageFile || a.Path != daemon || a.OwnerPackage != "openssh-server" ||
			!a.InUse || a.SHA256 == "" || a.Method != report.MethodPackageDB {
			t.Fatalf("walk %s: artifact = %+v", walk, a)
		}
	}

	// The file the process runs was replaced: the package's file is not the
	// one in memory, so it is not reported.
	in.Running[0].State = report.ExeReplaced
	if sec := testCollector(testEnv("/"), in, empty).run(context.Background()); len(sec.Artifacts) != 0 {
		t.Fatalf("replaced: artifacts = %+v", sec.Artifacts)
	}
}
