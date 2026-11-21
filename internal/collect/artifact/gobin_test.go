// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package artifact

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/report"
)

const goProgram = `package main

import (
	"os"
	"time"

	"github.com/klauspost/compress/zstd"
)

func main() {
	_ = zstd.SpeedDefault
	if len(os.Args) > 1 {
		time.Sleep(time.Minute)
	}
}
`

// buildGoBinary builds a program that depends on a module the repository
// already requires, so that it builds from the module cache without network.
func buildGoBinary(t *testing.T) string {
	t.Helper()
	sum, err := os.Open(filepath.Join("..", "..", "..", "go.sum"))
	if err != nil {
		t.Skip("repository go.sum not found")
	}
	defer sum.Close()
	var lines []string
	sc := bufio.NewScanner(sum)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "github.com/klauspost/compress v1.20.5") {
			lines = append(lines, sc.Text())
		}
	}
	dir := t.TempDir()
	bin, err := goBuild(dir, map[string]string{
		"main.go": goProgram,
		"go.mod":  "module example.com/gotool\n\ngo 1.22\n\nrequire github.com/klauspost/compress v1.20.5\n",
		"go.sum":  strings.Join(lines, "\n") + "\n",
	}, "gotool")
	if err != nil {
		t.Skipf("cannot build offline: %v", err)
	}
	return bin
}

func TestCollectGoBinary(t *testing.T) {
	bin := buildGoBinary(t)
	env := testEnv("/")
	sec := testCollector(env, Inputs{}, filepath.Dir(bin)).run(context.Background())
	var main report.Artifact
	mods := map[string]string{}
	for _, a := range sec.Artifacts {
		switch a.Kind {
		case report.ArtifactGoBinary:
			main = a
		case report.ArtifactGoModule:
			if a.Path != bin || a.Nested != nil || a.Method != report.MethodBuildInfo {
				t.Errorf("module = %+v", a)
			}
			mods[a.Module] = a.Version
		}
	}
	if main.Path != bin || main.Name != "example.com/gotool" || main.Module != "example.com/gotool" ||
		main.GoVersion != runtime.Version() || main.SHA256 == "" || main.Method != report.MethodBuildInfo {
		t.Fatalf("binary = %+v", main)
	}
	if mods["github.com/klauspost/compress"] != "v1.20.5" {
		t.Fatalf("modules = %v", mods)
	}
}

func TestCollectRunningDeleted(t *testing.T) {
	bin := buildGoBinary(t)
	cmd := exec.Command(bin, "sleep")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()
	// Wait until the process runs the binary, then delete it.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if p, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid), "exe")); err == nil && p == bin {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("process did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := os.Remove(bin); err != nil {
		t.Fatal(err)
	}
	env := testEnv("/")
	in := Inputs{Running: []RunningExe{{PID: cmd.Process.Pid, Path: bin + " (deleted)", State: report.ExeDeleted}}}
	sec := testCollector(env, in, filepath.Dir(bin)).run(context.Background())
	found := false
	for _, a := range sec.Artifacts {
		if a.Kind == report.ArtifactGoBinary {
			found = true
			if a.Path != bin || !a.InUse || a.SHA256 == "" {
				t.Fatalf("binary = %+v", a)
			}
		}
	}
	if !found {
		t.Fatalf("running binary not reported: %+v", sec.Artifacts)
	}
}
