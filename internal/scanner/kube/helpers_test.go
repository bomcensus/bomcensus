// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package kube

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	utilexec "k8s.io/client-go/util/exec"
)

// localExecutor runs exec sessions as local processes. "sh" in the command
// is replaced by shell.
type localExecutor struct {
	shell []string
	env   []string

	mu         sync.Mutex
	calls      int
	stdinBytes int64
}

type countingReader struct {
	r io.Reader
	e *localExecutor
}

func (c countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.e.mu.Lock()
	c.e.stdinBytes += int64(n)
	c.e.mu.Unlock()
	return n, err
}

func (e *localExecutor) Exec(ctx context.Context, r ExecRequest) error {
	argv := slices.Clone(r.Command)
	if len(argv) > 0 && argv[0] == "sh" && len(e.shell) > 0 {
		argv = append(slices.Clone(e.shell), argv[1:]...)
	}
	e.mu.Lock()
	e.calls++
	e.mu.Unlock()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdout, cmd.Stderr = r.Stdout, r.Stderr
	if e.env != nil {
		cmd.Env = e.env
	}
	cmd.WaitDelay = time.Second
	// Copy stdin ourselves: os/exec waits for its own stdin goroutine, which
	// stays blocked on an io.Pipe after the process exited.
	var stdin io.WriteCloser
	if r.Stdin != nil {
		w, err := cmd.StdinPipe()
		if err != nil {
			return err
		}
		stdin = w
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	if stdin != nil {
		go func() {
			io.Copy(stdin, countingReader{r.Stdin, e})
			stdin.Close()
		}()
	}
	err := cmd.Wait()
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() >= 0 {
		return utilexec.CodeExitError{Err: fmt.Errorf("command terminated with exit code %d", ee.ExitCode()), Code: ee.ExitCode()}
	}
	return err
}

func (e *localExecutor) counts() (calls int, stdinBytes int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls, e.stdinBytes
}

// testShells lists the shells available on this machine: /bin/sh, dash,
// bash and busybox sh (BOMCENSUS_TEST_BUSYBOX can point to a busybox
// binary).
func testShells(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	if _, err := os.Stat("/bin/sh"); err == nil {
		out["sh"] = []string{"/bin/sh"}
	}
	for _, name := range []string{"dash", "bash"} {
		if p, err := exec.LookPath(name); err == nil {
			out[name] = []string{p}
		}
	}
	bb := os.Getenv("BOMCENSUS_TEST_BUSYBOX")
	if bb == "" {
		bb, _ = exec.LookPath("busybox")
	}
	if bb != "" {
		out["busybox"] = []string{bb, "sh"}
	}
	if len(out) == 0 {
		t.Skip("no shell available")
	}
	return out
}

// toolPath builds a directory holding links to the given tools, for running
// the script with a reduced PATH.
func toolPath(t *testing.T, tools ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range tools {
		p, err := exec.LookPath(name)
		if err != nil {
			t.Skipf("tool %s not available", name)
		}
		if err := os.Symlink(p, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

var (
	fakeProbeMu    sync.Mutex
	fakeProbeCache = map[string][]byte{}
)

// fakeProbeELF builds testdata/fakeprobe for linux/goarch (unsigned).
func fakeProbeELF(t testing.TB, goarch string) []byte {
	t.Helper()
	fakeProbeMu.Lock()
	defer fakeProbeMu.Unlock()
	if b, ok := fakeProbeCache[goarch]; ok {
		return slices.Clone(b)
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not available")
	}
	dir, err := os.MkdirTemp("", "kube-fakeprobe-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	out := filepath.Join(dir, "fakeprobe")
	cmd := exec.Command(goBin, "build", "-trimpath", "-ldflags=-s -w", "-o", out, "./testdata/fakeprobe")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fake probe: %v\n%s", err, b)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	fakeProbeCache[goarch] = b
	return slices.Clone(b)
}

// dirEntries lists the names in dir.
func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

// processesRunningFrom returns pids whose executable lives under dir.
func processesRunningFrom(dir string) []string {
	ents, _ := os.ReadDir("/proc")
	var out []string
	for _, e := range ents {
		exe, err := os.Readlink(filepath.Join("/proc", e.Name(), "exe"))
		if err != nil {
			continue
		}
		if strings.HasPrefix(exe, dir+"/") {
			out = append(out, e.Name()+" "+exe)
		}
	}
	return out
}

// waitFor polls cond for up to d.
func waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cond()
}
