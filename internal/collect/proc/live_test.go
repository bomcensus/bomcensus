// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package proc

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/collect"
	"github.com/bomcensus/bomcensus/internal/report"
)

// helperEnv makes the test binary act as a child process for the tests
// below instead of running the tests.
const helperEnv = "BOMCENSUS_PROC_TEST_HELPER"

func TestMain(m *testing.M) {
	switch os.Getenv(helperEnv) {
	case "":
		os.Exit(m.Run())
	case "listen":
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fmt.Println("error", err)
			os.Exit(1)
		}
		fmt.Println("port", ln.Addr().(*net.TCPAddr).Port)
		waitForParent()
	default:
		fmt.Println("ready")
		waitForParent()
	}
	os.Exit(0)
}

// waitForParent returns when the parent closes standard input, or after a
// while so that a crashed test leaves no process behind.
func waitForParent() {
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Minute):
	}
}

type helper struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	line  string
}

// startHelper runs exe in helper mode and returns its first output line.
func startHelper(t *testing.T, exe, mode string) *helper {
	t.Helper()
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), helperEnv+"="+mode)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start helper process: %v", err)
	}
	h := &helper{cmd: cmd, stdin: stdin}
	t.Cleanup(func() {
		h.stdin.Close()
		_ = h.cmd.Wait()
	})
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Skipf("helper process did not start: %v", err)
	}
	h.line = strings.TrimSpace(line)
	return h
}

// liveCache is shared by the tests on the real /proc so that every running
// executable is hashed once.
var liveCache = collect.NewHashCache()

func liveEnv(t *testing.T) *collect.Env {
	t.Helper()
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("no /proc")
	}
	env := collect.NewEnv()
	env.Cache = liveCache
	env.Privileged = os.Geteuid() == 0
	return env
}

func TestLiveListen(t *testing.T) {
	env := liveEnv(t)
	self, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	h := startHelper(t, self, "listen")
	portStr, ok := strings.CutPrefix(h.line, "port ")
	if !ok {
		t.Skipf("helper cannot listen: %s", h.line)
	}
	port, _ := strconv.Atoi(portStr)

	sec := Collect(context.Background(), env)
	p := findProc(sec, h.cmd.Process.Pid)
	if p == nil {
		t.Fatalf("helper pid %d not found", h.cmd.Process.Pid)
	}
	if p.ExeSource != report.ExeFromProc || p.ExeState != report.ExeNormal || p.SHA256 == "" {
		t.Errorf("helper exe: %+v", p)
	}
	if p.PPID != os.Getpid() || p.UID != os.Geteuid() {
		t.Errorf("helper ppid %d uid %d", p.PPID, p.UID)
	}
	if time.Since(p.StartedAt) > time.Minute || time.Until(p.StartedAt) > 2*time.Second {
		t.Errorf("helper started at %v", p.StartedAt)
	}
	want := report.Listen{Proto: "tcp", Address: "127.0.0.1", Port: port}
	for _, l := range p.Listen {
		if l == want {
			return
		}
	}
	t.Errorf("listener %+v not found in %+v (unowned %+v)", want, p.Listen, sec.UnownedPorts)
}

func TestLiveDeletedAndReplaced(t *testing.T) {
	env := liveEnv(t)
	self, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Skip(err)
	}
	path := filepath.Join(t.TempDir(), "helper")
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatal(err)
	}
	h := startHelper(t, path, "sleep")
	if h.line != "ready" {
		t.Skipf("helper: %s", h.line)
	}
	pid := h.cmd.Process.Pid

	// Resolve the path the kernel reports, in case the temp dir is reached
	// through a symbolic link.
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		t.Skipf("cannot read own child's exe link: %v", err)
	}

	sec := Collect(context.Background(), env)
	p := findProc(sec, pid)
	if p == nil || p.Exe != target || p.ExeState != report.ExeNormal {
		t.Fatalf("before delete: %+v", p)
	}
	wantSum := sha256Hex(data)
	if p.SHA256 != wantSum {
		t.Errorf("hash %s, want %s", p.SHA256, wantSum)
	}

	if err := os.Remove(path); err != nil {
		t.Skipf("cannot delete helper binary: %v", err)
	}
	sec = Collect(context.Background(), env)
	p = findProc(sec, pid)
	if p == nil || p.Exe != target || p.ExeState != report.ExeDeleted || p.SHA256 != wantSum {
		t.Fatalf("after delete: %+v", p)
	}

	if err := os.WriteFile(path, []byte("a different file"), 0o755); err != nil {
		t.Skipf("cannot write replacement: %v", err)
	}
	sec = Collect(context.Background(), env)
	p = findProc(sec, pid)
	if p == nil || p.Exe != target || p.ExeState != report.ExeReplaced || p.SHA256 != wantSum {
		t.Fatalf("after replace: %+v", p)
	}
}
