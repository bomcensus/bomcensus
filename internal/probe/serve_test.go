// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package probe

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// startServe runs Serve with a shell child and returns the socket path.
func startServe(t *testing.T, o ServeOptions) string {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	o.Socket = filepath.Join(t.TempDir(), "probe.sock")
	o.Exe = "/bin/sh"
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	o.Ready = func() { close(ready) }
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, o) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(15 * time.Second):
			t.Error("Serve did not return after cancel")
		}
	})
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("Serve: %v", err)
	}
	return o.Socket
}

// exchange sends in, closes the write side and reads until EOF.
func exchange(t *testing.T, sock, in string) string {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	// A refused connection may be closed before the request is written, or
	// with the request unread, which the kernel reports as a reset.
	refused := func(err error) bool { return errors.Is(err, unix.EPIPE) || errors.Is(err, unix.ECONNRESET) }
	if _, err := io.WriteString(c, in); err != nil {
		if refused(err) {
			return ""
		}
		t.Fatal(err)
	}
	if err := c.(*net.UnixConn).CloseWrite(); err != nil {
		if refused(err) {
			return ""
		}
		t.Fatal(err)
	}
	out, err := io.ReadAll(c)
	if err != nil && !refused(err) {
		t.Fatal(err)
	}
	return string(out)
}

func TestServeConnection(t *testing.T) {
	sock := startServe(t, ServeOptions{
		Args:      []string{"-c", `read line; echo "got $line"`},
		AllowUIDs: []int{os.Getuid()},
	})
	if got := exchange(t, sock, "request\n"); got != "got request\n" {
		t.Errorf("answer %q", got)
	}
	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("socket mode %v, want 0600", fi.Mode().Perm())
	}
	// A second connection gets its own child.
	if got := exchange(t, sock, "again\n"); got != "got again\n" {
		t.Errorf("second answer %q", got)
	}
}

func TestServeRefusesUID(t *testing.T) {
	sock := startServe(t, ServeOptions{
		Args:      []string{"-c", "echo answered"},
		AllowUIDs: []int{os.Getuid() + 1},
	})
	if got := exchange(t, sock, "x"); got != "" {
		t.Errorf("refused peer got %q", got)
	}
}

func TestServeConnectionLimit(t *testing.T) {
	sock := startServe(t, ServeOptions{
		Args:           []string{"-c", "cat >/dev/null; echo ok"},
		MaxConnections: 1,
	})
	// The first connection holds the only slot until it closes its write side.
	first, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	// Let the listener take the first connection before the second one.
	time.Sleep(200 * time.Millisecond)
	if got := exchange(t, sock, ""); got != "" {
		t.Errorf("connection over the limit got %q", got)
	}
	_ = first.(*net.UnixConn).CloseWrite()
	_ = first.SetDeadline(time.Now().Add(10 * time.Second))
	out, _ := io.ReadAll(first)
	if string(out) != "ok\n" {
		t.Errorf("first connection got %q", out)
	}
}

func TestServeRuntimeLimit(t *testing.T) {
	sock := startServe(t, ServeOptions{
		Args:       []string{"-c", "sleep 30; echo late"},
		MaxRuntime: 300 * time.Millisecond,
	})
	start := time.Now()
	if got := exchange(t, sock, ""); got != "" {
		t.Errorf("killed collection wrote %q", got)
	}
	if d := time.Since(start); d > 8*time.Second {
		t.Errorf("collection ran %v despite the limit", d)
	}
}

func TestServeReplacesOnlySockets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "probe.sock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := Serve(context.Background(), ServeOptions{Socket: path})
	if err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Errorf("Serve over a regular file: %v", err)
	}
}

func TestListenerSeccompRules(t *testing.T) {
	full, lst := seccompRules(), listenerSeccompRules()
	if len(lst) != len(full)-1 {
		t.Fatalf("listener rules: %d, full: %d", len(lst), len(full))
	}
	prog, err := buildFilter(lst)
	if err != nil {
		t.Fatal(err)
	}
	if r := evalFilter(t, prog, auditArch, unix.SYS_CHROOT); r != retAllow {
		t.Errorf("chroot under the listener filter: %#x", r)
	}
	for _, nr := range []int{unix.SYS_PTRACE, unix.SYS_SETNS, unix.SYS_MOUNT} {
		if r := evalFilter(t, prog, auditArch, nr); r == retAllow {
			t.Errorf("syscall %d allowed under the listener filter", nr)
		}
	}
	if r := evalFilter(t, prog, auditArch, unix.SYS_SOCKET, unix.AF_INET); r == retAllow {
		t.Error("AF_INET socket allowed under the listener filter")
	}
}

func TestVerifyHostRootSandbox(t *testing.T) {
	good := func() *SandboxResult {
		two := []string{"CAP_DAC_READ_SEARCH", "CAP_SYS_PTRACE"}
		return &SandboxResult{UID: unprivilegedID, GID: unprivilegedID, Groups: []int{},
			Capabilities: two, Bounding: two, NoNewPrivs: true, Seccomp: 2}
	}
	if err := VerifyHostRootSandbox(good()); err != nil {
		t.Fatalf("complete drop rejected: %v", err)
	}
	for name, spoil := range map[string]func(*SandboxResult){
		"root":      func(r *SandboxResult) { r.UID = 0 },
		"groups":    func(r *SandboxResult) { r.Groups = []int{0} },
		"extra cap": func(r *SandboxResult) { r.Capabilities = append(r.Capabilities, "CAP_SYS_CHROOT") },
		"bounding": func(r *SandboxResult) {
			r.Bounding = []string{"CAP_DAC_READ_SEARCH", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE"}
		},
		"ambient":       func(r *SandboxResult) { r.Ambient = []string{"CAP_SYS_PTRACE"} },
		"no_new_privs":  func(r *SandboxResult) { r.NoNewPrivs = false },
		"no seccomp":    func(r *SandboxResult) { r.Seccomp = 0 },
		"missing a cap": func(r *SandboxResult) { r.Capabilities = r.Capabilities[:1] },
	} {
		r := good()
		spoil(r)
		if VerifyHostRootSandbox(r) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestEnterHostRootChecks(t *testing.T) {
	if err := EnterHostRoot("relative"); err == nil {
		t.Error("relative path accepted")
	}
	if err := EnterHostRoot(t.TempDir()); err == nil || !strings.Contains(err.Error(), "/proc") {
		t.Errorf("directory without proc: %v", err)
	}
	if os.Geteuid() != 0 {
		// Without CAP_SYS_CHROOT the change must fail, not be skipped.
		if err := EnterHostRoot("/"); err == nil {
			t.Error("chroot succeeded without privileges")
		}
	}
}
