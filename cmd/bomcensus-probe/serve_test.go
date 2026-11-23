// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package main

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/report"
)

// startServe runs "bomcensus-probe serve" with the listener sandbox and
// waits for its socket.
func startServe(t *testing.T, args ...string) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "probe.sock")
	cmd := exec.Command(probeBinary(t), append([]string{"serve", "--socket", sock, "--log-level", "debug"}, args...)...)
	var logs bytes.Buffer
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("serve log:\n%s", logs.String())
		}
	})
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if fi, err := os.Stat(sock); err == nil && fi.Mode().Type() == os.ModeSocket && strings.Contains(logs.String(), "probe listening") {
			return sock
		}
	}
	t.Fatalf("socket did not appear; log:\n%s", logs.String())
	return ""
}

func ask(t *testing.T, sock, req string) []byte {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Minute))
	// A refused connection may be closed before or after the request.
	refused := func(err error) bool { return errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) }
	if _, err := io.WriteString(c, req); err != nil {
		if refused(err) {
			return nil
		}
		t.Fatal(err)
	}
	if err := c.(*net.UnixConn).CloseWrite(); err != nil {
		if refused(err) {
			return nil
		}
		t.Fatal(err)
	}
	out, err := io.ReadAll(c)
	if err != nil && !refused(err) {
		t.Fatal(err)
	}
	return out
}

func TestServeCollect(t *testing.T) {
	sock := startServe(t, "--allow-uid", strconv.Itoa(os.Getuid()))
	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o666 {
		t.Errorf("socket mode %v with --allow-uid, want 0666", fi.Mode().Perm())
	}
	out := ask(t, sock, `{"sections":["host"],"policy":{"collect_cmdline":true}}`)
	rep, err := report.Decode(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("decode %d bytes: %v", len(out), err)
	}
	if rep.Host == nil || rep.Host.Hostname == "" {
		t.Errorf("no host section: %+v", rep.Host)
	}
	if rep.Packages != nil {
		t.Error("packages collected although only host was asked for")
	}
}

func TestServeRefusedPeer(t *testing.T) {
	sock := startServe(t, "--allow-uid", strconv.Itoa(os.Getuid()+1))
	if out := ask(t, sock, `{"sections":["host"]}`); len(out) != 0 {
		t.Errorf("refused peer got %d bytes", len(out))
	}
}

func TestServeUsage(t *testing.T) {
	for _, args := range [][]string{
		{"serve"},
		{"serve", "--socket", "/tmp/x.sock", "--allow-uid", "abc"},
		{"serve", "--socket", "/tmp/x.sock", "--host-root", "/host", "--no-sandbox"},
		{"collect", "--host-root", "/host", "--no-sandbox"},
	} {
		if _, stderr, code := runProbe(t, "", args...); code != 2 {
			t.Errorf("%v: exit %d, want 2 (%s)", args, code, stderr)
		}
	}
}

// Without CAP_SYS_CHROOT host root mode must fail instead of collecting
// the probe's own view.
func TestCollectHostRootUnprivileged(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	out, stderr, code := runProbe(t, `{"sections":["host"]}`, "collect", "--host-root", "/")
	if code != 1 || len(out) != 0 {
		t.Errorf("exit %d, %d bytes written; stderr %s", code, len(out), stderr)
	}
	if !strings.Contains(string(stderr), "chroot") {
		t.Errorf("stderr does not name the chroot: %s", stderr)
	}
}
