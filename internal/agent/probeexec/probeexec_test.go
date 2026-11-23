// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package probeexec

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/report"
)

func encoded(t *testing.T, hostname string) []byte {
	t.Helper()
	var buf bytes.Buffer
	err := report.Encode(&buf, &report.Report{
		SchemaVersion: report.SchemaVersion,
		ProbeVersion:  "test",
		CollectedAt:   time.Now(),
		Host:          &report.HostSection{Hostname: hostname},
	})
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestSocketHalfClose(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "probe.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	out := encoded(t, "via-socket")
	got := make(chan report.Request, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// The request ends at EOF, which only arrives after CloseWrite.
		b, err := io.ReadAll(c)
		if err != nil {
			return
		}
		var req report.Request
		_ = json.Unmarshal(b, &req)
		got <- req
		_, _ = c.Write(out)
	}()
	inv := &Invoker{Socket: sock, Path: filepath.Join(dir, "never-run")}
	rep, err := inv.Collect(context.Background(), &report.Request{Sections: []string{report.SectionHost}, KnownDigests: map[string]string{"host": "abc"}})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Host == nil || rep.Host.Hostname != "via-socket" {
		t.Fatalf("report = %+v", rep)
	}
	req := <-got
	if len(req.Sections) != 1 || req.KnownDigests["host"] != "abc" {
		t.Fatalf("request = %+v", req)
	}
}

type logBuf struct{ bytes.Buffer }

func TestChildProcess(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "report.bin")
	if err := os.WriteFile(outFile, encoded(t, "via-child"), 0o600); err != nil {
		t.Fatal(err)
	}
	reqFile := filepath.Join(dir, "request.json")
	script := filepath.Join(dir, ProbeName)
	body := "#!/bin/sh\n[ \"$1\" = collect ] || exit 2\ncat > " + reqFile + "\necho probe-diagnostics >&2\ncat " + outFile + "\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	var logs logBuf
	inv := &Invoker{
		Socket: filepath.Join(dir, "absent.sock"),
		Path:   script,
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
	}
	rep, err := inv.Collect(context.Background(), &report.Request{Sections: []string{"host"}})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Host.Hostname != "via-child" {
		t.Fatalf("report = %+v", rep.Host)
	}
	b, err := os.ReadFile(reqFile)
	if err != nil || !strings.Contains(string(b), `"sections":["host"]`) {
		t.Fatalf("request %q, %v", b, err)
	}
	if !strings.Contains(logs.String(), "probe-diagnostics") {
		t.Fatalf("stderr not logged: %s", logs.String())
	}
}

func TestChildFailure(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, ProbeName)
	if err := os.WriteFile(script, []byte("#!/bin/sh\ncat >/dev/null\nexit 3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	inv := &Invoker{Socket: filepath.Join(dir, "absent.sock"), Path: script}
	if _, err := inv.Collect(context.Background(), &report.Request{}); err == nil {
		t.Fatal("failed probe accepted")
	}
}

func TestRequireSocket(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	script := filepath.Join(dir, ProbeName)
	if err := os.WriteFile(script, []byte("#!/bin/sh\ntouch "+marker+"\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	notSocket := filepath.Join(dir, "file.sock")
	if err := os.WriteFile(notSocket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, sock := range []string{filepath.Join(dir, "absent.sock"), notSocket} {
		inv := &Invoker{Socket: sock, Path: script, RequireSocket: true}
		_, err := inv.Collect(context.Background(), &report.Request{})
		if err == nil || !strings.Contains(err.Error(), "probe socket required") {
			t.Errorf("%s: %v", sock, err)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("the probe ran as a child although the socket is required")
	}
}
