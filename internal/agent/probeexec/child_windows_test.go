// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package probeexec

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/report"
)

// fakeProbeEnv makes the test binary act as the probe: it reads the request
// and writes the file named by the variable, or hangs when it is "hang".
const fakeProbeEnv = "BOMCENSUS_FAKE_PROBE"

func TestMain(m *testing.M) {
	if v := os.Getenv(fakeProbeEnv); v != "" {
		_, _ = io.Copy(io.Discard, os.Stdin)
		if v == "hang" {
			time.Sleep(time.Hour)
		}
		b, err := os.ReadFile(v)
		if err != nil {
			os.Exit(3)
		}
		os.Stdout.Write(b)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func fakeInvoker(t *testing.T, mode string) *Invoker {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return &Invoker{Path: self, Env: append(defaultEnv(), fakeProbeEnv+"="+mode)}
}

func TestChildProcessWindows(t *testing.T) {
	var buf bytes.Buffer
	if err := report.Encode(&buf, &report.Report{SchemaVersion: report.SchemaVersion, CollectedAt: time.Now(),
		Host: &report.HostSection{Hostname: "via-child"}}); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "report.bin")
	if err := os.WriteFile(out, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := fakeInvoker(t, out).Collect(context.Background(), &report.Request{Sections: []string{"host"}})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Host == nil || rep.Host.Hostname != "via-child" {
		t.Fatalf("report = %+v", rep)
	}
}

func TestChildCancelWindows(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	if _, err := fakeInvoker(t, "hang").Collect(ctx, &report.Request{}); err == nil {
		t.Fatal("hanging probe accepted")
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Fatalf("cancel took %s", d)
	}
}

func TestDefaultsWindows(t *testing.T) {
	if DefaultSocket != "" || ProbeName != "bomcensus-probe.exe" {
		t.Errorf("DefaultSocket %q, ProbeName %q", DefaultSocket, ProbeName)
	}
	if _, err := statSocket(""); err == nil {
		t.Error("empty socket path accepted")
	}
}
