// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build !windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/release"
	"github.com/bomcensus/bomcensus/internal/sign"
	"github.com/bomcensus/bomcensus/internal/sign/signtest"
	"github.com/bomcensus/bomcensus/internal/updater"
	"github.com/bomcensus/bomcensus/internal/version"
)

func TestCommands(t *testing.T) {
	ctx := context.Background()
	tr := signtest.Install(t)
	dir := t.TempDir()
	install := filepath.Join(dir, "install")
	spool := filepath.Join(dir, "spool")
	for _, d := range []string{install, spool} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	now := time.Now()
	data := tr.SignELF(t, signtest.ELF(t, runtime.GOARCH))
	m := &sign.Manifest{
		Version:   "1.0.0",
		IssuedAt:  now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour),
		Files:     []sign.File{signtest.FileEntry("linux", runtime.GOARCH, updater.AgentName, data)},
	}
	mb, sig := tr.SignManifest(t, m)
	var buf bytes.Buffer
	files := []release.File{{OS: "linux", Arch: runtime.GOARCH, Name: updater.AgentName, Data: data}}
	if err := release.Write(ctx, &buf, mb, sig, files); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spool, updater.BundleName("1.0.0")), buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer
	if err := run(ctx, []string{"apply", "--spool", spool, "--install", install}, io.Discard, &logs); err != nil {
		t.Fatalf("apply: %v\n%s", err, logs.String())
	}
	if !strings.Contains(logs.String(), "installed=1.0.0") {
		t.Fatalf("logs:\n%s", logs.String())
	}
	if err := run(ctx, []string{"boot-check", "--install", install}, io.Discard, io.Discard); err != nil {
		t.Fatalf("boot-check: %v", err)
	}

	var out bytes.Buffer
	if err := run(ctx, []string{"status", "--install", install}, &out, io.Discard); err != nil {
		t.Fatalf("status: %v", err)
	}
	var st updater.State
	if err := json.Unmarshal(out.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Current != "1.0.0" || st.Pending == nil || st.Pending.Attempts != 1 {
		t.Fatalf("state %s", out.String())
	}

	out.Reset()
	if err := run(ctx, []string{"version"}, &out, io.Discard); err != nil || strings.TrimSpace(out.String()) != version.Version {
		t.Fatalf("version: %q %v", out.String(), err)
	}

	for _, args := range [][]string{nil, {"nope"}, {"apply", "--bogus"}, {"status", "extra"}, {"boot-check", "--max-attempts", "0"}} {
		if err := run(ctx, args, io.Discard, io.Discard); !errors.Is(err, errUsage) {
			t.Fatalf("%v: %v", args, err)
		}
	}
	if err := run(ctx, []string{"apply", "--spool", filepath.Join(dir, "missing"), "--install", install, "--lock-wait", "0s"}, io.Discard, io.Discard); err == nil {
		t.Fatal("apply with a missing spool succeeded")
	}
}
