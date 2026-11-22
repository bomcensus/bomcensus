// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build windows

package updater

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/release"
	"github.com/bomcensus/bomcensus/internal/sign"
	"github.com/bomcensus/bomcensus/internal/sign/signtest"
)

// TestWindowsUpdateFlow installs, upgrades and rolls back Authenticode
// signed bundles through the current junction.
func TestWindowsUpdateFlow(t *testing.T) {
	tr := signtest.Install(t)
	dir := t.TempDir()
	install, spool := filepath.Join(dir, "install"), filepath.Join(dir, "spool")
	for _, d := range []string{install, spool} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	var logs bytes.Buffer
	opts := Options{InstallDir: install, Now: func() time.Time { return now }, Logger: slog.New(slog.NewTextHandler(&logs, nil))}
	ctx := context.Background()
	pe := tr.SignPE(t, signtest.PE(t, runtime.GOARCH))
	put := func(v string) {
		m := &sign.Manifest{Version: v, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
		var files []release.File
		for _, n := range []string{"bomcensus-agent.exe", "bomcensus-probe.exe", "bomcensus-updater.exe", "bomcensus-scanner.exe"} {
			files = append(files, release.File{OS: "windows", Arch: runtime.GOARCH, Name: n, Data: pe})
			m.Files = append(m.Files, signtest.FileEntry("windows", runtime.GOARCH, n, pe))
		}
		mb, sig := tr.SignManifest(t, m)
		var buf bytes.Buffer
		if err := release.Write(ctx, &buf, mb, sig, files); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(spool, BundleName(v)), buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	apply := func() *Result {
		t.Helper()
		res, err := Apply(ctx, opts, spool)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	current := func(want string) {
		t.Helper()
		v, d, err := Current(ctx, install)
		if err != nil || v != want || d != filepath.Join(install, versionsDir, want) {
			t.Fatalf("current %q %q %v, want %s", v, d, err, want)
		}
		if _, err := os.Stat(filepath.Join(install, currentName, "bomcensus-agent.exe")); err != nil {
			t.Fatal(err)
		}
	}

	put("1.0.0")
	if res := apply(); res.Installed != "1.0.0" {
		t.Fatalf("install: %+v", res)
	}
	current("1.0.0")
	if err := os.WriteFile(filepath.Join(spool, ConfirmName("1.0.0")), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if res := apply(); res.Confirmed != "1.0.0" {
		t.Fatalf("confirm: %+v", res)
	}
	put("1.1.0")
	if res := apply(); res.Installed != "1.1.0" {
		t.Fatalf("upgrade: %+v", res)
	}
	current("1.1.0")
	if _, err := os.Stat(filepath.Join(install, versionsDir, "1.1.0", "bomcensus-scanner.exe")); !os.IsNotExist(err) {
		t.Fatalf("scanner installed: %v", err)
	}

	// The running agent of the failed version keeps its executable open,
	// so the rollback cannot remove it; Cleanup removes it later.
	running, err := os.Open(filepath.Join(install, versionsDir, "1.1.0", "bomcensus-agent.exe"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spool, RollbackName), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if res := apply(); res.RolledBack != "1.1.0" {
		t.Fatalf("rollback: %+v", res)
	}
	current("1.0.0")
	if !bytes.Contains(logs.Bytes(), []byte("cannot remove failed version")) {
		t.Fatalf("the failed version was removed while in use:\n%s", logs.String())
	}
	running.Close()
	if err := Cleanup(ctx, opts); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(install, versionsDir, "1.1.0")); !os.IsNotExist(err) {
		t.Fatalf("failed version left after cleanup: %v", err)
	}
}
