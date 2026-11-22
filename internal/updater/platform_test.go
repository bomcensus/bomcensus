// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build !windows

package updater

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/release"
	"github.com/bomcensus/bomcensus/internal/sign"
	"github.com/bomcensus/bomcensus/internal/sign/signtest"
)

func TestExpirePendingDoesNotCount(t *testing.T) {
	e := newEnv(t)
	e.upgradePending()
	ctx := context.Background()
	res, err := ExpirePending(ctx, e.opts(), BootLimits{})
	if err != nil || res.RolledBack != "" {
		t.Fatalf("expire: %+v %v", res, err)
	}
	if st := e.state(); st.Pending == nil || st.Pending.Attempts != 0 {
		t.Fatalf("pending %+v", st.Pending)
	}
	e.now = e.now.Add(DefaultPendingTimeout + time.Minute)
	res, err = ExpirePending(ctx, e.opts(), BootLimits{})
	if err != nil || res.RolledBack != "1.1.0" {
		t.Fatalf("expire after timeout: %+v %v", res, err)
	}
	wantState(t, e.state(), "1.0.0", "", "")
}

func TestCleanupRemovesLeftovers(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// Nothing installed: Cleanup must not touch anything.
	stray := filepath.Join(e.install, versionsDir, "0.9.0")
	if err := os.MkdirAll(stray, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Cleanup(ctx, e.opts()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stray); err != nil {
		t.Fatalf("removed without an installed version: %v", err)
	}
	e.upgradePending()
	// A rolled-back version whose files could not be removed (on Windows:
	// they were still running).
	for _, d := range []string{"1.2.0", ".tmp-x"} {
		if err := os.MkdirAll(filepath.Join(e.install, versionsDir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := Cleanup(ctx, e.opts()); err != nil {
		t.Fatal(err)
	}
	if got := e.versionDirs(); !slices.Equal(got, []string{"1.0.0", "1.1.0"}) {
		t.Fatalf("versions %v", got)
	}
}

// TestWindowsBundle installs a Windows bundle with the Windows file names on
// this system. Only the current link is a symlink instead of a junction.
func TestWindowsBundle(t *testing.T) {
	e := newEnv(t)
	hostOS = "windows"
	defer func() { hostOS = runtime.GOOS }()
	pe := e.trust.SignPE(t, signtest.PE(t, e.arch))
	m := &sign.Manifest{Version: "2.0.0", IssuedAt: e.now.Add(-time.Minute), ExpiresAt: e.now.Add(time.Hour)}
	var files []release.File
	for _, n := range append(slices.Clone(fileNames), scannerName) {
		n += ".exe"
		files = append(files, release.File{OS: "windows", Arch: e.arch, Name: n, Data: pe})
		m.Files = append(m.Files, signtest.FileEntry("windows", e.arch, n, pe))
	}
	// A Linux part in the same bundle is verified but not installed.
	for _, n := range fileNames {
		files = append(files, release.File{OS: "linux", Arch: e.arch, Name: n, Data: e.elf(e.arch)})
		m.Files = append(m.Files, signtest.FileEntry("linux", e.arch, n, e.elf(e.arch)))
	}
	mb, sig := e.trust.SignManifest(t, m)
	var buf bytes.Buffer
	if err := release.Write(context.Background(), &buf, mb, sig, files); err != nil {
		t.Fatal(err)
	}
	if _, err := release.Open(context.Background(), bytes.NewReader(buf.Bytes()), e.now); err != nil {
		if strings.Contains(err.Error(), "no code signature verifier") {
			t.Skip("release bundles cannot hold Windows files yet:", err)
		}
		t.Fatal(err)
	}
	e.spoolFile(BundleName("2.0.0"), buf.Bytes())
	res := e.apply()
	if res.Installed != "2.0.0" {
		t.Fatalf("result %+v", res)
	}
	ents, err := os.ReadDir(filepath.Join(e.install, versionsDir, "2.0.0"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, d := range ents {
		names = append(names, d.Name())
	}
	if !slices.Equal(names, []string{"bomcensus-agent.exe", "bomcensus-probe.exe", "bomcensus-updater.exe"}) {
		t.Fatalf("installed %v", names)
	}
	st := e.state()
	if _, ok := st.Installed["2.0.0"].Files["bomcensus-agent.exe"]; !ok {
		t.Fatalf("recorded %+v", st.Installed)
	}

	// A directory installed by install.ps1 is adopted after an Authenticode
	// check.
	e2 := newEnv(t)
	pe = e2.trust.SignPE(t, signtest.PE(t, e2.arch))
	dir := filepath.Join(e2.install, versionsDir, "1.0.0")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range fileNames {
		if err := os.WriteFile(filepath.Join(dir, n+".exe"), pe, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("versions/1.0.0", filepath.Join(e2.install, currentName)); err != nil {
		t.Fatal(err)
	}
	if err := Cleanup(context.Background(), e2.opts()); err != nil {
		t.Fatal(err)
	}
	s, err := openSession(context.Background(), e2.opts())
	if err != nil {
		t.Fatal(err)
	}
	in, ok := s.st.Installed["1.0.0"]
	s.close()
	if !ok || in.Source != SourceAdopted || len(in.Files) != 3 {
		t.Fatalf("not adopted: %+v", s.st.Installed)
	}
}
