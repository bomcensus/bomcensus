// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package hostinfo

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bomcensus/bomcensus/internal/collect"
	"github.com/bomcensus/bomcensus/internal/report"
)

// Fixtures: os-release files of ubuntu:24.04, alpine:3.20 and
// gcr.io/distroless/base-debian12; machine-ids are made up.

func fixtureEnv(t *testing.T, name string) *collect.Env {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return collect.NewEnv().WithRoot(abs)
}

func writeFile(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestUbuntu(t *testing.T) {
	sec := Collect(context.Background(), fixtureEnv(t, "ubuntu"))
	if sec.Coverage != report.CoverageFull {
		t.Fatalf("coverage %q: %s", sec.Coverage, sec.Reason)
	}
	want := report.OS{
		Family: "linux", ID: "ubuntu", IDLike: "debian", Name: "Ubuntu",
		Version: "24.04.5 LTS (Noble Numbat)", VersionID: "24.04", Codename: "noble",
		PrettyName: "Ubuntu 24.04.5 LTS",
	}
	if sec.OS != want {
		t.Errorf("os\n got %+v\nwant %+v", sec.OS, want)
	}
	if sec.MachineID != "3f1c2a9b8d7e46f5a0b1c2d3e4f50617" {
		t.Errorf("machine-id %q", sec.MachineID)
	}
	if sec.Hostname == "" || sec.Kernel == "" || sec.Arch == "" {
		t.Errorf("uname fields missing: %+v", sec)
	}
	if sec.Digest == "" || sec.CollectedAt.IsZero() {
		t.Errorf("meta %+v", sec.SectionMeta)
	}
}

func TestAlpine(t *testing.T) {
	sec := Collect(context.Background(), fixtureEnv(t, "alpine"))
	if sec.Coverage != report.CoverageFull {
		t.Fatalf("coverage %q: %s", sec.Coverage, sec.Reason)
	}
	if sec.OS.ID != "alpine" || sec.OS.VersionID != "3.20.10" || sec.OS.PrettyName != "Alpine Linux v3.20" {
		t.Errorf("os %+v", sec.OS)
	}
	if sec.MachineID != "" {
		t.Errorf("machine-id %q", sec.MachineID)
	}
}

func TestFallbackPaths(t *testing.T) {
	// Only /usr/lib/os-release and /var/lib/dbus/machine-id.
	sec := Collect(context.Background(), fixtureEnv(t, "usrlib"))
	if sec.Coverage != report.CoverageFull {
		t.Fatalf("coverage %q: %s", sec.Coverage, sec.Reason)
	}
	if sec.OS.ID != "debian" || sec.OS.VersionID != "12" || sec.OS.PrettyName != "Distroless" {
		t.Errorf("os %+v", sec.OS)
	}
	if sec.MachineID != "0a1b2c3d4e5f60718293a4b5c6d7e8f9" {
		t.Errorf("machine-id %q", sec.MachineID)
	}
}

func TestAbsoluteSymlinkInRoot(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "usr/lib/os-release"), "ID=inroot\n")
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/lib/os-release", filepath.Join(root, "etc/os-release")); err != nil {
		t.Fatal(err)
	}
	sec := Collect(context.Background(), collect.NewEnv().WithRoot(root))
	if sec.OS.ID != "inroot" {
		t.Errorf("os %+v", sec.OS)
	}
}

func TestLegacyRelease(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "etc/redhat-release"), "CentOS release 6.10 (Final)\n")
	writeFile(t, filepath.Join(root, "etc/machine-id"), "uninitialized\n")
	sec := Collect(context.Background(), collect.NewEnv().WithRoot(root))
	if sec.Coverage != report.CoveragePartial || sec.Reason == "" {
		t.Fatalf("coverage %q: %s", sec.Coverage, sec.Reason)
	}
	want := report.OS{Family: "linux", ID: "centos", Name: "CentOS", VersionID: "6.10", PrettyName: "CentOS release 6.10 (Final)"}
	if sec.OS != want {
		t.Errorf("os\n got %+v\nwant %+v", sec.OS, want)
	}
	if sec.MachineID != "" {
		t.Errorf("machine-id %q", sec.MachineID)
	}
}

func TestNoRelease(t *testing.T) {
	sec := Collect(context.Background(), collect.NewEnv().WithRoot(t.TempDir()))
	if sec.Coverage != report.CoveragePartial || sec.Reason == "" {
		t.Fatalf("coverage %q: %s", sec.Coverage, sec.Reason)
	}
	if sec.OS.Family != "linux" || sec.Arch == "" {
		t.Errorf("section %+v", sec)
	}
}

func TestParseOSRelease(t *testing.T) {
	got := parseOSRelease([]byte("# comment\nNAME='Single Quoted'\nVERSION=\"a \\\"b\\\" \\$c\"\nID = spaced \nbroken line\nVERSION_ID=\"unterminated\n"))
	want := report.OS{Family: "linux", Name: "Single Quoted", Version: `a "b" $c`, ID: "spaced", VersionID: "unterminated"}
	if got != want {
		t.Errorf("\n got %+v\nwant %+v", got, want)
	}
}

func TestDigestStable(t *testing.T) {
	env := fixtureEnv(t, "ubuntu")
	a := Collect(context.Background(), env)
	b := Collect(context.Background(), env)
	if a.Digest == "" || a.Digest != b.Digest {
		t.Errorf("digests %q and %q", a.Digest, b.Digest)
	}
	c := Collect(context.Background(), fixtureEnv(t, "alpine"))
	if c.Digest == a.Digest {
		t.Error("different hosts share a digest")
	}
}
