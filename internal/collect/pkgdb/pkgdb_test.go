// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package pkgdb

import (
	"bytes"
	"context"
	"encoding/binary"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/bomcensus/bomcensus/internal/collect"
	"github.com/bomcensus/bomcensus/internal/report"
)

// Fixtures under testdata were taken from container images and trimmed:
//
//	deb         debian:12 status excerpt and info/*.list, plus hand-written
//	            stanzas for the status states
//	distroless  gcr.io/distroless/base-debian12 status.d
//	rpm-sqlite  almalinux:9-minimal rpmdb.sqlite (rpm -e --justdb, VACUUM)
//	rpm-bdb     almalinux:8 Packages with nginx:1.22 module (rpm --rebuilddb)
//	rpm-ndb     opensuse/leap:15.6 Packages.db (rpm --rebuilddb)
//	apk         alpine:3.20 lib/apk/db/installed

func fixtureEnv(t *testing.T, name string) *collect.Env {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return collect.NewEnv().WithRoot(abs)
}

func collectRoot(t *testing.T, env *collect.Env) (*report.PackagesSection, *Index) {
	t.Helper()
	sec, ix := Collect(context.Background(), env)
	if sec == nil || ix == nil {
		t.Fatal("Collect returned nil")
	}
	return sec, ix
}

func findPkg(sec *report.PackagesSection, name string) *report.Package {
	for i := range sec.Packages {
		if sec.Packages[i].Name == name {
			return &sec.Packages[i]
		}
	}
	return nil
}

func wantPkg(t *testing.T, sec *report.PackagesSection, want report.Package) {
	t.Helper()
	got := findPkg(sec, want.Name)
	if got == nil {
		t.Errorf("package %s missing", want.Name)
		return
	}
	if *got != want {
		t.Errorf("package %s:\n got %+v\nwant %+v", want.Name, *got, want)
	}
}

func wantCoverage(t *testing.T, sec *report.PackagesSection, c report.Coverage) {
	t.Helper()
	if sec.Coverage != c {
		t.Fatalf("coverage %q (reason %q), want %q", sec.Coverage, sec.Reason, c)
	}
	if c != report.CoverageFull && sec.Reason == "" {
		t.Fatalf("coverage %q without a reason", c)
	}
	if sec.Reason != "" {
		t.Logf("reason: %s", sec.Reason)
	}
}

func wantOwner(t *testing.T, ix *Index, p, want string) {
	t.Helper()
	got, ok := ix.Owner(p)
	if want == "" {
		if ok {
			t.Errorf("Owner(%s) = %q, want none", p, got)
		}
		return
	}
	if !ok || got != want {
		t.Errorf("Owner(%s) = %q, %v; want %q", p, got, ok, want)
	}
}

func names(sec *report.PackagesSection) []string {
	var n []string
	for _, p := range sec.Packages {
		n = append(n, p.Name)
	}
	return n
}

func TestDpkg(t *testing.T) {
	sec, ix := collectRoot(t, fixtureEnv(t, "deb"))
	wantCoverage(t, sec, report.CoverageFull)
	if len(sec.Databases) != 1 || sec.Databases[0] != (report.PackageDB{Type: "deb", Path: "/var/lib/dpkg/status"}) {
		t.Errorf("databases %+v", sec.Databases)
	}
	if got, want := strings.Join(names(sec), " "), "base-files bash halfpkg heldpkg libc6 libgcc-s1 tzdata"; got != want {
		t.Errorf("packages %q, want %q", got, want)
	}
	// Source with version (binary-only upload).
	wantPkg(t, sec, report.Package{Type: "deb", Name: "bash", Version: "5.2.15-2+b13", Arch: "amd64",
		SourceName: "bash", SourceVersion: "5.2.15-2", Maintainer: "Matthias Klose <doko@debian.org>"})
	// Source without version.
	wantPkg(t, sec, report.Package{Type: "deb", Name: "libgcc-s1", Version: "12.2.0-14+deb12u1", Arch: "amd64",
		SourceName: "gcc-12", SourceVersion: "12.2.0-14+deb12u1", Maintainer: "Debian GCC Maintainers <debian-gcc@lists.debian.org>"})
	// No Source field.
	wantPkg(t, sec, report.Package{Type: "deb", Name: "tzdata", Version: "2026f-0+deb12u1", Arch: "all",
		SourceName: "tzdata", SourceVersion: "2026f-0+deb12u1", Maintainer: "GNU Libc Maintainers <debian-glibc@lists.debian.org>"})
	// States other than "install ok installed" are recorded.
	wantPkg(t, sec, report.Package{Type: "deb", Name: "halfpkg", Version: "0.9-2", Arch: "amd64",
		SourceName: "halfpkg", SourceVersion: "0.9-2", Maintainer: "Example <pkg@example.org>",
		Status: "install reinstreq half-installed"})
	wantPkg(t, sec, report.Package{Type: "deb", Name: "heldpkg", Version: "2:1.2.3-3+b1", Arch: "all",
		SourceName: "heldsrc", SourceVersion: "1.2.3-3", Maintainer: "Example <pkg@example.org>",
		Status: "hold ok installed"})

	// bash.list has /bin/bash; /bin is a symlink to usr/bin.
	wantOwner(t, ix, "/bin/bash", "bash")
	wantOwner(t, ix, "/usr/bin/bash", "bash")
	wantOwner(t, ix, "/usr/bin/../bin/bash", "bash")
	// libc6:amd64.list has /lib/x86_64-linux-gnu/libc.so.6.
	wantOwner(t, ix, "/usr/lib/x86_64-linux-gnu/libc.so.6", "libc6")
	wantOwner(t, ix, "/lib/x86_64-linux-gnu/libc.so.6", "libc6")
	wantOwner(t, ix, "/usr/bin/bashbug", "bash")
	// Lists of packages in config-files state are ignored.
	wantOwner(t, ix, "/etc/oldpkg.conf", "")
	// Directories followed by their contents in a list are not indexed.
	wantOwner(t, ix, "/usr/share/doc/bash", "")
	wantOwner(t, ix, "/etc", "")
	wantOwner(t, ix, "/usr/bin/nonexistent", "")
	wantOwner(t, ix, "relative/path", "")
	if !ix.Complete() {
		t.Error("index not complete")
	}
}

func TestParseDpkgSource(t *testing.T) {
	for _, tc := range []struct{ in, name, version string }{
		{"glibc", "glibc", ""},
		{"gcc-12 (12.2.0-14)", "gcc-12", "12.2.0-14"},
		{"  bash   ( 5.2.15-2 ) ", "bash", "5.2.15-2"},
		{"foo(1.0)", "foo", "1.0"},
		{"foo (1.0", "foo", ""},
		{"", "", ""},
	} {
		n, v := parseDpkgSource(tc.in)
		if n != tc.name || v != tc.version {
			t.Errorf("parseDpkgSource(%q) = %q, %q; want %q, %q", tc.in, n, v, tc.name, tc.version)
		}
	}
}

func TestDpkgStatusD(t *testing.T) {
	sec, ix := collectRoot(t, fixtureEnv(t, "distroless"))
	wantCoverage(t, sec, report.CoverageFull)
	if len(sec.Databases) != 1 || sec.Databases[0].Path != "/var/lib/dpkg/status.d" {
		t.Errorf("databases %+v", sec.Databases)
	}
	if got, want := strings.Join(names(sec), " "), "base-files libc6 netbase"; got != want {
		t.Errorf("packages %q, want %q", got, want)
	}
	wantPkg(t, sec, report.Package{Type: "deb", Name: "libc6", Version: "2.36-9+deb12u14", Arch: "amd64",
		SourceName: "glibc", SourceVersion: "2.36-9+deb12u14", Maintainer: "GNU Libc Maintainers <debian-glibc@lists.debian.org>"})
	wantOwner(t, ix, "/lib/x86_64-linux-gnu/libc.so.6", "libc6")
	wantOwner(t, ix, "/usr/share/doc/netbase/copyright", "netbase")
}

func TestRPMSQLite(t *testing.T) {
	sec, ix := collectRoot(t, fixtureEnv(t, "rpm-sqlite"))
	wantCoverage(t, sec, report.CoverageFull)
	if len(sec.Databases) != 1 || sec.Databases[0] != (report.PackageDB{Type: "rpm", Path: "/var/lib/rpm/rpmdb.sqlite"}) {
		t.Errorf("databases %+v", sec.Databases)
	}
	// gpg-pubkey is not a package.
	if got, want := strings.Join(names(sec), " "), "basesystem bash libgcc openssl-libs shadow-utils"; got != want {
		t.Errorf("packages %q, want %q", got, want)
	}
	const team = "AlmaLinux Packaging Team <packager@almalinux.org>"
	wantPkg(t, sec, report.Package{Type: "rpm", Name: "openssl-libs", Version: "1:3.5.9-1.el9_9", Arch: "x86_64",
		SourceName: "openssl", SourceVersion: "1:3.5.9-1.el9_9", Vendor: "AlmaLinux", Maintainer: team})
	wantPkg(t, sec, report.Package{Type: "rpm", Name: "libgcc", Version: "11.5.0-17.el9_9.alma.1", Arch: "x86_64",
		SourceName: "gcc", SourceVersion: "11.5.0-17.el9_9.alma.1", Vendor: "AlmaLinux", Maintainer: team})
	wantPkg(t, sec, report.Package{Type: "rpm", Name: "basesystem", Version: "11-13.el9", Arch: "noarch",
		SourceName: "basesystem", SourceVersion: "11-13.el9", Vendor: "AlmaLinux", Maintainer: team})

	wantOwner(t, ix, "/usr/bin/bash", "bash")
	wantOwner(t, ix, "/bin/bash", "bash")
	wantOwner(t, ix, "/lib64/libgcc_s.so.1", "libgcc")
	wantOwner(t, ix, "/sbin/useradd", "shadow-utils")
	wantOwner(t, ix, "/usr/bin", "")
	if !ix.Complete() {
		t.Error("index not complete")
	}
}

func TestRPMBDB(t *testing.T) {
	sec, ix := collectRoot(t, fixtureEnv(t, "rpm-bdb"))
	wantCoverage(t, sec, report.CoverageFull)
	if len(sec.Databases) != 1 || sec.Databases[0].Path != "/var/lib/rpm/Packages" {
		t.Errorf("databases %+v", sec.Databases)
	}
	if got, want := strings.Join(names(sec), " "), "basesystem bash libgcc nginx-filesystem openssl-libs shadow-utils"; got != want {
		t.Errorf("packages %q, want %q", got, want)
	}
	wantPkg(t, sec, report.Package{Type: "rpm", Name: "nginx-filesystem",
		Version: "1:1.22.1-1.module_el8.10.0+4179+4d9c78ab.1.alma.2", Arch: "noarch",
		SourceName: "nginx", SourceVersion: "1:1.22.1-1.module_el8.10.0+4179+4d9c78ab.1.alma.2",
		Vendor: "AlmaLinux", Maintainer: "AlmaLinux Packaging Team <packager@almalinux.org>",
		ModularityLabel: "nginx:1.22:8100020260514161000:9edba152"})
	wantPkg(t, sec, report.Package{Type: "rpm", Name: "shadow-utils", Version: "2:4.6-23.el8_10", Arch: "x86_64",
		SourceName: "shadow-utils", SourceVersion: "2:4.6-23.el8_10",
		Vendor: "AlmaLinux", Maintainer: "AlmaLinux Packaging Team <packager@almalinux.org>"})
	wantOwner(t, ix, "/bin/bash", "bash")
	wantOwner(t, ix, "/usr/bin/bash", "bash")
}

func TestRPMNDB(t *testing.T) {
	sec, ix := collectRoot(t, fixtureEnv(t, "rpm-ndb"))
	wantCoverage(t, sec, report.CoverageFull)
	// /var/lib/rpm is a symlink to /usr/lib/sysimage/rpm: read once.
	if len(sec.Databases) != 1 || sec.Databases[0] != (report.PackageDB{Type: "rpm", Path: "/usr/lib/sysimage/rpm/Packages.db"}) {
		t.Errorf("databases %+v", sec.Databases)
	}
	if got, want := strings.Join(names(sec), " "), "bash filesystem libgcc_s1 libopenssl3"; got != want {
		t.Errorf("packages %q, want %q", got, want)
	}
	wantPkg(t, sec, report.Package{Type: "rpm", Name: "libopenssl3", Version: "3.1.4-150600.5.50.1", Arch: "x86_64",
		SourceName: "openssl-3", SourceVersion: "3.1.4-150600.5.50.1",
		Vendor: "SUSE LLC <https://www.suse.com/>", Maintainer: "https://www.suse.com/"})
	wantOwner(t, ix, "/bin/bash", "bash")
	wantOwner(t, ix, "/lib64/libgcc_s.so.1", "libgcc_s1")
}

func TestAPK(t *testing.T) {
	sec, ix := collectRoot(t, fixtureEnv(t, "apk"))
	wantCoverage(t, sec, report.CoverageFull)
	if len(sec.Databases) != 1 || sec.Databases[0] != (report.PackageDB{Type: "apk", Path: "/lib/apk/db/installed"}) {
		t.Errorf("databases %+v", sec.Databases)
	}
	const ncopa = "Natanael Copa <ncopa@alpinelinux.org>"
	// o: gives the origin.
	wantPkg(t, sec, report.Package{Type: "apk", Name: "alpine-baselayout-data", Version: "3.6.5-r0", Arch: "x86_64",
		SourceName: "alpine-baselayout", SourceVersion: "3.6.5-r0", Maintainer: ncopa})
	wantPkg(t, sec, report.Package{Type: "apk", Name: "apk-tools", Version: "2.14.4-r1", Arch: "x86_64",
		SourceName: "apk-tools", SourceVersion: "2.14.4-r1", Maintainer: ncopa})
	if findPkg(sec, "musl") == nil || findPkg(sec, "busybox") == nil {
		t.Errorf("packages %v", names(sec))
	}
	wantOwner(t, ix, "/bin/busybox", "busybox")
	wantOwner(t, ix, "/lib/ld-musl-x86_64.so.1", "musl")
	wantOwner(t, ix, "/bin", "")
}

func TestNoDatabase(t *testing.T) {
	sec, ix := collectRoot(t, collect.NewEnv().WithRoot(t.TempDir()))
	wantCoverage(t, sec, report.CoverageFull)
	if len(sec.Databases) != 0 || len(sec.Packages) != 0 {
		t.Errorf("databases %+v packages %+v", sec.Databases, sec.Packages)
	}
	if sec.Digest == "" {
		t.Error("no digest")
	}
	wantOwner(t, ix, "/bin/sh", "")

	var nilIndex *Index
	if _, ok := nilIndex.Owner("/bin/sh"); ok {
		t.Error("nil index owns a file")
	}
}

func TestDigestStable(t *testing.T) {
	for _, name := range []string{"deb", "distroless", "rpm-sqlite", "rpm-bdb", "rpm-ndb", "apk"} {
		env := fixtureEnv(t, name)
		a, _ := collectRoot(t, env)
		b, _ := collectRoot(t, env)
		if a.Digest == "" || a.Digest != b.Digest {
			t.Errorf("%s: digests %q and %q", name, a.Digest, b.Digest)
		}
	}
}

// copyTree copies a fixture into a temporary root so that tests can damage it.
func copyTree(t *testing.T, name string) string {
	t.Helper()
	dst := t.TempDir()
	src := filepath.Join("testdata", name)
	err := filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		out := filepath.Join(dst, rel)
		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(target, out)
		case fi.IsDir():
			return os.MkdirAll(out, 0o755)
		default:
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return os.WriteFile(out, b, 0o644)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func writeFile(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func truncateFile(t *testing.T, p string, frac float64) {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, p, b[:int(float64(len(b))*frac)])
}

func TestTruncatedDpkg(t *testing.T) {
	root := copyTree(t, "deb")
	p := filepath.Join(root, "var/lib/dpkg/status")
	b, _ := os.ReadFile(p)
	// Cut in the middle of the libc6 stanza, after its Package line.
	i := bytes.Index(b, []byte("Package: libc6\n"))
	writeFile(t, p, b[:i+len("Package: libc6\nStat")])
	sec, _ := collectRoot(t, collect.NewEnv().WithRoot(root))
	wantCoverage(t, sec, report.CoveragePartial)
	if findPkg(sec, "bash") == nil || findPkg(sec, "libc6") != nil {
		t.Errorf("packages %v", names(sec))
	}
	if !strings.Contains(sec.Reason, "/var/lib/dpkg/status") {
		t.Errorf("reason %q", sec.Reason)
	}
}

func TestLongLine(t *testing.T) {
	root := t.TempDir()
	var b bytes.Buffer
	b.WriteString("Package: a\nStatus: install ok installed\nVersion: 1\nDescription: ")
	b.Write(bytes.Repeat([]byte("x"), 3*maxLine))
	b.WriteString("\n\nPackage: b\nStatus: install ok installed\nVersion: 2\n")
	writeFile(t, filepath.Join(root, "var/lib/dpkg/status"), b.Bytes())
	sec, _ := collectRoot(t, collect.NewEnv().WithRoot(root))
	wantCoverage(t, sec, report.CoveragePartial)
	if got := strings.Join(names(sec), " "); got != "a b" {
		t.Errorf("packages %q", got)
	}
}

func TestGarbageDpkg(t *testing.T) {
	root := t.TempDir()
	junk := randomBytes(1, 256<<10)
	writeFile(t, filepath.Join(root, "var/lib/dpkg/status"), junk)
	sec, _ := collectRoot(t, collect.NewEnv().WithRoot(root))
	wantCoverage(t, sec, report.CoverageNone)
}

func randomBytes(seed uint64, n int) []byte {
	rng := rand.New(rand.NewPCG(seed, seed+1))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.Uint32())
	}
	return b
}

func TestTruncatedBDB(t *testing.T) {
	root := copyTree(t, "rpm-bdb")
	truncateFile(t, filepath.Join(root, "var/lib/rpm/Packages"), 0.6)
	sec, _ := collectRoot(t, collect.NewEnv().WithRoot(root))
	wantCoverage(t, sec, report.CoveragePartial)
	if len(sec.Packages) == 0 || len(sec.Packages) >= 6 {
		t.Errorf("packages %v", names(sec))
	}
}

func TestCorruptNDB(t *testing.T) {
	root := copyTree(t, "rpm-ndb")
	p := filepath.Join(root, "usr/lib/sysimage/rpm/Packages.db")
	b, _ := os.ReadFile(p)
	// Break the blob magic of the libopenssl3 header.
	broken := false
	for i := ndbHeaderSlots * ndbSlotSize; i+ndbSlotSize <= ndbPageSize; i += ndbSlotSize {
		if binary.LittleEndian.Uint32(b[i+4:]) == 0 {
			continue
		}
		off := int(binary.LittleEndian.Uint32(b[i+8:])) * ndbBlockSize
		n := int(binary.LittleEndian.Uint32(b[i+12:])) * ndbBlockSize
		if bytes.Contains(b[off:off+n], []byte("libopenssl3\x00")) {
			b[off] ^= 0xff
			broken = true
			break
		}
	}
	if !broken {
		t.Fatal("libopenssl3 not found")
	}
	writeFile(t, p, b)
	sec, _ := collectRoot(t, collect.NewEnv().WithRoot(root))
	wantCoverage(t, sec, report.CoveragePartial)
	if len(sec.Packages) != 3 {
		t.Errorf("packages %v", names(sec))
	}
}

func TestGarbageSQLite(t *testing.T) {
	root := t.TempDir()
	junk := randomBytes(3, 64<<10)
	copy(junk, sqliteMagic)
	writeFile(t, filepath.Join(root, "var/lib/rpm/rpmdb.sqlite"), junk)
	sec, _ := collectRoot(t, collect.NewEnv().WithRoot(root))
	wantCoverage(t, sec, report.CoverageNone)
	if !strings.Contains(sec.Reason, "/var/lib/rpm/rpmdb.sqlite") {
		t.Errorf("reason %q", sec.Reason)
	}
	// The database must not have gained -wal or -shm files.
	ents, _ := os.ReadDir(filepath.Join(root, "var/lib/rpm"))
	if len(ents) != 1 {
		t.Errorf("files next to the database: %v", ents)
	}
}

func TestTruncatedSQLite(t *testing.T) {
	root := copyTree(t, "rpm-sqlite")
	truncateFile(t, filepath.Join(root, "var/lib/rpm/rpmdb.sqlite"), 0.5)
	sec, _ := collectRoot(t, collect.NewEnv().WithRoot(root))
	if sec.Coverage == report.CoverageFull {
		t.Fatalf("coverage full for a truncated database: %v", names(sec))
	}
}

func TestSQLiteReadOnly(t *testing.T) {
	root := copyTree(t, "rpm-sqlite")
	dir := filepath.Join(root, "var/lib/rpm")
	sec, _ := collectRoot(t, collect.NewEnv().WithRoot(root))
	wantCoverage(t, sec, report.CoverageFull)
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Errorf("files next to the database after reading: %v", ents)
	}

	// A write-ahead log without its index may hold changes that were not read.
	writeFile(t, filepath.Join(dir, "rpmdb.sqlite-wal"), make([]byte, 4096))
	sec, _ = collectRoot(t, collect.NewEnv().WithRoot(root))
	wantCoverage(t, sec, report.CoveragePartial)
	if len(sec.Packages) != 5 {
		t.Errorf("packages %v", names(sec))
	}
}

func TestUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	root := copyTree(t, "apk")
	p := filepath.Join(root, "lib/apk/db/installed")
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	sec, _ := collectRoot(t, collect.NewEnv().WithRoot(root))
	wantCoverage(t, sec, report.CoverageNone)
	if len(sec.Databases) != 0 {
		t.Errorf("databases %+v", sec.Databases)
	}
}

func TestMixedPartial(t *testing.T) {
	// A readable dpkg database next to a broken rpm database.
	root := copyTree(t, "deb")
	writeFile(t, filepath.Join(root, "var/lib/rpm/Packages"), []byte("not a database"))
	sec, _ := collectRoot(t, collect.NewEnv().WithRoot(root))
	wantCoverage(t, sec, report.CoveragePartial)
	if findPkg(sec, "bash") == nil {
		t.Errorf("packages %v", names(sec))
	}
}

func TestAbsoluteSymlinkStaysInRoot(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "var/lib/dpkg/status"),
		[]byte("Package: tool\nStatus: install ok installed\nVersion: 1.0\nArchitecture: amd64\n"))
	writeFile(t, filepath.Join(root, "var/lib/dpkg/info/tool.list"), []byte("/.\n/usr\n/usr/bin\n/usr/bin/tool\n"))
	// An absolute target must resolve inside the root, not on the host.
	if err := os.Symlink("/usr/bin", filepath.Join(root, "bin")); err != nil {
		t.Fatal(err)
	}
	_, ix := collectRoot(t, collect.NewEnv().WithRoot(root))
	wantOwner(t, ix, "/bin/tool", "tool")
	wantOwner(t, ix, "/usr/bin/tool", "tool")

	// A symlink loop does not hang.
	if err := os.Symlink("loop", filepath.Join(root, "loop")); err != nil {
		t.Fatal(err)
	}
	wantOwner(t, ix, "/loop/tool", "")
}

func TestOwnerConcurrent(t *testing.T) {
	_, ix := collectRoot(t, fixtureEnv(t, "rpm-sqlite"))
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				if o, ok := ix.Owner("/bin/bash"); !ok || o != "bash" {
					t.Errorf("Owner = %q, %v", o, ok)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestIndexLimit(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "var/lib/dpkg/status"),
		[]byte("Package: many\nStatus: install ok installed\nVersion: 1\n"))
	var b bytes.Buffer
	for i := range 100 {
		b.WriteString("/usr/share/many/f")
		b.WriteString(strings.Repeat("x", i))
		b.WriteByte('\n')
	}
	writeFile(t, filepath.Join(root, "var/lib/dpkg/info/many.list"), b.Bytes())
	_, ix := collectRoot(t, collect.NewEnv().WithRoot(root))
	wantOwner(t, ix, "/usr/share/many/fxx", "many")
	if !ix.Complete() || len(ix.files) != 100 {
		t.Errorf("complete %v, %d files", ix.Complete(), len(ix.files))
	}
}

// TestCorruptionNeverPanics flips random bytes in every rpm database and
// reads it again, including the file index.
func TestCorruptionNeverPanics(t *testing.T) {
	rng := rand.New(rand.NewPCG(5, 6))
	for _, tc := range []struct{ fixture, db string }{
		{"rpm-sqlite", "var/lib/rpm/rpmdb.sqlite"},
		{"rpm-bdb", "var/lib/rpm/Packages"},
		{"rpm-ndb", "usr/lib/sysimage/rpm/Packages.db"},
		{"apk", "lib/apk/db/installed"},
		{"deb", "var/lib/dpkg/status"},
	} {
		orig, err := os.ReadFile(filepath.Join("testdata", tc.fixture, tc.db))
		if err != nil {
			t.Fatal(err)
		}
		root := copyTree(t, tc.fixture)
		p := filepath.Join(root, tc.db)
		for round := range 20 {
			b := append([]byte(nil), orig...)
			for range 1 + rng.IntN(64) {
				b[rng.IntN(len(b))] = byte(rng.Uint32())
			}
			if round%5 == 4 {
				b = b[:rng.IntN(len(b))]
			}
			writeFile(t, p, b)
			sec, ix := collectRoot(t, collect.NewEnv().WithRoot(root))
			ix.Owner("/usr/bin/bash")
			_ = sec
		}
	}
}

func FuzzRPMHeader(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 0, 0, 0, 4, 0, 0, 3, 232, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 1, 'a', 'b', 'c', 0})
	f.Add([]byte{0, 0, 0, 1, 0, 0, 0, 4, 0, 0, 4, 93, 0, 0, 0, 8, 0, 0, 0, 0, 255, 255, 255, 255, 'a', 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if h, err := parseRPMHeader(b, pkgTags); err == nil {
			_, _, _ = rpmPackage(h)
		}
		if h, err := parseRPMHeader(b, fileTags); err == nil {
			_, _, _ = rpmFiles(h)
		}
	})
}

func FuzzDpkgStatus(f *testing.F) {
	f.Add([]byte("Package: a\nStatus: install ok installed\nVersion: 1\nSource: b (2)\n\n"))
	f.Add([]byte("Package: a\n Status\n:\n\n\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = parseDpkgStatus(context.Background(), bytes.NewReader(b), true)
		_, _ = parseAPKInstalled(context.Background(), bytes.NewReader(b))
		_ = parseAPKFiles(context.Background(), bytes.NewReader(b), func(string, string) bool { return true })
	})
}

func FuzzRPMContainers(f *testing.F) {
	for _, p := range []string{"testdata/rpm-bdb/var/lib/rpm/Packages", "testdata/rpm-ndb/usr/lib/sysimage/rpm/Packages.db"} {
		b, err := os.ReadFile(p)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b[:min(len(b), 64<<10)])
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r := bytes.NewReader(b)
		fn := func(blob []byte) bool {
			if h, err := parseRPMHeader(blob, pkgTags); err == nil {
				_, _, _ = rpmPackage(h)
			}
			return true
		}
		if n, err := openNDB(r, int64(len(b))); err == nil {
			_, _ = n.each(context.Background(), fn)
		}
		if d, err := openBDB(r, int64(len(b))); err == nil {
			_, _ = d.each(context.Background(), fn)
		}
	})
}
