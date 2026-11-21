// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package updatesvc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/release"
	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/internal/sign"
	"github.com/bomcensus/bomcensus/internal/sign/signtest"
)

var fileNames = []string{"bomcensus-agent", ProbeName, "bomcensus-updater"}

type fixture struct {
	trust *signtest.Trust
	elf   map[string][]byte // signed ELF per arch
	now   time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	tr := signtest.Install(t)
	f := &fixture{trust: tr, elf: map[string][]byte{}, now: time.Now()}
	for _, arch := range []string{"amd64", "arm64"} {
		f.elf[arch] = tr.SignELF(t, signtest.ELF(t, arch))
	}
	return f
}

// bundle builds a signed bundle of version for the given architectures.
// The manifest always lists both architectures.
func (f *fixture) bundle(t *testing.T, version string, arches ...string) []byte {
	t.Helper()
	m := &sign.Manifest{Version: version, IssuedAt: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(24 * time.Hour)}
	var files []release.File
	for _, arch := range []string{"amd64", "arm64"} {
		for _, n := range fileNames {
			m.Files = append(m.Files, signtest.FileEntry("linux", arch, n, f.elf[arch]))
		}
	}
	for _, arch := range arches {
		for _, n := range fileNames {
			files = append(files, release.File{OS: "linux", Arch: arch, Name: n, Data: f.elf[arch]})
		}
	}
	mb, sig := f.trust.SignManifest(t, m)
	var buf bytes.Buffer
	if err := release.Write(context.Background(), &buf, mb, sig, files); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func newService(t *testing.T) *Service {
	t.Helper()
	s, err := New(Config{Store: newTestDB(t)})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestImport(t *testing.T) {
	f := newFixture(t)
	s := newService(t)
	ctx := context.Background()
	full := f.bundle(t, "1.0.0", "amd64", "arm64")

	r, err := s.Import(ctx, bytes.NewReader(full), store.ReleaseUpload)
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != "1.0.0" || !r.Verified || r.Source != store.ReleaseUpload || len(r.Platforms) != 2 {
		t.Fatalf("release %+v", r)
	}
	if _, err := s.Import(ctx, bytes.NewReader(full), store.ReleaseUpload); !errors.Is(err, ErrExists) {
		t.Fatalf("second import: %v", err)
	}

	// Same version, different manifest.
	f.now = f.now.Add(time.Second)
	if _, err := s.Import(ctx, bytes.NewReader(f.bundle(t, "1.0.0", "amd64")), store.ReleaseUpload); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("different manifest: %v", err)
	}

	list, err := s.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list %v %v", list, err)
	}
}

func TestImportRejectsTampered(t *testing.T) {
	f := newFixture(t)
	s := newService(t)
	ctx := context.Background()
	b := f.bundle(t, "1.0.0", "amd64")
	// Flip a byte well inside the first executable.
	start := bytes.Index(b, f.elf["amd64"][:64])
	if start < 0 {
		t.Fatal("executable not found in bundle")
	}
	b[start+4096] ^= 0xff
	if _, err := s.Import(ctx, bytes.NewReader(b), store.ReleaseUpload); !errors.Is(err, ErrVerification) {
		t.Fatalf("tampered: %v", err)
	}
	if _, err := s.Import(ctx, bytes.NewReader([]byte("not a tar")), store.ReleaseUpload); !errors.Is(err, ErrVerification) {
		t.Fatalf("garbage: %v", err)
	}
	// Signed with a key the server does not trust.
	other := signtest.NewTrust(t)
	m := &sign.Manifest{Version: "2.0.0", IssuedAt: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(time.Hour)}
	var files []release.File
	for _, n := range fileNames {
		m.Files = append(m.Files, signtest.FileEntry("linux", "amd64", n, f.elf["amd64"]))
		files = append(files, release.File{OS: "linux", Arch: "amd64", Name: n, Data: f.elf["amd64"]})
	}
	mb, sig := other.SignManifest(t, m)
	var buf bytes.Buffer
	if err := release.Write(ctx, &buf, mb, sig, files); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Import(ctx, &buf, store.ReleaseUpload); !errors.Is(err, ErrVerification) {
		t.Fatalf("untrusted key: %v", err)
	}
	if list, _ := s.List(ctx); len(list) != 0 {
		t.Fatalf("rejected bundles stored: %v", list)
	}
}

func TestImportAddsPlatforms(t *testing.T) {
	f := newFixture(t)
	s := newService(t)
	ctx := context.Background()
	r, err := s.Import(ctx, bytes.NewReader(f.bundle(t, "1.0.0", "amd64")), store.ReleaseUpload)
	if err != nil || len(r.Platforms) != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = s.Import(ctx, bytes.NewReader(f.bundle(t, "1.0.0", "amd64", "arm64")), store.ReleaseUpload)
	if err != nil || len(r.Platforms) != 2 {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestBundle(t *testing.T) {
	f := newFixture(t)
	s := newService(t)
	ctx := context.Background()
	if _, err := s.Import(ctx, bytes.NewReader(f.bundle(t, "1.0.0", "amd64", "arm64")), store.ReleaseUpload); err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "arm64"} {
		rc, size, err := s.Bundle(ctx, "1.0.0", "linux", arch)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(data)) != size {
			t.Fatalf("%s: announced %d bytes, streamed %d", arch, size, len(data))
		}
		b, err := release.Open(ctx, bytes.NewReader(data), time.Now())
		if err != nil {
			t.Fatalf("%s: re-open: %v", arch, err)
		}
		if p := b.Platforms(); len(p) != 1 || p[0].Arch != arch {
			t.Fatalf("platforms %v", p)
		}
		got, ok := b.File("linux", arch, ProbeName)
		if !ok || !bytes.Equal(got, f.elf[arch]) {
			t.Fatal("file differs")
		}
		c, err := s.Check(ctx, "0.9.0", "linux", arch)
		if err != nil {
			t.Fatal(err)
		}
		if c.TargetVersion != "" || c.Manifest != nil {
			t.Fatalf("check without a deployed version: %+v", c)
		}
	}
	if _, _, err := s.Bundle(ctx, "1.0.0", "linux", "riscv64"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing platform: %v", err)
	}
	if _, _, err := s.Bundle(ctx, "9.9.9", "linux", "amd64"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing version: %v", err)
	}

	// Closing early ends the stream without leaking the writer.
	rc, _, err := s.Bundle(ctx, "1.0.0", "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rc.Read(make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	rc.Close()
}

func TestSettingsProbeCheck(t *testing.T) {
	f := newFixture(t)
	s := newService(t)
	ctx := context.Background()

	if _, _, err := s.Probe(ctx, "linux", "amd64"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("probe without releases: %v", err)
	}
	if _, err := s.Import(ctx, bytes.NewReader(f.bundle(t, "1.0.0", "amd64", "arm64")), store.ReleaseUpload); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Import(ctx, bytes.NewReader(f.bundle(t, "1.10.0", "amd64")), store.ReleaseUpload); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Import(ctx, bytes.NewReader(f.bundle(t, "1.9.0", "amd64")), store.ReleaseUpload); err != nil {
		t.Fatal(err)
	}

	// No deployed version: newest release with the platform.
	probe, v, err := s.Probe(ctx, "linux", "amd64")
	if err != nil || v != "1.10.0" || !bytes.Equal(probe, f.elf["amd64"]) {
		t.Fatalf("probe amd64: %s %v", v, err)
	}
	if _, v, _ := s.Probe(ctx, "linux", "arm64"); v != "1.0.0" {
		t.Fatalf("probe arm64: %s", v)
	}

	for _, bad := range []store.UpdateSettings{
		{TargetVersion: "1.0.0", CheckIntervalMinutes: 0},
		{TargetVersion: "1.0.0", CheckIntervalMinutes: MaxCheckIntervalMinutes + 1},
		{TargetVersion: "3.0.0", CheckIntervalMinutes: 60},
	} {
		if err := s.SetSettings(ctx, bad); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%+v: %v", bad, err)
		}
	}
	if err := s.SetSettings(ctx, store.UpdateSettings{TargetVersion: "1.0.0", CheckIntervalMinutes: 30}); err != nil {
		t.Fatal(err)
	}
	if set, _ := s.Settings(ctx); set.TargetVersion != "1.0.0" || set.CheckIntervalMinutes != 30 {
		t.Fatalf("settings %+v", set)
	}
	// Deployed version wins.
	if _, v, _ := s.Probe(ctx, "linux", "amd64"); v != "1.0.0" {
		t.Fatalf("probe with deployed version: %s", v)
	}

	c, err := s.Check(ctx, "0.9.0", "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if c.TargetVersion != "1.0.0" || c.CheckIntervalMinutes != 30 || !c.Newer || len(c.Files) != len(fileNames) || len(c.Manifest) == 0 || len(c.Signature) == 0 {
		t.Fatalf("check %+v", c)
	}
	rc, size, _ := s.Bundle(ctx, "1.0.0", "linux", "amd64")
	rc.Close()
	if c.BundleSize != size {
		t.Fatalf("bundle size %d, want %d", c.BundleSize, size)
	}
	if c, _ := s.Check(ctx, "1.2.0", "linux", "amd64"); c.Newer {
		t.Fatal("downgrade reported as newer")
	}
	// Deployed release without the caller's platform.
	if err := s.SetSettings(ctx, store.UpdateSettings{TargetVersion: "1.10.0", CheckIntervalMinutes: 30}); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.Check(ctx, "1.0.0", "linux", "arm64"); c.TargetVersion != "1.10.0" || c.Files != nil {
		t.Fatalf("check without platform %+v", c)
	}
	if err := s.SetSettings(ctx, store.UpdateSettings{CheckIntervalMinutes: 60}); err != nil {
		t.Fatal(err)
	}
}

func TestImportDir(t *testing.T) {
	f := newFixture(t)
	s := newService(t)
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bomcensus-1.0.0.tar"), f.bundle(t, "1.0.0", "amd64"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.tar"), []byte("junk"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("ignored"), 0o644); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.ImportDir(ctx, dir); err != nil {
			t.Fatal(err)
		}
	}
	list, err := s.List(ctx)
	if err != nil || len(list) != 1 || list[0].Version != "1.0.0" {
		t.Fatalf("list %+v %v", list, err)
	}
	if err := s.ImportDir(ctx, filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing directory accepted")
	}
}
