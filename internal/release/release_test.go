// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package release

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/sign"
	"github.com/bomcensus/bomcensus/internal/sign/signtest"
)

var names = []string{"bomcensus-agent", "bomcensus-probe"}

type fixture struct {
	trust    *signtest.Trust
	manifest []byte
	sig      []byte
	files    []File
	now      time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	tr := signtest.Install(t)
	now := time.Now()
	m := &sign.Manifest{Version: "1.0.0", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	var files []File
	for _, arch := range []string{"amd64", "arm64"} {
		signed := tr.SignELF(t, signtest.ELF(t, arch))
		for _, n := range names {
			files = append(files, File{OS: "linux", Arch: arch, Name: n, Data: signed})
			m.Files = append(m.Files, signtest.FileEntry("linux", arch, n, signed))
		}
	}
	b, sig := tr.SignManifest(t, m)
	return &fixture{trust: tr, manifest: b, sig: sig, files: files, now: now}
}

func (f *fixture) write(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(context.Background(), &buf, f.manifest, f.sig, f.files); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestBundleRoundTrip(t *testing.T) {
	f := newFixture(t)
	b, err := Open(context.Background(), bytes.NewReader(f.write(t)), f.now)
	if err != nil {
		t.Fatal(err)
	}
	if b.Version() != "1.0.0" {
		t.Fatalf("version %q", b.Version())
	}
	if got := b.Platforms(); len(got) != 2 || got[0] != (Platform{"linux", "amd64"}) || got[1] != (Platform{"linux", "arm64"}) {
		t.Fatalf("platforms %v", got)
	}
	for _, want := range f.files {
		got, ok := b.File(want.OS, want.Arch, want.Name)
		if !ok || !bytes.Equal(got, want.Data) {
			t.Fatalf("%s differs", want.Path())
		}
	}
	if !bytes.Equal(b.ManifestBytes(), f.manifest) || !bytes.Equal(b.Signature(), f.sig) {
		t.Fatal("manifest or signature differs")
	}
}

func TestBundlePlatformExtract(t *testing.T) {
	f := newFixture(t)
	full, err := Open(context.Background(), bytes.NewReader(f.write(t)), f.now)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := full.WritePlatform(context.Background(), &buf, "linux", "arm64"); err != nil {
		t.Fatal(err)
	}
	part, err := Open(context.Background(), bytes.NewReader(buf.Bytes()), f.now)
	if err != nil {
		t.Fatal(err)
	}
	if got := part.Platforms(); len(got) != 1 || got[0] != (Platform{"linux", "arm64"}) {
		t.Fatalf("platforms %v", got)
	}
	if len(part.Files("linux", "arm64")) != len(names) || len(part.Files("linux", "amd64")) != 0 {
		t.Fatal("unexpected files")
	}
	// The manifest still describes the whole release.
	if len(part.Manifest().Files) != 2*len(names) {
		t.Fatal("manifest was changed")
	}
	if err := full.WritePlatform(context.Background(), io.Discard, "linux", "riscv64"); err == nil {
		t.Fatal("extracted a missing platform")
	}
}

// entry is a raw tar entry used to build malformed bundles.
type entry struct {
	name string
	typ  byte
	data []byte
}

func rawTar(t *testing.T, entries []entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.name, Typeflag: typ, Mode: 0o755, Size: int64(len(e.data))}
		if typ != tar.TypeReg {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write(e.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func (f *fixture) entries() []entry {
	es := []entry{{name: ManifestName, data: f.manifest}, {name: SignatureName, data: f.sig}}
	for _, fl := range f.files {
		es = append(es, entry{name: fl.Path(), data: fl.Data})
	}
	return es
}

func TestBundleRejects(t *testing.T) {
	f := newFixture(t)
	open := func(data []byte) error {
		_, err := Open(context.Background(), bytes.NewReader(data), f.now)
		return err
	}
	if err := open(rawTar(t, f.entries())); err != nil {
		t.Fatalf("baseline: %v", err)
	}

	cases := map[string]func(es []entry) []entry{
		"tampered file": func(es []entry) []entry {
			d := bytes.Clone(es[2].data)
			d[len(d)/2] ^= 1
			es[2].data = d
			return es
		},
		"tampered manifest": func(es []entry) []entry {
			es[0].data = bytes.Replace(es[0].data, []byte("1.0.0"), []byte("2.0.0"), 1)
			return es
		},
		"bad signature": func(es []entry) []entry {
			s := bytes.Clone(es[1].data)
			s[3] ^= 1
			es[1].data = s
			return es
		},
		"manifest not first": func(es []entry) []entry {
			es[0], es[1] = es[1], es[0]
			return es
		},
		"unlisted file": func(es []entry) []entry {
			return append(es, entry{name: "linux-amd64/extra", data: []byte("x")})
		},
		"duplicate file": func(es []entry) []entry { return append(es, es[2]) },
		"incomplete platform": func(es []entry) []entry {
			return es[:3]
		},
		"no files": func(es []entry) []entry { return es[:2] },
		"path traversal": func(es []entry) []entry {
			es[2].name = "linux-amd64/../linux-amd64/" + names[0]
			return es
		},
		"symlink": func(es []entry) []entry {
			return append(es, entry{name: "linux-amd64/link", typ: tar.TypeSymlink})
		},
		"swapped architectures": func(es []entry) []entry {
			es[2].data, es[4].data = es[4].data, es[2].data
			return es
		},
	}
	for name, mod := range cases {
		err := open(rawTar(t, mod(f.entries())))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		t.Logf("%s: %v", name, err)
	}

	t.Run("expired manifest", func(t *testing.T) {
		if _, err := Open(context.Background(), bytes.NewReader(f.write(t)), f.now.Add(2*time.Hour)); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("oversized file", func(t *testing.T) {
		old := maxFileSize
		maxFileSize = 1024
		defer func() { maxFileSize = old }()
		if err := open(f.write(t)); err == nil || !strings.Contains(err.Error(), "limit") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("oversized bundle", func(t *testing.T) {
		old := maxBundleSize
		maxBundleSize = 64 << 10
		defer func() { maxBundleSize = old }()
		if err := open(f.write(t)); err == nil || !strings.Contains(err.Error(), "size limit") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("write rejects mismatched file", func(t *testing.T) {
		files := append([]File(nil), f.files...)
		files[0].Data = []byte("not the file")
		if err := Write(context.Background(), io.Discard, f.manifest, f.sig, files); err == nil {
			t.Fatal("accepted")
		}
	})
}

// TestBundleCodeSignature covers files whose manifest entry matches but whose
// code signature or architecture is wrong.
func TestBundleCodeSignature(t *testing.T) {
	tr := signtest.Install(t)
	now := time.Now()
	build := func(t *testing.T, arch string, data []byte) error {
		m := &sign.Manifest{
			Version: "1.0.0", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
			Files: []sign.File{signtest.FileEntry("linux", arch, names[0], data)},
		}
		b, sig := tr.SignManifest(t, m)
		var buf bytes.Buffer
		if err := Write(context.Background(), &buf, b, sig, []File{{OS: "linux", Arch: arch, Name: names[0], Data: data}}); err != nil {
			t.Fatal(err)
		}
		_, err := Open(context.Background(), &buf, now)
		return err
	}
	elf := signtest.ELF(t, "amd64")
	signed := tr.SignELF(t, elf)
	if err := build(t, "amd64", signed); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if err := build(t, "amd64", elf); err == nil {
		t.Error("unsigned ELF accepted")
	}
	tampered := bytes.Clone(signed)
	tampered[len(elf)/3] ^= 1
	if err := build(t, "amd64", tampered); err == nil {
		t.Error("tampered ELF accepted")
	}
	if err := build(t, "arm64", signed); err == nil {
		t.Error("amd64 ELF accepted as arm64")
	}
	if err := build(t, "amd64", signtest.NewTrust(t).SignELF(t, elf)); err == nil {
		t.Error("ELF signed by another root accepted")
	}
	if err := build(t, "amd64", []byte("#!/bin/sh\necho hi\n")); err == nil {
		t.Error("non-ELF accepted")
	}
}

// TestBundleWindows covers Windows platforms: PE files with Authenticode
// signatures next to Linux files in one bundle.
func TestBundleWindows(t *testing.T) {
	tr := signtest.Install(t)
	now := time.Now()
	m := &sign.Manifest{Version: "1.0.0", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	var files []File
	add := func(goos, arch, name string, data []byte) {
		files = append(files, File{OS: goos, Arch: arch, Name: name, Data: data})
		m.Files = append(m.Files, signtest.FileEntry(goos, arch, name, data))
	}
	add("linux", "amd64", names[0], tr.SignELF(t, signtest.ELF(t, "amd64")))
	for _, arch := range []string{"amd64", "arm64"} {
		add("windows", arch, names[0]+".exe", tr.SignPE(t, signtest.PE(t, arch)))
	}
	mb, sig := tr.SignManifest(t, m)
	var buf bytes.Buffer
	if err := Write(context.Background(), &buf, mb, sig, files); err != nil {
		t.Fatal(err)
	}
	b, err := Open(context.Background(), bytes.NewReader(buf.Bytes()), now)
	if err != nil {
		t.Fatal(err)
	}
	want := []Platform{{"linux", "amd64"}, {"windows", "amd64"}, {"windows", "arm64"}}
	if got := b.Platforms(); len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("platforms %v", got)
	}
	var one bytes.Buffer
	if err := b.WritePlatform(context.Background(), &one, "windows", "arm64"); err != nil {
		t.Fatal(err)
	}
	if b, err = Open(context.Background(), &one, now); err != nil {
		t.Fatal(err)
	}
	if got := b.Files("windows", "arm64"); len(got) != 1 || got[0].Name != names[0]+".exe" {
		t.Fatalf("files %v", got)
	}
}

func TestBundleWindowsCodeSignature(t *testing.T) {
	tr := signtest.Install(t)
	now := time.Now()
	build := func(t *testing.T, arch string, data []byte) error {
		m := &sign.Manifest{
			Version: "1.0.0", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
			Files: []sign.File{signtest.FileEntry("windows", arch, "bomcensus-agent.exe", data)},
		}
		b, sig := tr.SignManifest(t, m)
		var buf bytes.Buffer
		if err := Write(context.Background(), &buf, b, sig, []File{{OS: "windows", Arch: arch, Name: "bomcensus-agent.exe", Data: data}}); err != nil {
			t.Fatal(err)
		}
		_, err := Open(context.Background(), &buf, now)
		return err
	}
	pe := signtest.PE(t, "amd64")
	signed := tr.SignPE(t, pe)
	if err := build(t, "amd64", signed); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if err := build(t, "amd64", pe); err == nil {
		t.Error("unsigned PE accepted")
	}
	tampered := bytes.Clone(signed)
	tampered[0x200] ^= 1
	if err := build(t, "amd64", tampered); err == nil {
		t.Error("tampered PE accepted")
	}
	if err := build(t, "arm64", signed); err == nil {
		t.Error("amd64 PE accepted as arm64")
	}
	if err := build(t, "amd64", signtest.NewTrust(t).SignPE(t, pe)); err == nil {
		t.Error("PE signed by another root accepted")
	}
	if err := build(t, "amd64", tr.SignELF(t, signtest.ELF(t, "amd64"))); err == nil {
		t.Error("ELF accepted on windows")
	}
	if err := build(t, "386", signed); err == nil {
		t.Error("unsupported architecture accepted")
	}
}

func TestExeName(t *testing.T) {
	if got := ExeName("windows", "bomcensus-agent"); got != "bomcensus-agent.exe" {
		t.Fatal(got)
	}
	if got := ExeName("linux", "bomcensus-agent"); got != "bomcensus-agent" {
		t.Fatal(got)
	}
}

func TestCheckMachine(t *testing.T) {
	other := map[string]string{"amd64": "arm64", "arm64": "amd64"}
	for _, arch := range []string{"amd64", "arm64"} {
		for goos, data := range map[string][]byte{"linux": signtest.ELF(t, arch), "windows": signtest.PE(t, arch)} {
			if err := CheckMachine(goos, data, arch); err != nil {
				t.Fatalf("%s/%s: %v", goos, arch, err)
			}
			if err := CheckMachine(goos, data, other[arch]); err == nil {
				t.Fatalf("%s/%s accepted as %s", goos, arch, other[arch])
			}
		}
	}
	if err := CheckMachine("windows", signtest.ELF(t, "amd64"), "amd64"); err == nil {
		t.Fatal("ELF accepted as PE")
	}
	if err := CheckMachine("linux", signtest.PE(t, "amd64"), "amd64"); err == nil {
		t.Fatal("PE accepted as ELF")
	}
	if err := CheckMachine("windows", signtest.PE(t, "amd64"), "riscv64"); err == nil {
		t.Fatal("unknown architecture accepted")
	}
	if err := CheckMachine("darwin", signtest.ELF(t, "amd64"), "amd64"); err == nil {
		t.Fatal("unknown os accepted")
	}
}
