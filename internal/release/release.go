// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package release reads, verifies and writes release bundles.
//
// A bundle is an uncompressed tar file whose first two entries are
// manifest.json and manifest.sig, followed by the files of the release at
// <os>-<arch>/<name> (for example linux-amd64/bomcensus-agent or
// windows-amd64/bomcensus-agent.exe).
//
// A bundle need not contain every file the manifest lists: a bundle cut
// down to one platform keeps the signed manifest of the full release. Every
// platform that is present must be complete, and at least one must be
// present.
package release

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/bomcensus/bomcensus/internal/sign"
)

const (
	// ManifestName is the tar entry holding the encoded manifest.
	ManifestName = "manifest.json"
	// SignatureName is the tar entry holding the detached manifest signature.
	SignatureName = "manifest.sig"
)

// Limits applied when reading a bundle. Variables so tests can lower them.
var (
	maxFileSize   int64 = 256 << 20
	maxBundleSize int64 = 1 << 30
	maxEntries          = 2 + sign.MaxManifestFiles
)

// File is one release file with its contents.
type File struct {
	OS   string
	Arch string
	Name string
	Data []byte
}

// Path returns the tar entry name of the file.
func (f File) Path() string { return f.OS + "-" + f.Arch + "/" + f.Name }

// Platform is an os/arch pair.
type Platform struct {
	OS   string
	Arch string
}

func (p Platform) String() string { return p.OS + "-" + p.Arch }

type fileKey struct{ os, arch, name string }

// Bundle is a verified release bundle held in memory. The bytes it returns
// are the bytes that were verified.
type Bundle struct {
	manifest      *sign.Manifest
	manifestBytes []byte
	signature     []byte
	files         map[fileKey][]byte
	platforms     []Platform
}

// Manifest returns a copy of the verified manifest.
func (b *Bundle) Manifest() *sign.Manifest {
	m := *b.manifest
	m.Files = append([]sign.File(nil), b.manifest.Files...)
	return &m
}

// Version returns the release version.
func (b *Bundle) Version() string { return b.manifest.Version }

// ManifestBytes returns the signed manifest bytes.
func (b *Bundle) ManifestBytes() []byte { return bytes.Clone(b.manifestBytes) }

// Signature returns the detached manifest signature.
func (b *Bundle) Signature() []byte { return bytes.Clone(b.signature) }

// Platforms returns the platforms present in the bundle, in manifest order.
func (b *Bundle) Platforms() []Platform { return append([]Platform(nil), b.platforms...) }

// File returns the contents of one file. The returned slice must not be
// modified.
func (b *Bundle) File(os, arch, name string) ([]byte, bool) {
	d, ok := b.files[fileKey{os, arch, name}]
	return d, ok
}

// Files returns the files of one platform in manifest order. The returned
// data must not be modified.
func (b *Bundle) Files(os, arch string) []File {
	var out []File
	for _, f := range b.manifest.FilesFor(os, arch) {
		if d, ok := b.files[fileKey{f.OS, f.Arch, f.Name}]; ok {
			out = append(out, File{OS: f.OS, Arch: f.Arch, Name: f.Name, Data: d})
		}
	}
	return out
}

// WritePlatform writes a bundle that holds only the files of one platform,
// with the original manifest and signature. The result is a valid bundle.
func (b *Bundle) WritePlatform(ctx context.Context, w io.Writer, os, arch string) error {
	files := b.Files(os, arch)
	if len(files) == 0 {
		return fmt.Errorf("release: bundle has no files for %s-%s", os, arch)
	}
	return Write(ctx, w, b.manifestBytes, b.signature, files)
}

// Write writes a bundle. Every file must match its manifest entry and the
// files present must form complete platforms. The signature is not checked.
func Write(ctx context.Context, w io.Writer, manifest, sig []byte, files []File) error {
	m, err := sign.ParseUnverifiedManifest(manifest)
	if err != nil {
		return err
	}
	byKey := make(map[fileKey][]byte, len(files))
	for _, f := range files {
		k := fileKey{f.OS, f.Arch, f.Name}
		if _, dup := byKey[k]; dup {
			return fmt.Errorf("release: duplicate file %s", f.Path())
		}
		e, ok := m.Lookup(f.OS, f.Arch, f.Name)
		if !ok {
			return fmt.Errorf("release: %s is not in the manifest", f.Path())
		}
		if err := checkContent(e, f.Data); err != nil {
			return err
		}
		byKey[k] = f.Data
	}
	if _, err := completePlatforms(m, byKey); err != nil {
		return err
	}

	tw := tar.NewWriter(w)
	epoch := time.Unix(0, 0)
	put := func(name string, mode int64, data []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		hdr := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     name,
			Mode:     mode,
			Size:     int64(len(data)),
			ModTime:  epoch,
			Format:   tar.FormatUSTAR,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("release: write %s: %w", name, err)
		}
		if _, err := tw.Write(data); err != nil {
			return fmt.Errorf("release: write %s: %w", name, err)
		}
		return nil
	}
	if err := put(ManifestName, 0o644, manifest); err != nil {
		return err
	}
	if err := put(SignatureName, 0o644, sig); err != nil {
		return err
	}
	// Manifest order keeps the output deterministic.
	for _, e := range m.Files {
		d, ok := byKey[fileKey{e.OS, e.Arch, e.Name}]
		if !ok {
			continue
		}
		if err := put(File{OS: e.OS, Arch: e.Arch, Name: e.Name}.Path(), 0o755, d); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("release: write bundle: %w", err)
	}
	return nil
}

// Open reads a bundle from r and verifies it completely: the manifest
// signature against the compiled-in release keys and its validity period at
// now, the size and SHA-256 of every file, that every file is listed in the
// manifest, that present platforms are complete, and the code signature of
// every file. Linux files must be ELF executables for the platform's
// architecture with a valid AuthentiELF signature, Windows files PE
// executables for the platform's architecture with a valid Authenticode
// signature; other operating systems are rejected.
func Open(ctx context.Context, r io.Reader, now time.Time) (*Bundle, error) {
	lr := &limitReader{r: r, n: maxBundleSize}
	tr := tar.NewReader(lr)

	manifest, err := readSmall(tr, ManifestName, sign.MaxManifestSize)
	if err != nil {
		return nil, err
	}
	sig, err := readSmall(tr, SignatureName, 1024)
	if err != nil {
		return nil, err
	}
	m, err := sign.VerifyManifest(manifest, sig, now)
	if err != nil {
		return nil, fmt.Errorf("release: %w", err)
	}

	files := make(map[fileKey][]byte)
	for entries := 2; ; entries++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("release: read bundle: %w", lr.wrap(err))
		}
		if entries >= maxEntries {
			return nil, errors.New("release: too many entries in bundle")
		}
		if hdr.Typeflag == tar.TypeDir {
			if _, ok := parsePlatformDir(strings.TrimSuffix(hdr.Name, "/")); !ok {
				return nil, fmt.Errorf("release: unexpected directory %q", hdr.Name)
			}
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("release: %q is not a regular file", hdr.Name)
		}
		k, ok := parseFilePath(hdr.Name)
		if !ok {
			return nil, fmt.Errorf("release: unexpected entry %q", hdr.Name)
		}
		if _, dup := files[k]; dup {
			return nil, fmt.Errorf("release: duplicate entry %q", hdr.Name)
		}
		e, ok := m.Lookup(k.os, k.arch, k.name)
		if !ok {
			return nil, fmt.Errorf("release: %q is not in the manifest", hdr.Name)
		}
		// Reject before reading anything that cannot match.
		if hdr.Size != e.Size {
			return nil, fmt.Errorf("release: %s: size %d, manifest says %d", hdr.Name, hdr.Size, e.Size)
		}
		if hdr.Size > maxFileSize {
			return nil, fmt.Errorf("release: %s: size %d exceeds the limit of %d", hdr.Name, hdr.Size, maxFileSize)
		}
		data := make([]byte, hdr.Size)
		if _, err := io.ReadFull(tr, data); err != nil {
			return nil, fmt.Errorf("release: read %s: %w", hdr.Name, lr.wrap(err))
		}
		if err := checkContent(e, data); err != nil {
			return nil, err
		}
		if err := verifyCode(k, data); err != nil {
			return nil, fmt.Errorf("release: %s: %w", hdr.Name, err)
		}
		files[k] = data
	}
	platforms, err := completePlatforms(m, files)
	if err != nil {
		return nil, err
	}
	return &Bundle{manifest: m, manifestBytes: manifest, signature: sig, files: files, platforms: platforms}, nil
}

func readSmall(tr *tar.Reader, name string, limit int64) ([]byte, error) {
	hdr, err := tr.Next()
	if err != nil {
		return nil, fmt.Errorf("release: read %s: %w", name, err)
	}
	if hdr.Typeflag != tar.TypeReg || hdr.Name != name {
		return nil, fmt.Errorf("release: expected %s, found %q", name, hdr.Name)
	}
	if hdr.Size > limit {
		return nil, fmt.Errorf("release: %s is %d bytes, maximum is %d", name, hdr.Size, limit)
	}
	b := make([]byte, hdr.Size)
	if _, err := io.ReadFull(tr, b); err != nil {
		return nil, fmt.Errorf("release: read %s: %w", name, err)
	}
	return b, nil
}

func checkContent(e sign.File, data []byte) error {
	if int64(len(data)) != e.Size {
		return fmt.Errorf("release: %s-%s/%s: size %d, manifest says %d", e.OS, e.Arch, e.Name, len(data), e.Size)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != e.SHA256 {
		return fmt.Errorf("release: %s-%s/%s: SHA-256 does not match the manifest", e.OS, e.Arch, e.Name)
	}
	return nil
}

// ExeName returns the file name of executable name on operating system
// goos: name plus ".exe" on Windows.
func ExeName(goos, name string) string {
	if goos == "windows" {
		return name + ".exe"
	}
	return name
}

// CheckMachine checks that data is an executable of operating system goos
// (ELF for linux, PE for windows) for architecture arch.
func CheckMachine(goos string, data []byte, arch string) error {
	switch goos {
	case "linux":
		return checkELFMachine(data, arch)
	case "windows":
		return checkPEMachine(data, arch)
	default:
		return fmt.Errorf("unsupported os %q", goos)
	}
}

// VerifyCode checks that data is an executable of goos and arch with a
// valid code signature (AuthentiELF for linux, Authenticode for windows).
func VerifyCode(goos string, data []byte, arch string) error {
	if err := CheckMachine(goos, data, arch); err != nil {
		return err
	}
	switch goos {
	case "linux":
		return sign.VerifyELF(data)
	default:
		return sign.VerifyPE(data)
	}
}

func verifyCode(k fileKey, data []byte) error {
	return VerifyCode(k.os, data, k.arch)
}

// completePlatforms checks that every platform with at least one file
// present has all of its manifest files present, and returns those
// platforms in manifest order.
func completePlatforms(m *sign.Manifest, files map[fileKey][]byte) ([]Platform, error) {
	var out []Platform
	seen := map[Platform]bool{}
	for _, e := range m.Files {
		p := Platform{e.OS, e.Arch}
		if seen[p] {
			continue
		}
		seen[p] = true
		want := m.FilesFor(e.OS, e.Arch)
		have := 0
		for _, f := range want {
			if _, ok := files[fileKey{f.OS, f.Arch, f.Name}]; ok {
				have++
			}
		}
		switch {
		case have == 0:
		case have < len(want):
			return nil, fmt.Errorf("release: platform %s is incomplete (%d of %d files)", p, have, len(want))
		default:
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("release: bundle contains no files")
	}
	return out, nil
}

func parsePlatformDir(s string) (Platform, bool) {
	osName, arch, ok := strings.Cut(s, "-")
	if !ok || !sign.ValidPlatformName(osName) || !sign.ValidPlatformName(arch) {
		return Platform{}, false
	}
	return Platform{osName, arch}, true
}

func parseFilePath(name string) (fileKey, bool) {
	if path.Clean(name) != name {
		return fileKey{}, false
	}
	dir, base, ok := strings.Cut(name, "/")
	if !ok || !sign.ValidFileName(base) {
		return fileKey{}, false
	}
	p, ok := parsePlatformDir(dir)
	if !ok {
		return fileKey{}, false
	}
	return fileKey{p.OS, p.Arch, base}, true
}

// ELF e_machine values for the supported architectures.
var elfMachines = map[string]uint16{
	"amd64": 62,  // EM_X86_64
	"arm64": 183, // EM_AARCH64
}

func checkELFMachine(data []byte, arch string) error {
	want, ok := elfMachines[arch]
	if !ok {
		return fmt.Errorf("unsupported architecture %q", arch)
	}
	if len(data) < 20 || !sign.IsELF(data) {
		return errors.New("not an ELF file")
	}
	var machine uint16
	switch data[5] {
	case 1: // ELFDATA2LSB
		machine = uint16(data[18]) | uint16(data[19])<<8
	case 2: // ELFDATA2MSB
		machine = uint16(data[18])<<8 | uint16(data[19])
	default:
		return errors.New("invalid ELF data encoding")
	}
	if machine != want {
		return fmt.Errorf("ELF machine %d does not match architecture %s", machine, arch)
	}
	return nil
}

// PE machine types for the supported architectures.
var peMachines = map[string]uint16{
	"amd64": 0x8664, // IMAGE_FILE_MACHINE_AMD64
	"arm64": 0xaa64, // IMAGE_FILE_MACHINE_ARM64
}

func checkPEMachine(data []byte, arch string) error {
	want, ok := peMachines[arch]
	if !ok {
		return fmt.Errorf("unsupported architecture %q", arch)
	}
	if !sign.IsPE(data) {
		return errors.New("not a PE file")
	}
	off := int(binary.LittleEndian.Uint32(data[0x3c:])) + 4 // COFF header
	if off+2 > len(data) {
		return errors.New("truncated PE header")
	}
	if machine := binary.LittleEndian.Uint16(data[off:]); machine != want {
		return fmt.Errorf("PE machine %#x does not match architecture %s", machine, arch)
	}
	return nil
}

// errBundleTooLarge is returned once more than maxBundleSize bytes were read.
var errBundleTooLarge = errors.New("release: bundle exceeds the size limit")

type limitReader struct {
	r        io.Reader
	n        int64
	exceeded bool
}

func (l *limitReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		l.exceeded = true
		return 0, errBundleTooLarge
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}

func (l *limitReader) wrap(err error) error {
	if l.exceeded {
		return errBundleTooLarge
	}
	return err
}
