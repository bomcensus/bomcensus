// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package signtest provides throwaway release trust for tests. Its functions
// take a testing.TB and replace the trust that package sign normally takes
// from link-time values, so they are not usable from production code.
//
// The replacement is process-wide: tests that install different trust must
// not run in parallel.
package signtest

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/sign"
	"github.com/bomcensus/bomcensus/internal/sign/internal/testhook"
)

// SetTrust installs raw releaseKeys and codeSigningRoots values for the
// duration of the test.
func SetTrust(t testing.TB, releaseKeys, codeSigningRoots string) {
	t.Helper()
	restore := testhook.SetTrust(releaseKeys, codeSigningRoots)
	t.Cleanup(restore)
}

// Trust is a generated set of release keys.
type Trust struct {
	ManifestKey ed25519.PrivateKey
	RootCert    *x509.Certificate
	RootKey     *ecdsa.PrivateKey
	CodeCert    *x509.Certificate
	CodeKey     *ecdsa.PrivateKey
}

// NewTrust generates a manifest key, a code-signing root and a leaf without
// installing them.
func NewTrust(t testing.TB) *Trust {
	t.Helper()
	_, mk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root, rootKey, err := sign.NewCodeSigningCA("test code signing root", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	leaf, leafKey, err := sign.NewCodeSigningCert(root, rootKey, "test code signer", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return &Trust{ManifestKey: mk, RootCert: root, RootKey: rootKey, CodeCert: leaf, CodeKey: leafKey}
}

// Install generates trust and installs it for the duration of the test.
func Install(t testing.TB) *Trust {
	t.Helper()
	tr := NewTrust(t)
	tr.Install(t)
	return tr
}

// ReleaseKeys returns the releaseKeys value for this trust.
func (tr *Trust) ReleaseKeys() string {
	return sign.EncodeReleaseKeys(tr.ManifestKey.Public().(ed25519.PublicKey))
}

// CodeSigningRoots returns the codeSigningRoots value for this trust.
func (tr *Trust) CodeSigningRoots() string {
	return sign.EncodeCodeSigningRoots(tr.RootCert)
}

// Install makes this trust the compiled-in trust for the duration of the test.
func (tr *Trust) Install(t testing.TB) {
	t.Helper()
	SetTrust(t, tr.ReleaseKeys(), tr.CodeSigningRoots())
}

// SignManifest encodes and signs m.
func (tr *Trust) SignManifest(t testing.TB, m *sign.Manifest) (manifest, sig []byte) {
	t.Helper()
	b, err := sign.EncodeManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	return b, sign.SignManifest(tr.ManifestKey, b)
}

// SignELF returns data signed with the leaf certificate.
func (tr *Trust) SignELF(t testing.TB, data []byte) []byte {
	t.Helper()
	out, err := sign.SignELF(context.Background(), data, &sign.ELFSigner{Key: tr.CodeKey, Certificate: tr.CodeCert})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// FileEntry returns the manifest entry for data.
func FileEntry(goos, arch, name string, data []byte) sign.File {
	d := sha256.Sum256(data)
	return sign.File{OS: goos, Arch: arch, Name: name, SHA256: hex.EncodeToString(d[:]), Size: int64(len(data))}
}

var (
	elfMu    sync.Mutex
	elfCache = map[string][]byte{}
)

// ELF returns a small static linux/<goarch> Go executable, built once per
// process with the Go toolchain. The test is skipped when no toolchain is
// available. Callers get their own copy.
func ELF(t testing.TB, goarch string) []byte {
	t.Helper()
	elfMu.Lock()
	defer elfMu.Unlock()
	if b, ok := elfCache[goarch]; ok {
		return append([]byte(nil), b...)
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not available")
	}
	dir, err := os.MkdirTemp("", "signtest-elf-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	files := map[string]string{
		"go.mod":  "module elftest\n\ngo 1.21\n",
		"main.go": "package main\n\nfunc main() { println(\"elftest\") }\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(dir, "elftest")
	cmd := exec.Command(goBin, "build", "-trimpath", "-ldflags=-s -w", "-o", out, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0", "GOFLAGS=", "GOTOOLCHAIN=local", "GOWORK=off")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatal(fmt.Errorf("build test ELF: %w\n%s", err, b))
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	elfCache[goarch] = b
	return append([]byte(nil), b...)
}
