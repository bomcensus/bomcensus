// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package sign

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"
)

const (
	// MaxManifestSize bounds the encoded manifest.
	MaxManifestSize = 1 << 20
	// MaxManifestFiles bounds the number of files in a manifest.
	MaxManifestFiles = 256
	// MaxClockSkew is how far IssuedAt may lie in the future of the
	// verifier's clock.
	MaxClockSkew = 10 * time.Minute
)

// ErrManifestSignature means no compiled-in key verifies the manifest.
var ErrManifestSignature = errors.New("sign: manifest signature does not verify")

// ErrManifestExpired means the manifest is past its expiry time.
var ErrManifestExpired = errors.New("sign: manifest expired")

// ErrManifestNotYetValid means the manifest was issued in the future.
var ErrManifestNotYetValid = errors.New("sign: manifest not yet valid")

// Manifest describes one release. Its exact encoded bytes are signed with a
// detached Ed25519 signature.
type Manifest struct {
	Version   string    `json:"version"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Files     []File    `json:"files"`
}

// File is one file of a release.
type File struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	Name   string `json:"name"`
	SHA256 string `json:"sha256"` // lowercase hex
	Size   int64  `json:"size"`
}

var (
	platformRe = regexp.MustCompile(`^[a-z0-9]{1,16}$`)
	fileNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	sha256Re   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidPlatformName reports whether s is acceptable as an os or arch value.
func ValidPlatformName(s string) bool { return platformRe.MatchString(s) }

// ValidFileName reports whether s is acceptable as a release file name.
func ValidFileName(s string) bool { return fileNameRe.MatchString(s) }

// Validate checks that the manifest is well formed. It does not check the
// signature or the validity period against a clock.
func (m *Manifest) Validate() error {
	if !ValidVersion(m.Version) {
		return fmt.Errorf("sign: manifest: invalid version %q", m.Version)
	}
	if m.IssuedAt.IsZero() || m.ExpiresAt.IsZero() {
		return errors.New("sign: manifest: issued_at and expires_at are required")
	}
	if !m.ExpiresAt.After(m.IssuedAt) {
		return errors.New("sign: manifest: expires_at is not after issued_at")
	}
	if len(m.Files) == 0 {
		return errors.New("sign: manifest: no files")
	}
	if len(m.Files) > MaxManifestFiles {
		return fmt.Errorf("sign: manifest: %d files, maximum is %d", len(m.Files), MaxManifestFiles)
	}
	seen := make(map[[3]string]bool, len(m.Files))
	for i, f := range m.Files {
		if !ValidPlatformName(f.OS) || !ValidPlatformName(f.Arch) {
			return fmt.Errorf("sign: manifest: file %d: invalid os/arch %q/%q", i, f.OS, f.Arch)
		}
		if !ValidFileName(f.Name) {
			return fmt.Errorf("sign: manifest: file %d: invalid name %q", i, f.Name)
		}
		if !sha256Re.MatchString(f.SHA256) {
			return fmt.Errorf("sign: manifest: file %s: invalid sha256", f.Name)
		}
		if f.Size <= 0 {
			return fmt.Errorf("sign: manifest: file %s: invalid size %d", f.Name, f.Size)
		}
		k := [3]string{f.OS, f.Arch, f.Name}
		if seen[k] {
			return fmt.Errorf("sign: manifest: duplicate file %s/%s/%s", f.OS, f.Arch, f.Name)
		}
		seen[k] = true
	}
	return nil
}

// Lookup returns the entry for one file.
func (m *Manifest) Lookup(os, arch, name string) (File, bool) {
	for _, f := range m.Files {
		if f.OS == os && f.Arch == arch && f.Name == name {
			return f, true
		}
	}
	return File{}, false
}

// FilesFor returns the entries of one os/arch in manifest order.
func (m *Manifest) FilesFor(os, arch string) []File {
	var out []File
	for _, f := range m.Files {
		if f.OS == os && f.Arch == arch {
			out = append(out, f)
		}
	}
	return out
}

// Digest returns the decoded SHA-256 of the file.
func (f File) Digest() ([32]byte, error) {
	var d [32]byte
	b, err := hex.DecodeString(f.SHA256)
	if err != nil || len(b) != len(d) {
		return d, fmt.Errorf("sign: file %s: invalid sha256", f.Name)
	}
	copy(d[:], b)
	return d, nil
}

// EncodeManifest validates m and returns the bytes to sign and ship.
func EncodeManifest(m *Manifest) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	c := *m
	c.IssuedAt = c.IssuedAt.UTC().Truncate(time.Second)
	c.ExpiresAt = c.ExpiresAt.UTC().Truncate(time.Second)
	b, err := json.MarshalIndent(&c, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("sign: encode manifest: %w", err)
	}
	b = append(b, '\n')
	if len(b) > MaxManifestSize {
		return nil, fmt.Errorf("sign: manifest is %d bytes, maximum is %d", len(b), MaxManifestSize)
	}
	return b, nil
}

// SignManifest returns the detached signature of the encoded manifest.
func SignManifest(key ed25519.PrivateKey, manifest []byte) []byte {
	return ed25519.Sign(key, manifest)
}

// ParseUnverifiedManifest decodes and validates a manifest without checking
// its signature or validity period. Only the release tooling should use it;
// everything that acts on a release must use VerifyManifest.
func ParseUnverifiedManifest(manifest []byte) (*Manifest, error) {
	if len(manifest) > MaxManifestSize {
		return nil, fmt.Errorf("sign: manifest is %d bytes, maximum is %d", len(manifest), MaxManifestSize)
	}
	dec := json.NewDecoder(bytes.NewReader(manifest))
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("sign: decode manifest: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("sign: decode manifest: trailing data")
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// VerifyManifest checks the detached signature against the compiled-in
// release keys, decodes and validates the manifest and checks that now lies
// within its validity period (IssuedAt may be up to MaxClockSkew ahead).
func VerifyManifest(manifest, sig []byte, now time.Time) (*Manifest, error) {
	keys, err := ReleaseKeys()
	if err != nil {
		return nil, err
	}
	return verifyManifest(keys, manifest, sig, now)
}

func verifyManifest(keys []ed25519.PublicKey, manifest, sig []byte, now time.Time) (*Manifest, error) {
	if len(manifest) > MaxManifestSize {
		return nil, fmt.Errorf("sign: manifest is %d bytes, maximum is %d", len(manifest), MaxManifestSize)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, ErrManifestSignature
	}
	ok := false
	for _, k := range keys {
		if ed25519.Verify(k, manifest, sig) {
			ok = true
			break
		}
	}
	if !ok {
		return nil, ErrManifestSignature
	}
	m, err := ParseUnverifiedManifest(manifest)
	if err != nil {
		return nil, err
	}
	if now.After(m.ExpiresAt) {
		return nil, fmt.Errorf("%w at %s", ErrManifestExpired, m.ExpiresAt.Format(time.RFC3339))
	}
	if m.IssuedAt.After(now.Add(MaxClockSkew)) {
		return nil, fmt.Errorf("%w until %s", ErrManifestNotYetValid, m.IssuedAt.Format(time.RFC3339))
	}
	return m, nil
}
