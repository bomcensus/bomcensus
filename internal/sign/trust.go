// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package sign verifies bomcensus releases: the signed release manifest and
// the code signatures of the executables (AuthentiELF for ELF files,
// Authenticode for PE files).
//
// The trust anchors are compiled into the binaries with
//
//	-X github.com/bomcensus/bomcensus/internal/sign.releaseKeys=<keys>
//	-X github.com/bomcensus/bomcensus/internal/sign.codeSigningRoots=<roots>
//
// releaseKeys is a comma-separated list of standard base64 encoded raw
// Ed25519 public keys (normally the current and the next key).
// codeSigningRoots is the standard base64 encoding of one or more PEM
// CERTIFICATE blocks. When a value is empty every verification that needs it
// fails.
package sign

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/bomcensus/bomcensus/internal/sign/internal/testhook"
)

// Set at link time. They must stay plain string variables for -X to work.
var (
	releaseKeys      string
	codeSigningRoots string
)

// ErrNoReleaseKeys means the binary was built without release manifest keys.
var ErrNoReleaseKeys = errors.New("sign: no release manifest keys compiled in")

// ErrNoCodeSigningRoots means the binary was built without code-signing roots.
var ErrNoCodeSigningRoots = errors.New("sign: no code-signing roots compiled in")

type trustValues struct {
	releaseKeys      string
	codeSigningRoots string
}

// override replaces the link-time values in tests (see package signtest).
var override atomic.Pointer[trustValues]

func init() {
	testhook.SetTrust = func(keys, roots string) func() {
		prev := override.Swap(&trustValues{releaseKeys: keys, codeSigningRoots: roots})
		return func() { override.Store(prev) }
	}
}

func currentTrust() trustValues {
	if v := override.Load(); v != nil {
		return *v
	}
	return trustValues{releaseKeys: releaseKeys, codeSigningRoots: codeSigningRoots}
}

// ReleaseKeys returns the compiled-in Ed25519 release manifest keys.
func ReleaseKeys() ([]ed25519.PublicKey, error) {
	return ParseReleaseKeys(currentTrust().releaseKeys)
}

// CodeSigningRoots returns the compiled-in code-signing root certificates.
func CodeSigningRoots() (*x509.CertPool, error) {
	certs, err := ParseCodeSigningRoots(currentTrust().codeSigningRoots)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool, nil
}

// ParseReleaseKeys decodes a releaseKeys value.
func ParseReleaseKeys(s string) ([]ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, ErrNoReleaseKeys
	}
	var keys []ed25519.PublicKey
	for i, part := range strings.Split(s, ",") {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(part))
		if err != nil {
			return nil, fmt.Errorf("sign: release key %d: %w", i, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("sign: release key %d: length %d, want %d", i, len(raw), ed25519.PublicKeySize)
		}
		keys = append(keys, ed25519.PublicKey(raw))
	}
	return keys, nil
}

// EncodeReleaseKeys produces a releaseKeys value.
func EncodeReleaseKeys(keys ...ed25519.PublicKey) string {
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = base64.StdEncoding.EncodeToString(k)
	}
	return strings.Join(parts, ",")
}

// ParseCodeSigningRoots decodes a codeSigningRoots value.
func ParseCodeSigningRoots(s string) ([]*x509.Certificate, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, ErrNoCodeSigningRoots
	}
	rest, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("sign: code-signing roots: %w", err)
	}
	var certs []*x509.Certificate
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("sign: code-signing roots: unexpected PEM block %q", b.Type)
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("sign: code-signing roots: %w", err)
		}
		certs = append(certs, c)
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("sign: code-signing roots: trailing data after PEM blocks")
	}
	if len(certs) == 0 {
		return nil, errors.New("sign: code-signing roots: no certificates")
	}
	return certs, nil
}

// EncodeCodeSigningRoots produces a codeSigningRoots value.
func EncodeCodeSigningRoots(certs ...*x509.Certificate) string {
	var b strings.Builder
	for _, c := range certs {
		b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	return base64.StdEncoding.EncodeToString([]byte(b.String()))
}
