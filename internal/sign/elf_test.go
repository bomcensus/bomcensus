// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package sign_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"runtime"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/sign"
	"github.com/bomcensus/bomcensus/internal/sign/signtest"
)

func TestELFRoundTrip(t *testing.T) {
	tr := signtest.Install(t)
	orig := signtest.ELF(t, runtime.GOARCH)
	signed := tr.SignELF(t, orig)
	if err := sign.VerifyELF(signed); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(orig, signed) {
		t.Fatal("signing did not change the file")
	}
	// Re-signing replaces the signature and still verifies.
	if err := sign.VerifyELF(tr.SignELF(t, signed)); err != nil {
		t.Fatal(err)
	}
}

func TestELFRejects(t *testing.T) {
	tr := signtest.Install(t)
	orig := signtest.ELF(t, runtime.GOARCH)
	signed := tr.SignELF(t, orig)

	t.Run("unsigned", func(t *testing.T) {
		if err := sign.VerifyELF(orig); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("not ELF", func(t *testing.T) {
		if err := sign.VerifyELF([]byte("#!/bin/sh\n")); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("flipped byte", func(t *testing.T) {
		bad := bytes.Clone(signed)
		bad[len(orig)/2] ^= 0xff
		if err := sign.VerifyELF(bad); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("appended data", func(t *testing.T) {
		if err := sign.VerifyELF(append(bytes.Clone(signed), 0)); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("other root", func(t *testing.T) {
		other := signtest.NewTrust(t)
		if err := sign.VerifyELF(other.SignELF(t, orig)); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("no roots compiled in", func(t *testing.T) {
		signtest.SetTrust(t, tr.ReleaseKeys(), "")
		if err := sign.VerifyELF(signed); !errors.Is(err, sign.ErrNoCodeSigningRoots) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("expired signer without timestamp", func(t *testing.T) {
		now := time.Now()
		cert, key, err := sign.NewCodeSigningCert(tr.RootCert, tr.RootKey, "expired", now.Add(-2*time.Hour), now.Add(-time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if err := sign.VerifyELF(signWith(t, orig, key, cert)); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("signer without code-signing usage", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(42),
			Subject:      pkix.Name{CommonName: "no eku"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tr.RootCert, key.Public(), tr.RootKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if err := sign.VerifyELF(signWith(t, orig, key, cert)); err == nil {
			t.Fatal("accepted")
		}
	})
}

func signWith(t *testing.T, data []byte, key *ecdsa.PrivateKey, cert *x509.Certificate) []byte {
	t.Helper()
	out, err := sign.SignELF(context.Background(), data, &sign.ELFSigner{Key: key, Certificate: cert})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
