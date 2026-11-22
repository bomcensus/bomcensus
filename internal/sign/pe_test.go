// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package sign_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/sign"
	"github.com/bomcensus/bomcensus/internal/sign/signtest"
)

func TestPERoundTrip(t *testing.T) {
	tr := signtest.Install(t)
	for _, arch := range []string{"amd64", "arm64"} {
		orig := signtest.PE(t, arch)
		if !sign.IsPE(orig) || sign.IsELF(orig) {
			t.Fatal("fixture is not a PE file")
		}
		signed := tr.SignPE(t, orig)
		if err := sign.VerifyPE(signed); err != nil {
			t.Fatalf("%s: %v", arch, err)
		}
		// Only the checksum and the certificate directory entry change.
		diff := 0
		for i := range orig {
			if orig[i] != signed[i] {
				diff++
			}
		}
		if diff > 12 {
			t.Fatalf("%d bytes of the image changed", diff)
		}
		// Re-signing replaces the signature and still verifies.
		again := tr.SignPE(t, signed)
		if err := sign.VerifyPE(again); err != nil {
			t.Fatal(err)
		}
		dir := certDirOffset(t, signed)
		if !bytes.Equal(again[dir:dir+4], signed[dir:dir+4]) {
			t.Fatal("re-signing moved the certificate table")
		}
	}
}

func TestPEUnalignedInput(t *testing.T) {
	tr := signtest.Install(t)
	orig := append(signtest.PE(t, "amd64"), 1, 2, 3) // overlay data, not 8-aligned
	signed := tr.SignPE(t, orig)
	if err := sign.VerifyPE(signed); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signed[1024:1027], []byte{1, 2, 3}) {
		t.Fatal("overlay data lost")
	}
}

func TestPERSASigner(t *testing.T) {
	tr := signtest.Install(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := issue(t, tr, key.Public(), time.Now().Add(-time.Hour), time.Now().Add(time.Hour), true)
	if err := sign.VerifyPE(signPEWith(t, signtest.PE(t, "amd64"), key, cert)); err != nil {
		t.Fatal(err)
	}
}

func TestPERejects(t *testing.T) {
	tr := signtest.Install(t)
	orig := signtest.PE(t, "amd64")
	signed := tr.SignPE(t, orig)
	certDir := certDirOffset(t, signed)

	cases := map[string][]byte{
		"unsigned":         orig,
		"not PE":           []byte("#!/bin/sh\n"),
		"ELF":              append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 100)...),
		"flipped code":     flip(signed, 0x200),
		"flipped header":   flip(signed, 0x50),
		"flipped sig data": flip(signed, len(signed)-200),
		"appended data":    append(bytes.Clone(signed), make([]byte, 8)...),
		"truncated":        signed[:len(signed)-8],
	}
	// Certificate table moved into the section data.
	moved := bytes.Clone(signed)
	binary.LittleEndian.PutUint32(moved[certDir:], 0x200)
	cases["table overlaps image"] = moved
	// Two entries in the table: the second one is not covered by anything.
	two := bytes.Clone(signed)
	size := binary.LittleEndian.Uint32(two[certDir+4:])
	off := binary.LittleEndian.Uint32(two[certDir:])
	two = append(two, two[off:off+size]...)
	binary.LittleEndian.PutUint32(two[certDir+4:], 2*size)
	cases["two entries"] = two
	// Wrong certificate type.
	typ := bytes.Clone(signed)
	typ[off+6] = 1
	cases["X509 entry type"] = typ

	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			err := sign.VerifyPE(data)
			if err == nil {
				t.Fatal("accepted")
			}
			t.Log(err)
		})
	}
	t.Run("checksum is not covered", func(t *testing.T) {
		// The checksum is excluded from the image hash by design.
		cs := bytes.Clone(signed)
		cs[certDir-112-32+64]++ // CheckSum of the PE32+ optional header
		if err := sign.VerifyPE(cs); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("other root", func(t *testing.T) {
		other := signtest.NewTrust(t)
		if err := sign.VerifyPE(other.SignPE(t, orig)); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("no roots compiled in", func(t *testing.T) {
		signtest.SetTrust(t, tr.ReleaseKeys(), "")
		if err := sign.VerifyPE(signed); !errors.Is(err, sign.ErrNoCodeSigningRoots) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("expired signer without timestamp", func(t *testing.T) {
		now := time.Now()
		cert, key, err := sign.NewCodeSigningCert(tr.RootCert, tr.RootKey, "expired", now.Add(-2*time.Hour), now.Add(-time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if err := sign.VerifyPE(signPEWith(t, orig, key, cert)); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("signer without code-signing usage", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert := issue(t, tr, key.Public(), time.Now().Add(-time.Hour), time.Now().Add(time.Hour), false)
		if err := sign.VerifyPE(signPEWith(t, orig, key, cert)); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("key does not match certificate", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if _, err := sign.SignPE(context.Background(), orig, &sign.CodeSigner{Key: key, Certificate: tr.CodeCert}); err == nil {
			t.Fatal("signed")
		}
	})
}

// TestPEOsslsigncode cross-checks SignPE with osslsigncode: osslsigncode
// must accept the signature, and VerifyPE must verify a signature nested by
// osslsigncode and reject one under an untrusted root.
func TestPEOsslsigncode(t *testing.T) {
	tool, err := exec.LookPath("osslsigncode")
	if err != nil {
		t.Skip("osslsigncode not installed")
	}
	tr := signtest.Install(t)
	dir := t.TempDir()
	ca := writePEM(t, dir, "ca.crt", "CERTIFICATE", tr.RootCert.Raw)
	for _, arch := range []string{"amd64", "arm64"} {
		signed := filepath.Join(dir, arch+".exe")
		if err := os.WriteFile(signed, tr.SignPE(t, signtest.PE(t, arch)), 0o644); err != nil {
			t.Fatal(err)
		}
		run(t, tool, "verify", "-in", signed, "-CAfile", ca)
	}

	// Nest a second signature with osslsigncode.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := issue(t, tr, rsaKey.Public(), time.Now().Add(-time.Hour), time.Now().Add(time.Hour), true)
	keyDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := writePEM(t, dir, "nested.key", "PRIVATE KEY", keyDER)
	certFile := writePEM(t, dir, "nested.crt", "CERTIFICATE", cert.Raw)
	in := filepath.Join(dir, "amd64.exe")
	out := filepath.Join(dir, "nested.exe")
	run(t, tool, "sign", "-nest", "-h", "sha256", "-certs", certFile, "-key", keyFile, "-in", in, "-out", out)
	run(t, tool, "verify", "-in", out, "-CAfile", ca)
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := sign.VerifyPE(data); err != nil {
		t.Fatalf("nested signature: %v", err)
	}

	// A nested signature that does not verify fails the file.
	other := signtest.NewTrust(t)
	otherKey, _ := x509.MarshalPKCS8PrivateKey(other.CodeKey)
	keyFile = writePEM(t, dir, "other.key", "PRIVATE KEY", otherKey)
	certFile = writePEM(t, dir, "other.crt", "CERTIFICATE", other.CodeCert.Raw)
	out = filepath.Join(dir, "nested-other.exe")
	run(t, tool, "sign", "-nest", "-h", "sha256", "-certs", certFile, "-key", keyFile, "-in", in, "-out", out)
	if data, err = os.ReadFile(out); err != nil {
		t.Fatal(err)
	}
	if err := sign.VerifyPE(data); err == nil || !strings.Contains(err.Error(), "#1") {
		t.Fatalf("untrusted nested signature: got %v", err)
	}
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

func writePEM(t *testing.T, dir, name, typ string, der []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func flip(b []byte, i int) []byte {
	b = bytes.Clone(b)
	b[i] ^= 0xff
	return b
}

// certDirOffset returns the offset of the certificate table directory entry
// of a PE32+ file.
func certDirOffset(t *testing.T, b []byte) int {
	t.Helper()
	pe := int(binary.LittleEndian.Uint32(b[0x3c:]))
	if binary.LittleEndian.Uint16(b[pe+24:]) != 0x20b {
		t.Fatal("not PE32+")
	}
	return pe + 24 + 112 + 4*8
}

func issue(t *testing.T, tr *signtest.Trust, pub crypto.PublicKey, notBefore, notAfter time.Time, codeSigning bool) *x509.Certificate {
	t.Helper()
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test signer"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if codeSigning {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tr.RootCert, pub, tr.RootKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func signPEWith(t *testing.T, data []byte, key crypto.Signer, cert *x509.Certificate) []byte {
	t.Helper()
	out, err := sign.SignPE(context.Background(), data, &sign.CodeSigner{Key: key, Certificate: cert})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
