// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestCertificatesPEM(t *testing.T) {
	c := newTestChain(t, chainOpts{})
	data := EncodeCertificatesPEM(c.certs()...)
	got, err := ParseCertificatesPEM(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || !got[0].Equal(c.leaf) || !got[2].Equal(c.root) {
		t.Fatal("round trip changed the chain")
	}
	// Comments as written by openssl are tolerated.
	commented := append([]byte("subject=CN = leaf\nissuer=CN = inter\n"), data...)
	if got, err := ParseCertificatesPEM(commented); err != nil || len(got) != 3 {
		t.Fatalf("commented chain: %d, %v", len(got), err)
	}

	truncated := data[:len(data)-30]
	keyPEM, _ := EncodePrivateKeyPEM(c.leafKey)
	bad := map[string][]byte{
		"empty":     nil,
		"no PEM":    []byte("hello"),
		"truncated": truncated,
		"key block": append(append([]byte(nil), data...), keyPEM...),
		"bad DER":   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0x00}}),
	}
	for name, in := range bad {
		if _, err := ParseCertificatesPEM(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPrivateKeyPEM(t *testing.T) {
	ec := newKey(t)
	ed, err := GenerateAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []crypto.Signer{ec, ed, rk} {
		data, err := EncodePrivateKeyPEM(k)
		if err != nil {
			t.Fatal(err)
		}
		if blk, _ := pem.Decode(data); blk == nil || blk.Type != "PRIVATE KEY" {
			t.Fatal("not PKCS#8")
		}
		back, err := ParsePrivateKeyPEM(data)
		if err != nil {
			t.Fatal(err)
		}
		if !back.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(k.Public()) {
			t.Fatalf("%T round trip", k)
		}
	}

	sec1, err := x509.MarshalECPrivateKey(ec.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	ecParams := pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}})
	sec1PEM := append(ecParams, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})...)
	if k, err := ParsePrivateKeyPEM(sec1PEM); err != nil || !k.Public().(*ecdsa.PublicKey).Equal(ec.Public()) {
		t.Fatalf("SEC 1: %v", err)
	}
	pkcs1PEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rk)})
	if k, err := ParsePrivateKeyPEM(pkcs1PEM); err != nil || !k.Public().(*rsa.PublicKey).Equal(rk.Public()) {
		t.Fatalf("PKCS#1: %v", err)
	}

	ecPEM, _ := EncodePrivateKeyPEM(ec)
	bad := map[string][]byte{
		"empty":       nil,
		"certificate": EncodeCertificatesPEM(newTestCA(t).Cert),
		"two keys":    append(append([]byte(nil), ecPEM...), ecPEM...),
		"encrypted": pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Headers: map[string]string{
			"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,00000000000000000000000000000000",
		}, Bytes: []byte{1, 2, 3}}),
		"bad DER":   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{0x30, 0x00}}),
		"truncated": ecPEM[:len(ecPEM)-20],
	}
	for name, in := range bad {
		if _, err := ParsePrivateKeyPEM(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTemporaryCertificate(t *testing.T) {
	tc, err := NewTemporaryCertificate()
	if err != nil {
		t.Fatal(err)
	}
	if tc.Leaf == nil || len(tc.Certificate) != 1 {
		t.Fatal("missing leaf")
	}
	if err := tc.Leaf.CheckSignatureFrom(tc.Leaf); err == nil {
		t.Fatal("temporary certificate must not be a CA")
	}
	if err := tc.Leaf.CheckSignature(tc.Leaf.SignatureAlgorithm, tc.Leaf.RawTBSCertificate, tc.Leaf.Signature); err != nil {
		t.Fatalf("not self-signed: %v", err)
	}
	if !KeyMatches(tc.Leaf, tc.PrivateKey.(crypto.Signer)) {
		t.Fatal("key does not match")
	}
	other, err := NewTemporaryCertificate()
	if err != nil {
		t.Fatal(err)
	}
	if SPKIHash(other.Leaf) == SPKIHash(tc.Leaf) {
		t.Fatal("temporary keys repeat")
	}
}
