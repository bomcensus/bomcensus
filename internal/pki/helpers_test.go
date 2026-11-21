// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// testChain is root -> intermediate -> leaf, built by hand because CA does
// not issue intermediates.
type testChain struct {
	root, inter, leaf          *x509.Certificate
	rootKey, interKey, leafKey crypto.Signer
}

func (c testChain) certs() []*x509.Certificate {
	return []*x509.Certificate{c.leaf, c.inter, c.root}
}

type chainOpts struct {
	leafNotBefore, leafNotAfter   time.Time
	interNotBefore, interNotAfter time.Time
	leafUsage                     []x509.ExtKeyUsage
	dnsNames                      []string
}

func newKey(t *testing.T) crypto.Signer {
	t.Helper()
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustSerial(t *testing.T) *big.Int {
	t.Helper()
	s, err := NewSerial()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func sign(t *testing.T, tmpl, parent *x509.Certificate, pub crypto.PublicKey, parentKey crypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl.SerialNumber = mustSerial(t)
	tmpl.BasicConstraintsValid = true
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newTestChain(t *testing.T, o chainOpts) testChain {
	t.Helper()
	now := time.Now()
	def := func(v, d time.Time) time.Time {
		if v.IsZero() {
			return d
		}
		return v
	}
	if o.leafUsage == nil {
		o.leafUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	if o.dnsNames == nil {
		o.dnsNames = []string{"agents.example.test"}
	}
	var c testChain
	c.rootKey, c.interKey, c.leafKey = newKey(t), newKey(t), newKey(t)
	c.root = sign(t, &x509.Certificate{
		Subject:   pkix.Name{CommonName: "Test Root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true,
	}, nil, c.rootKey.Public(), c.rootKey)
	c.inter = sign(t, &x509.Certificate{
		Subject:   pkix.Name{CommonName: "Test Intermediate"},
		NotBefore: def(o.interNotBefore, now.Add(-time.Hour)), NotAfter: def(o.interNotAfter, now.Add(5*365*24*time.Hour)),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true,
	}, c.root, c.interKey.Public(), c.rootKey)
	c.leaf = sign(t, &x509.Certificate{
		Subject:   pkix.Name{CommonName: o.dnsNames[0]},
		DNSNames:  o.dnsNames,
		NotBefore: def(o.leafNotBefore, now.Add(-time.Hour)), NotAfter: def(o.leafNotAfter, now.Add(24*time.Hour)),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: o.leafUsage,
	}, c.inter, c.leafKey.Public(), c.interKey)
	return c
}

func newTestCA(t *testing.T) *CA {
	t.Helper()
	ca, err := NewCA(CAOptions{Subject: pkix.Name{CommonName: "Test CA"}})
	if err != nil {
		t.Fatal(err)
	}
	return ca
}
