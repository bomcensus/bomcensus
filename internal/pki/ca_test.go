// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"
)

func TestNewCA(t *testing.T) {
	nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ca, err := NewCA(CAOptions{
		Subject:   pkix.Name{CommonName: "bomcensus Agent CA", Organization: []string{"JC-Lab"}},
		NotBefore: nb,
		Lifetime:  5 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	c := ca.Cert
	if !c.IsCA || !c.BasicConstraintsValid || c.MaxPathLen != 0 || !c.MaxPathLenZero {
		t.Fatal("not an intermediate-less CA")
	}
	if c.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("missing certSign")
	}
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		t.Fatal("CA key is not P-256")
	}
	if c.Subject.CommonName != "bomcensus Agent CA" || !c.NotBefore.Equal(nb) || !c.NotAfter.Equal(nb.Add(5*365*24*time.Hour)) {
		t.Fatalf("subject/validity: %s %s %s", c.Subject, c.NotBefore, c.NotAfter)
	}
	if err := c.CheckSignatureFrom(c); err != nil {
		t.Fatalf("not self-signed: %v", err)
	}
	if len(c.SubjectKeyId) == 0 {
		t.Fatal("missing subject key id")
	}
	if _, err := LoadCA(c, ca.Key); err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if _, err := LoadCA(c, newKey(t)); err == nil {
		t.Fatal("LoadCA accepted a foreign key")
	}
	leaf, err := ca.IssueServer(newKey(t).Public(), LeafOptions{DNSNames: []string{"x"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCA(leaf, ca.Key); err == nil {
		t.Fatal("LoadCA accepted a leaf")
	}
	if _, err := NewCA(CAOptions{Lifetime: -time.Hour}); err == nil {
		t.Fatal("negative lifetime accepted")
	}
}

func TestIssueLeaf(t *testing.T) {
	ca, err := NewCA(CAOptions{Subject: pkix.Name{CommonName: "short"}, Lifetime: 48 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	key := newKey(t)
	srv, err := ca.IssueServer(key.Public(), LeafOptions{DNSNames: []string{"a.example.test", "b.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if srv.IsCA || srv.Subject.CommonName != "a.example.test" {
		t.Fatalf("leaf: IsCA=%v CN=%q", srv.IsCA, srv.Subject.CommonName)
	}
	if len(srv.ExtKeyUsage) != 1 || srv.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("EKU = %v", srv.ExtKeyUsage)
	}
	if !srv.NotAfter.Equal(ca.Cert.NotAfter) {
		t.Fatalf("leaf outlives CA: %s > %s", srv.NotAfter, ca.Cert.NotAfter)
	}
	if string(srv.AuthorityKeyId) != string(ca.Cert.SubjectKeyId) {
		t.Fatal("authority key id not set")
	}
	cli, err := ca.IssueClient(key.Public(), LeafOptions{DNSNames: []string{"a.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(cli.ExtKeyUsage) != 1 || cli.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("client EKU = %v", cli.ExtKeyUsage)
	}
	if srv.SerialNumber.Cmp(cli.SerialNumber) == 0 {
		t.Fatal("serial numbers repeat")
	}
	if _, err := ca.IssueServer(key.Public(), LeafOptions{}); err == nil {
		t.Fatal("certificate without SAN accepted")
	}
	if _, err := ca.IssueServer(key.Public(), LeafOptions{DNSNames: []string{"x"}, NotBefore: ca.Cert.NotAfter.Add(time.Hour)}); err == nil {
		t.Fatal("certificate outside CA validity accepted")
	}
}

func TestNewSerial(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		s, err := NewSerial()
		if err != nil {
			t.Fatal(err)
		}
		if s.Sign() <= 0 || s.BitLen() > 128 {
			t.Fatalf("serial out of range: %v", s)
		}
		if seen[s.String()] {
			t.Fatal("duplicate serial")
		}
		seen[s.String()] = true
	}
}
