// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAgentCertificateRoundTrip(t *testing.T) {
	ca := newTestCA(t)
	key, err := GenerateAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := CreateAgentCSR(key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ParseAgentCSR(der)
	if err != nil {
		t.Fatal(err)
	}
	const id = "01J9Z8Q4N6T3W5X7Y2A0B1C3D4"
	cert, err := ca.IssueAgent(csr, id, AgentOptions{Lifetime: 90 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if !cert.PublicKey.(ed25519.PublicKey).Equal(key.Public()) {
		t.Fatal("certificate key differs from CSR key")
	}
	if got := cert.URIs[0].String(); got != "bomcensus://agent/"+id {
		t.Fatalf("URI = %q", got)
	}
	got, err := AgentIDFromCert(cert)
	if err != nil || got != id {
		t.Fatalf("AgentIDFromCert = %q, %v", got, err)
	}
	for _, u := range []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth} {
		got, err := VerifyAgent([]*x509.Certificate{cert}, ca.Cert, u)
		if err != nil || got != id {
			t.Fatalf("VerifyAgent(%v) = %q, %v", u, got, err)
		}
	}
	if _, err := VerifyAgent([]*x509.Certificate{cert}, newTestCA(t).Cert, x509.ExtKeyUsageClientAuth); err == nil {
		t.Fatal("agent certificate accepted by a foreign CA")
	}
	if cert.NotAfter.Sub(cert.NotBefore) != 90*24*time.Hour {
		t.Fatalf("lifetime = %v", cert.NotAfter.Sub(cert.NotBefore))
	}
}

func TestParseAgentCSR(t *testing.T) {
	key, err := GenerateAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	good, err := CreateAgentCSR(key)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), good...)
	tampered[len(tampered)-1] ^= 0xff

	cases := []struct {
		name string
		der  []byte
		ok   bool
	}{
		{"ed25519", good, true},
		{"ecdsa key", ecdsaCSR, false},
		{"bad signature", tampered, false},
		{"empty", nil, false},
		{"garbage", []byte{0x30, 0x03, 0x01, 0x01, 0x00}, false},
		{"too large", make([]byte, MaxCSRSize+1), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseAgentCSR(tc.der)
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestIssueAgentRejects(t *testing.T) {
	ca := newTestCA(t)
	key, _ := GenerateAgentKey()
	der, _ := CreateAgentCSR(key)
	csr, err := ParseAgentCSR(der)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", "a/b", "a b", "agent?x", strings.Repeat("a", MaxAgentIDLen+1), "é"} {
		if _, err := ca.IssueAgent(csr, id, AgentOptions{}); err == nil {
			t.Errorf("IssueAgent accepted id %q", id)
		}
	}
	if _, err := ca.IssueAgent(nil, "a1", AgentOptions{}); err == nil {
		t.Error("IssueAgent accepted nil CSR")
	}
}

func TestAgentIDFromCertRejects(t *testing.T) {
	ca := newTestCA(t)
	agentKey, _ := GenerateAgentKey()
	agentPub := agentKey.Public()
	agentURI := AgentURI("a1")
	mk := func(cn string, uris []*url.URL, pub any) *x509.Certificate {
		return sign(t, &x509.Certificate{
			Subject: pkix.Name{CommonName: cn}, URIs: uris,
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		}, ca.Cert, pub, ca.Key)
	}
	server, err := ca.IssueServer(newKey(t).Public(), LeafOptions{DNSNames: []string{"a1"}})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		cert *x509.Certificate
	}{
		{"server certificate", server},
		{"no URI", mk("a1", nil, agentPub)},
		{"CN mismatch", mk("a2", []*url.URL{agentURI}, agentPub)},
		{"two URIs", mk("a1", []*url.URL{agentURI, AgentURI("a2")}, agentPub)},
		{"wrong host", mk("a1", []*url.URL{{Scheme: "bomcensus", Host: "scanner", Path: "/a1"}}, agentPub)},
		{"nested path", mk("a1/b", []*url.URL{{Scheme: "bomcensus", Host: "agent", Path: "/a1/b"}}, agentPub)},
		{"query", mk("a1", []*url.URL{{Scheme: "bomcensus", Host: "agent", Path: "/a1", RawQuery: "x=1"}}, agentPub)},
		{"ecdsa key", mk("a1", []*url.URL{agentURI}, newKey(t).Public())},
		{"nil", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if id, err := AgentIDFromCert(tc.cert); err == nil {
				t.Fatalf("accepted, id %q", id)
			}
		})
	}
	// Unrelated URI SANs next to the agent URI are tolerated.
	extra := mk("a1", []*url.URL{{Scheme: "https", Host: "example.test"}, agentURI}, agentPub)
	if id, err := AgentIDFromCert(extra); err != nil || id != "a1" {
		t.Fatalf("extra URI: %q, %v", id, err)
	}
}
