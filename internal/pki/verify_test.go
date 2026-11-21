// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pki

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"testing"
	"time"
)

const testName = "agents.example.test"

func TestVerifyPinned(t *testing.T) {
	good := newTestChain(t, chainOpts{})
	other := newTestChain(t, chainOpts{})
	now := time.Now()
	expired := newTestChain(t, chainOpts{leafNotBefore: now.Add(-48 * time.Hour), leafNotAfter: now.Add(-24 * time.Hour)})
	notYet := newTestChain(t, chainOpts{leafNotBefore: now.Add(24 * time.Hour), leafNotAfter: now.Add(48 * time.Hour)})
	clientOnly := newTestChain(t, chainOpts{leafUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	both := newTestChain(t, chainOpts{leafUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}})
	ipChain := newTestChain(t, chainOpts{dnsNames: []string{"x.example.test"}})

	cases := []struct {
		name    string
		chain   []*x509.Certificate
		pin     [32]byte
		host    string
		usage   x509.ExtKeyUsage
		wantErr error // nil: success; errAny: any error
	}{
		{"pin at root", good.certs(), SPKIHash(good.root), testName, x509.ExtKeyUsageServerAuth, nil},
		{"pin at intermediate", good.certs(), SPKIHash(good.inter), testName, x509.ExtKeyUsageServerAuth, nil},
		{"pin at leaf", good.certs(), SPKIHash(good.leaf), testName, x509.ExtKeyUsageServerAuth, nil},
		{"pin at intermediate, root not sent", good.certs()[:2], SPKIHash(good.inter), testName, x509.ExtKeyUsageServerAuth, nil},
		{"out of order chain", []*x509.Certificate{good.leaf, good.root, good.inter}, SPKIHash(good.root), testName, x509.ExtKeyUsageServerAuth, nil},
		{"root pinned but not sent", good.certs()[:2], SPKIHash(good.root), testName, x509.ExtKeyUsageServerAuth, ErrPinNotFound},
		{"wrong pin", good.certs(), SPKIHash(other.root), testName, x509.ExtKeyUsageServerAuth, ErrPinNotFound},
		{"zero pin", good.certs(), [32]byte{}, testName, x509.ExtKeyUsageServerAuth, ErrPinNotFound},
		{"pinned cert appended to foreign chain", append(other.certs(), good.root), SPKIHash(good.root), testName, x509.ExtKeyUsageServerAuth, errAny},
		{"intermediate missing", []*x509.Certificate{good.leaf, good.root}, SPKIHash(good.root), testName, x509.ExtKeyUsageServerAuth, errAny},
		{"wrong name", good.certs(), SPKIHash(good.root), "other.example.test", x509.ExtKeyUsageServerAuth, errAny},
		{"name is IP", ipChain.certs(), SPKIHash(ipChain.root), "192.0.2.1", x509.ExtKeyUsageServerAuth, errAny},
		{"empty name", good.certs(), SPKIHash(good.root), "", x509.ExtKeyUsageServerAuth, errAny},
		{"expired leaf", expired.certs(), SPKIHash(expired.root), testName, x509.ExtKeyUsageServerAuth, errAny},
		{"expired leaf pinned itself", expired.certs(), SPKIHash(expired.leaf), testName, x509.ExtKeyUsageServerAuth, errAny},
		{"leaf not yet valid", notYet.certs(), SPKIHash(notYet.root), testName, x509.ExtKeyUsageServerAuth, errAny},
		{"usage mismatch server", clientOnly.certs(), SPKIHash(clientOnly.root), testName, x509.ExtKeyUsageServerAuth, errAny},
		{"usage mismatch client", good.certs(), SPKIHash(good.root), testName, x509.ExtKeyUsageClientAuth, errAny},
		{"client usage", clientOnly.certs(), SPKIHash(clientOnly.root), testName, x509.ExtKeyUsageClientAuth, nil},
		{"dual usage as client", both.certs(), SPKIHash(both.inter), testName, x509.ExtKeyUsageClientAuth, nil},
		{"empty chain", nil, SPKIHash(good.root), testName, x509.ExtKeyUsageServerAuth, ErrEmptyChain},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyPinned(tc.chain, tc.pin, tc.host, tc.usage)
			checkErr(t, err, tc.wantErr)
		})
	}
}

var errAny = errors.New("any error")

func checkErr(t *testing.T, err, want error) {
	t.Helper()
	switch {
	case want == nil && err != nil:
		t.Fatalf("unexpected error: %v", err)
	case want == errAny && err == nil:
		t.Fatal("expected an error")
	case want != nil && want != errAny && !errors.Is(err, want):
		t.Fatalf("err = %v, want %v", err, want)
	}
}

func TestVerifyAnchors(t *testing.T) {
	good := newTestChain(t, chainOpts{})
	other := newTestChain(t, chainOpts{})
	cases := []struct {
		name    string
		chain   []*x509.Certificate
		anchors []*x509.Certificate
		host    string
		wantErr error
	}{
		{"root anchor, chain without root", good.certs()[:2], []*x509.Certificate{good.root}, testName, nil},
		{"second of two anchors", good.certs(), []*x509.Certificate{other.root, good.root}, testName, nil},
		{"intermediate anchor", good.certs()[:1], []*x509.Certificate{good.inter}, testName, nil},
		{"foreign anchor", good.certs(), []*x509.Certificate{other.root}, testName, errAny},
		{"no anchors", good.certs(), nil, testName, errAny},
		{"wrong name", good.certs(), []*x509.Certificate{good.root}, "nope.example.test", errAny},
		{"empty chain", nil, []*x509.Certificate{good.root}, testName, ErrEmptyChain},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checkErr(t, VerifyAnchors(tc.chain, tc.anchors, tc.host, x509.ExtKeyUsageServerAuth), tc.wantErr)
		})
	}
}

func TestIssuedCertificatesVerifyPinned(t *testing.T) {
	ca := newTestCA(t)
	key := newKey(t)
	srv, err := ca.IssueServer(key.Public(), LeafOptions{DNSNames: []string{testName}, IPAddresses: []net.IP{net.ParseIP("192.0.2.10")}})
	if err != nil {
		t.Fatal(err)
	}
	cli, err := ca.IssueClient(key.Public(), LeafOptions{DNSNames: []string{testName}})
	if err != nil {
		t.Fatal(err)
	}
	pin := SPKIHash(ca.Cert)
	chain := []*x509.Certificate{srv, ca.Cert}
	if err := VerifyPinned(chain, pin, testName, x509.ExtKeyUsageServerAuth); err != nil {
		t.Fatalf("server by name: %v", err)
	}
	if err := VerifyPinned(chain, pin, "192.0.2.10", x509.ExtKeyUsageServerAuth); err != nil {
		t.Fatalf("server by IP: %v", err)
	}
	if err := VerifyPinned(chain, pin, testName, x509.ExtKeyUsageClientAuth); err == nil {
		t.Fatal("server certificate accepted for clientAuth")
	}
	cchain := []*x509.Certificate{cli, ca.Cert}
	if err := VerifyPinned(cchain, pin, testName, x509.ExtKeyUsageClientAuth); err != nil {
		t.Fatalf("client: %v", err)
	}
	if err := VerifyPinned(cchain, pin, testName, x509.ExtKeyUsageServerAuth); err == nil {
		t.Fatal("client certificate accepted for serverAuth")
	}
	if err := VerifyAnchors([]*x509.Certificate{srv}, []*x509.Certificate{ca.Cert}, testName, x509.ExtKeyUsageServerAuth); err != nil {
		t.Fatalf("anchors: %v", err)
	}

	// Reissuing the CA certificate with the same key keeps the pin.
	reissued := sign(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "Test CA"}, IsCA: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: ca.Cert.NotBefore, NotAfter: ca.Cert.NotAfter.Add(time.Hour),
	}, nil, ca.Key.Public(), ca.Key)
	if SPKIHash(reissued) != pin {
		t.Fatal("SPKI hash changed with reissue")
	}
	if err := VerifyPinned([]*x509.Certificate{srv, reissued}, pin, testName, x509.ExtKeyUsageServerAuth); err != nil {
		t.Fatalf("reissued CA: %v", err)
	}
}

func TestHashes(t *testing.T) {
	ca := newTestCA(t)
	if got, want := Fingerprint(ca.Cert), sha256.Sum256(ca.Cert.Raw); got != want {
		t.Fatal("Fingerprint is not SHA-256 of DER")
	}
	if got, want := SPKIHash(ca.Cert), sha256.Sum256(ca.Cert.RawSubjectPublicKeyInfo); got != want {
		t.Fatal("SPKIHash is not SHA-256 of SPKI")
	}
	if SPKIHash(ca.Cert) == Fingerprint(ca.Cert) {
		t.Fatal("SPKI hash equals fingerprint")
	}
}

// TestPinnedHandshake shows the intended use from a tls.Config.
func TestPinnedHandshake(t *testing.T) {
	ca := newTestCA(t)
	key := newKey(t)
	srv, err := ca.IssueServer(key.Public(), LeafOptions{DNSNames: []string{testName}})
	if err != nil {
		t.Fatal(err)
	}
	serverCert := TLSCertificate([]*x509.Certificate{srv, ca.Cert}, key)

	run := func(pin [32]byte) error {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		go func() {
			s := tls.Server(c2, &tls.Config{Certificates: []tls.Certificate{serverCert}})
			_ = s.HandshakeContext(ctx)
		}()
		cl := tls.Client(c1, &tls.Config{
			ServerName:         testName,
			InsecureSkipVerify: true, // replaced by VerifyConnection
			VerifyConnection: func(cs tls.ConnectionState) error {
				return VerifyPinned(cs.PeerCertificates, pin, cs.ServerName, x509.ExtKeyUsageServerAuth)
			},
		})
		return cl.HandshakeContext(ctx)
	}
	if err := run(SPKIHash(ca.Cert)); err != nil {
		t.Fatalf("pinned handshake: %v", err)
	}
	if err := run([32]byte{1}); !errors.Is(err, ErrPinNotFound) {
		t.Fatalf("wrong pin handshake err = %v", err)
	}
}

func TestParseChain(t *testing.T) {
	c := newTestChain(t, chainOpts{})
	got, err := ParseChain([][]byte{c.leaf.Raw, c.inter.Raw})
	if err != nil || len(got) != 2 || !got[0].Equal(c.leaf) {
		t.Fatalf("ParseChain = %v, %v", got, err)
	}
	if _, err := ParseChain(nil); !errors.Is(err, ErrEmptyChain) {
		t.Fatalf("empty: %v", err)
	}
	if _, err := ParseChain([][]byte{{0x30, 0x01}}); err == nil {
		t.Fatal("garbage accepted")
	}
}
