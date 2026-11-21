// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pki

import (
	"crypto"
	"crypto/x509"
	"testing"
	"time"
)

func TestValidatePair(t *testing.T) {
	now := time.Now()
	good := newTestChain(t, chainOpts{})
	other := newTestChain(t, chainOpts{})
	expiredInter := newTestChain(t, chainOpts{interNotBefore: now.Add(-48 * time.Hour), interNotAfter: now.Add(-time.Hour)})
	futureLeaf := newTestChain(t, chainOpts{leafNotBefore: now.Add(time.Hour), leafNotAfter: now.Add(48 * time.Hour)})
	clientOnly := newTestChain(t, chainOpts{leafUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})

	cases := []struct {
		name    string
		chain   []*x509.Certificate
		key     crypto.Signer
		usage   x509.ExtKeyUsage
		ok      bool
		wantTop *x509.Certificate
	}{
		{"full chain", good.certs(), good.leafKey, x509.ExtKeyUsageServerAuth, true, good.root},
		{"without root", good.certs()[:2], good.leafKey, x509.ExtKeyUsageServerAuth, true, good.inter},
		{"leaf only", good.certs()[:1], good.leafKey, x509.ExtKeyUsageServerAuth, true, good.leaf},
		{"client usage", clientOnly.certs(), clientOnly.leafKey, x509.ExtKeyUsageClientAuth, true, clientOnly.root},
		{"key mismatch", good.certs(), other.leafKey, x509.ExtKeyUsageServerAuth, false, nil},
		{"CA key for leaf", good.certs(), good.interKey, x509.ExtKeyUsageServerAuth, false, nil},
		{"wrong order", []*x509.Certificate{good.leaf, good.root, good.inter}, good.leafKey, x509.ExtKeyUsageServerAuth, false, nil},
		{"root first", []*x509.Certificate{good.root, good.inter, good.leaf}, good.rootKey, x509.ExtKeyUsageServerAuth, false, nil},
		{"missing intermediate", []*x509.Certificate{good.leaf, good.root}, good.leafKey, x509.ExtKeyUsageServerAuth, false, nil},
		{"foreign intermediate", []*x509.Certificate{good.leaf, other.inter, other.root}, good.leafKey, x509.ExtKeyUsageServerAuth, false, nil},
		{"expired intermediate", expiredInter.certs(), expiredInter.leafKey, x509.ExtKeyUsageServerAuth, false, nil},
		{"leaf not yet valid", futureLeaf.certs(), futureLeaf.leafKey, x509.ExtKeyUsageServerAuth, false, nil},
		{"usage mismatch", clientOnly.certs(), clientOnly.leafKey, x509.ExtKeyUsageServerAuth, false, nil},
		{"empty chain", nil, good.leafKey, x509.ExtKeyUsageServerAuth, false, nil},
		{"nil key", good.certs(), nil, x509.ExtKeyUsageServerAuth, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ValidatePair(tc.chain, tc.key, tc.usage, now)
			if !tc.ok {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !p.Top().Equal(tc.wantTop) || p.DefaultPin != SPKIHash(tc.wantTop) {
				t.Fatal("wrong default pin")
			}
			var earliest time.Time
			for _, c := range tc.chain {
				if earliest.IsZero() || c.NotAfter.Before(earliest) {
					earliest = c.NotAfter
				}
			}
			if !p.NotAfter.Equal(earliest) {
				t.Fatalf("NotAfter = %s, want %s", p.NotAfter, earliest)
			}
			tc := p.TLSCertificate()
			if len(tc.Certificate) != len(p.Chain) || tc.Leaf != p.Chain[0] {
				t.Fatal("TLSCertificate does not carry the chain")
			}
		})
	}
}

func TestParseManualPair(t *testing.T) {
	c := newTestChain(t, chainOpts{})
	keyPEM, err := EncodePrivateKeyPEM(c.leafKey)
	if err != nil {
		t.Fatal(err)
	}
	chainPEM := EncodeCertificatesPEM(c.certs()...)
	p, err := ParseManualPair(chainPEM, keyPEM, x509.ExtKeyUsageServerAuth, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if p.DefaultPin != SPKIHash(c.root) || len(p.Chain) != 3 {
		t.Fatal("unexpected pair")
	}
	// The pair is usable with the pinned verification agents perform.
	if err := VerifyPinned(p.Chain, p.DefaultPin, testName, x509.ExtKeyUsageServerAuth); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseManualPair(keyPEM, keyPEM, x509.ExtKeyUsageServerAuth, time.Now()); err == nil {
		t.Fatal("key accepted as chain")
	}
	if _, err := ParseManualPair(chainPEM, chainPEM, x509.ExtKeyUsageServerAuth, time.Now()); err == nil {
		t.Fatal("chain accepted as key")
	}
	if _, err := ParseManualPair(chainPEM, keyPEM, x509.ExtKeyUsageServerAuth, time.Now().Add(48*time.Hour)); err == nil {
		t.Fatal("expired leaf accepted")
	}
}
