// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package agentapi

import (
	"crypto/x509/pkix"
	"encoding/hex"
	"testing"

	"github.com/bomcensus/bomcensus/agentproto/dto"
	"github.com/bomcensus/bomcensus/internal/pki"
)

func hexHash(h [32]byte) string { return hex.EncodeToString(h[:]) }

// A reissued leaf (for example after the server names changed) from the same
// CA must not be reported as interception; another CA must.
func TestObservedIssuerByCA(t *testing.T) {
	h := &Handlers{pki: newFakePKI(t, nil)}
	own := h.pki.(*fakePKI)
	var err error
	if own.pending, err = pki.NewCA(pki.CAOptions{Subject: pkix.Name{CommonName: "Agent TLS CA 2"}}); err != nil {
		t.Fatal(err)
	}

	reissued := &dto.ObservedCert{
		Sha256: hexHash([32]byte{1}), Subject: "CN=new", Issuer: "CN=Agent TLS CA",
		IssuerSpkiSha256: ptr(hexHash(pki.SPKIHash(own.tlsCA.Cert))),
	}
	if got := h.observedIssuer(reissued); got != "" {
		t.Fatalf("same CA, new leaf reported as %q", got)
	}

	evil, err := pki.NewCA(pki.CAOptions{Subject: pkix.Name{CommonName: "Proxy CA"}})
	if err != nil {
		t.Fatal(err)
	}
	mitm := &dto.ObservedCert{
		Sha256: hexHash([32]byte{2}), Subject: "CN=x", Issuer: "CN=Proxy CA",
		IssuerSpkiSha256: ptr(hexHash(pki.SPKIHash(evil.Cert))),
	}
	if got := h.observedIssuer(mitm); got != "CN=Proxy CA" {
		t.Fatalf("foreign CA reported as %q", got)
	}

	// A prepared anchor is accepted too.
	prepared := &dto.ObservedCert{
		Sha256: hexHash([32]byte{3}), Subject: "CN=x", Issuer: "CN=Agent TLS CA 2",
		IssuerSpkiSha256: ptr(hexHash(pki.SPKIHash(own.pending.Cert))),
	}
	if got := h.observedIssuer(prepared); got != "" {
		t.Fatalf("prepared anchor reported as %q", got)
	}

	// Without the issuer hash the certificate cannot be attributed to the
	// server's CAs, even when it is the server's own leaf.
	noIssuer := &dto.ObservedCert{Sha256: hexHash(pki.Fingerprint(own.chain[0])), Subject: "CN=x", Issuer: "CN=Agent TLS CA"}
	if got := h.observedIssuer(noIssuer); got != "CN=Agent TLS CA" {
		t.Fatalf("certificate without issuer hash reported as %q", got)
	}
}

func ptr[T any](v T) *T { return &v }
