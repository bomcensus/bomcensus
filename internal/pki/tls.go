// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"
)

// TemporaryLifetime is the validity of the in-memory listener certificate
// a listen-mode agent uses until enrollment completes.
const TemporaryLifetime = 30 * 24 * time.Hour

// TLSCertificate builds a tls.Certificate from a chain (leaf first) and key.
func TLSCertificate(chain []*x509.Certificate, key crypto.Signer) tls.Certificate {
	tc := tls.Certificate{PrivateKey: key}
	for _, c := range chain {
		tc.Certificate = append(tc.Certificate, c.Raw)
	}
	if len(chain) > 0 {
		tc.Leaf = chain[0]
	}
	return tc
}

// NewTemporaryCertificate creates a fresh ECDSA P-256 key and a self-signed
// serverAuth certificate for it. Nothing is persisted; the peer is not
// expected to verify it.
func NewTemporaryCertificate() (tls.Certificate, error) {
	key, err := GenerateKey()
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := NewSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	nb, na, err := validity(time.Time{}, TemporaryLifetime, TemporaryLifetime)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "bomcensus-agent-enrollment"},
		NotBefore:             nb,
		NotAfter:              na,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("pki: create temporary certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("pki: parse temporary certificate: %w", err)
	}
	return TLSCertificate([]*x509.Certificate{cert}, key), nil
}
