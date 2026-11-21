// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pki

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
)

var (
	// ErrPinNotFound is returned when no certificate in the presented chain
	// has the pinned SPKI hash.
	ErrPinNotFound = errors.New("pki: no certificate in chain matches the pinned SPKI hash")
	// ErrEmptyChain is returned for a chain without certificates.
	ErrEmptyChain = errors.New("pki: empty certificate chain")
)

// SPKIHash returns the SHA-256 of the certificate's SubjectPublicKeyInfo.
// It is the ca-hash of the enrollment string.
func SPKIHash(cert *x509.Certificate) [32]byte {
	return sha256.Sum256(cert.RawSubjectPublicKeyInfo)
}

// Fingerprint returns the SHA-256 of the certificate's DER encoding.
func Fingerprint(cert *x509.Certificate) [32]byte {
	return sha256.Sum256(cert.Raw)
}

// KeyMatches reports whether key is the private key of cert.
func KeyMatches(cert *x509.Certificate, key crypto.Signer) bool {
	if cert == nil || key == nil {
		return false
	}
	pub, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	return ok && pub.Equal(cert.PublicKey)
}

// ParseChain parses DER certificates as delivered by crypto/tls
// (leaf first).
func ParseChain(raw [][]byte) ([]*x509.Certificate, error) {
	if len(raw) == 0 {
		return nil, ErrEmptyChain
	}
	chain := make([]*x509.Certificate, 0, len(raw))
	for i, der := range raw {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("pki: certificate %d: %w", i, err)
		}
		chain = append(chain, c)
	}
	return chain, nil
}

// VerifyPinned implements the pinned verification of the enrollment
// protocol: every certificate in chain whose SPKI hash equals pin becomes a
// root, no other root is trusted, and chain[0] must verify up to one of them
// for usage and serverName. The pinned certificate may be the leaf itself,
// an intermediate or the root. serverName must not be empty.
func VerifyPinned(chain []*x509.Certificate, pin [32]byte, serverName string, usage x509.ExtKeyUsage) error {
	if len(chain) == 0 {
		return ErrEmptyChain
	}
	roots := x509.NewCertPool()
	var anchors []*x509.Certificate
	for _, c := range chain {
		if SPKIHash(c) == pin {
			roots.AddCert(c)
			anchors = append(anchors, c)
		}
	}
	if len(anchors) == 0 {
		return ErrPinNotFound
	}
	return verify(chain, roots, serverName, usage)
}

// VerifyAnchors verifies chain[0] up to one of anchors (for example the
// Agent TLS anchors of a trust bundle) for usage and serverName. The
// presented chain does not need to contain the anchor. serverName must not
// be empty.
func VerifyAnchors(chain []*x509.Certificate, anchors []*x509.Certificate, serverName string, usage x509.ExtKeyUsage) error {
	if len(chain) == 0 {
		return ErrEmptyChain
	}
	if len(anchors) == 0 {
		return errors.New("pki: no trust anchors")
	}
	roots := x509.NewCertPool()
	for _, a := range anchors {
		roots.AddCert(a)
	}
	return verify(chain, roots, serverName, usage)
}

// VerifyAgent verifies an agent certificate chain against the Agent CA for
// usage (clientAuth when the agent dials, serverAuth when the server dials a
// listen-mode agent) and returns the agent id. Revocation is not checked
// here.
func VerifyAgent(chain []*x509.Certificate, agentCA *x509.Certificate, usage x509.ExtKeyUsage) (string, error) {
	if len(chain) == 0 {
		return "", ErrEmptyChain
	}
	if agentCA == nil {
		return "", errors.New("pki: Agent CA is required")
	}
	roots := x509.NewCertPool()
	roots.AddCert(agentCA)
	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{usage},
	}
	// Agent certificates are issued directly by the Agent CA.
	if _, err := chain[0].Verify(opts); err != nil {
		return "", fmt.Errorf("pki: verify agent certificate: %w", err)
	}
	return AgentIDFromCert(chain[0])
}

func verify(chain []*x509.Certificate, roots *x509.CertPool, serverName string, usage x509.ExtKeyUsage) error {
	if serverName == "" {
		return errors.New("pki: server name is required")
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	opts := x509.VerifyOptions{
		DNSName:       serverName,
		Roots:         roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{usage},
	}
	if _, err := chain[0].Verify(opts); err != nil {
		return fmt.Errorf("pki: verify chain: %w", err)
	}
	return nil
}
