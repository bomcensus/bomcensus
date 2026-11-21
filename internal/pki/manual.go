// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pki

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// ManualPair is an administrator-supplied certificate chain and key
// (manual TLS mode) that passed ValidatePair.
type ManualPair struct {
	// Chain is leaf first, in the supplied order.
	Chain []*x509.Certificate
	Key   crypto.Signer
	// DefaultPin is the SPKI hash of the topmost certificate of the chain,
	// the default ca-hash for enrollment strings in manual Agent TLS mode.
	DefaultPin [32]byte
	// NotAfter is the earliest expiry in the chain.
	NotAfter time.Time
}

// Top returns the topmost certificate of the chain.
func (p *ManualPair) Top() *x509.Certificate { return p.Chain[len(p.Chain)-1] }

// TLSCertificate returns the pair for use in a tls.Config.
func (p *ManualPair) TLSCertificate() tls.Certificate { return TLSCertificate(p.Chain, p.Key) }

// ParseManualPair parses a PEM chain (leaf first) and a PEM private key and
// validates them with ValidatePair.
func ParseManualPair(chainPEM, keyPEM []byte, usage x509.ExtKeyUsage, now time.Time) (*ManualPair, error) {
	chain, err := ParseCertificatesPEM(chainPEM)
	if err != nil {
		return nil, err
	}
	key, err := ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	return ValidatePair(chain, key, usage, now)
}

// ValidatePair checks a manual chain and key: the key belongs to the leaf,
// each certificate is issued by the next one, every certificate is valid at
// now, the leaf allows usage, and the leaf verifies up to the topmost
// certificate. Host names are not checked here.
func ValidatePair(chain []*x509.Certificate, key crypto.Signer, usage x509.ExtKeyUsage, now time.Time) (*ManualPair, error) {
	if len(chain) == 0 {
		return nil, ErrEmptyChain
	}
	if key == nil {
		return nil, errors.New("pki: private key is required")
	}
	leaf := chain[0]
	if !KeyMatches(leaf, key) {
		return nil, errors.New("pki: private key does not match the leaf certificate")
	}
	notAfter := leaf.NotAfter
	for i, c := range chain {
		if now.Before(c.NotBefore) {
			return nil, fmt.Errorf("pki: certificate %d (%s) is not valid before %s", i, c.Subject, c.NotBefore.UTC().Format(time.RFC3339))
		}
		if now.After(c.NotAfter) {
			return nil, fmt.Errorf("pki: certificate %d (%s) expired at %s", i, c.Subject, c.NotAfter.UTC().Format(time.RFC3339))
		}
		if c.NotAfter.Before(notAfter) {
			notAfter = c.NotAfter
		}
		if i+1 < len(chain) {
			parent := chain[i+1]
			if !bytes.Equal(c.RawIssuer, parent.RawSubject) {
				return nil, fmt.Errorf("pki: certificate %d is not issued by certificate %d; the chain must be ordered leaf first", i, i+1)
			}
			if err := c.CheckSignatureFrom(parent); err != nil {
				return nil, fmt.Errorf("pki: certificate %d is not signed by certificate %d: %w", i, i+1, err)
			}
		}
	}
	if !allowsUsage(leaf, usage) {
		return nil, fmt.Errorf("pki: leaf certificate does not allow extended key usage %d", usage)
	}

	top := chain[len(chain)-1]
	roots := x509.NewCertPool()
	roots.AddCert(top)
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{usage},
	}); err != nil {
		return nil, fmt.Errorf("pki: verify chain: %w", err)
	}
	return &ManualPair{
		Chain:      chain,
		Key:        key,
		DefaultPin: SPKIHash(top),
		NotAfter:   notAfter,
	}, nil
}

func allowsUsage(c *x509.Certificate, usage x509.ExtKeyUsage) bool {
	if len(c.ExtKeyUsage) == 0 && len(c.UnknownExtKeyUsage) == 0 {
		return true
	}
	for _, u := range c.ExtKeyUsage {
		if u == usage || u == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}
