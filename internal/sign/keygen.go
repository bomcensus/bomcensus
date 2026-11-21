// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package sign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// NewCodeSigningCA creates a self-signed ECDSA P-256 root CA for code
// signing. Its path length is limited to one intermediate.
func NewCodeSigningCA(commonName string, notBefore, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("sign: generate CA key: %w", err)
	}
	tmpl, err := certTemplate(commonName, key.Public(), notBefore, notAfter)
	if err != nil {
		return nil, nil, err
	}
	tmpl.IsCA = true
	tmpl.BasicConstraintsValid = true
	tmpl.MaxPathLen = 1
	tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, fmt.Errorf("sign: create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("sign: parse CA certificate: %w", err)
	}
	return cert, key, nil
}

// NewCodeSigningCert issues an ECDSA P-256 leaf certificate with the
// code-signing extended key usage.
func NewCodeSigningCert(ca *x509.Certificate, caKey crypto.Signer, commonName string, notBefore, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if ca == nil || caKey == nil {
		return nil, nil, errors.New("sign: CA certificate and key are required")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("sign: generate signing key: %w", err)
	}
	tmpl, err := certTemplate(commonName, key.Public(), notBefore, notAfter)
	if err != nil {
		return nil, nil, err
	}
	tmpl.BasicConstraintsValid = true
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	tmpl.AuthorityKeyId = ca.SubjectKeyId
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, key.Public(), caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("sign: create signing certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("sign: parse signing certificate: %w", err)
	}
	return cert, key, nil
}

func certTemplate(commonName string, pub crypto.PublicKey, notBefore, notAfter time.Time) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("sign: serial: %w", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("sign: marshal public key: %w", err)
	}
	ski := sha256.Sum256(spki)
	return &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		SubjectKeyId: ski[:20],
	}, nil
}
