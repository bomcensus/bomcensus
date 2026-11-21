// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package pki holds the certificate handling shared by the server, agents
// and scanners: internal CAs, leaf issuance, agent identity certificates,
// pinned chain verification, trust bundles and PEM helpers.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

const (
	// DefaultCALifetime is used when CAOptions.Lifetime is zero.
	DefaultCALifetime = 10 * 365 * 24 * time.Hour
	// DefaultLeafLifetime is used when a leaf lifetime is zero.
	DefaultLeafLifetime = 90 * 24 * time.Hour

	// backdate is subtracted from the current time when NotBefore is not
	// given, to tolerate clock skew between peers.
	backdate = 5 * time.Minute
)

// GenerateKey creates an ECDSA P-256 key, the key type of every
// automatically managed CA and TLS certificate.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pki: generate key: %w", err)
	}
	return k, nil
}

// CA is a certificate authority that issues leaves directly (no
// intermediates).
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// CAOptions configures NewCA.
type CAOptions struct {
	Subject pkix.Name
	// NotBefore defaults to the current time minus a few minutes.
	NotBefore time.Time
	// Lifetime defaults to DefaultCALifetime.
	Lifetime time.Duration
}

// NewCA creates a self-signed CA with a new ECDSA P-256 key.
func NewCA(opts CAOptions) (*CA, error) {
	key, err := GenerateKey()
	if err != nil {
		return nil, err
	}
	notBefore, notAfter, err := validity(opts.NotBefore, opts.Lifetime, DefaultCALifetime)
	if err != nil {
		return nil, err
	}
	serial, err := NewSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               opts.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("pki: create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse CA certificate: %w", err)
	}
	return &CA{Cert: cert, Key: key}, nil
}

// LoadCA checks that cert is a CA certificate and that key belongs to it.
func LoadCA(cert *x509.Certificate, key crypto.Signer) (*CA, error) {
	if cert == nil || key == nil {
		return nil, errors.New("pki: CA certificate and key are required")
	}
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return nil, errors.New("pki: certificate is not a CA")
	}
	if !KeyMatches(cert, key) {
		return nil, errors.New("pki: CA key does not match certificate")
	}
	return &CA{Cert: cert, Key: key}, nil
}

// LeafOptions configures server and client TLS certificates.
type LeafOptions struct {
	CommonName  string
	DNSNames    []string
	IPAddresses []net.IP
	// NotBefore defaults to the current time minus a few minutes.
	NotBefore time.Time
	// Lifetime defaults to DefaultLeafLifetime. The certificate never
	// outlives the CA.
	Lifetime time.Duration
}

// IssueServer issues a TLS server certificate (serverAuth) for pub.
func (ca *CA) IssueServer(pub crypto.PublicKey, opts LeafOptions) (*x509.Certificate, error) {
	return ca.issueTLS(pub, opts, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
}

// IssueClient issues a TLS client certificate (clientAuth) for pub. The
// server presents it when it dials a listen-mode agent, and the agent checks
// its name, so opts should carry the server name as a SAN.
func (ca *CA) IssueClient(pub crypto.PublicKey, opts LeafOptions) (*x509.Certificate, error) {
	return ca.issueTLS(pub, opts, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
}

func (ca *CA) issueTLS(pub crypto.PublicKey, opts LeafOptions, usage []x509.ExtKeyUsage) (*x509.Certificate, error) {
	if len(opts.DNSNames) == 0 && len(opts.IPAddresses) == 0 {
		return nil, errors.New("pki: certificate needs at least one DNS name or IP address")
	}
	cn := opts.CommonName
	if cn == "" && len(opts.DNSNames) > 0 {
		cn = opts.DNSNames[0]
	}
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: cn},
		DNSNames:    opts.DNSNames,
		IPAddresses: opts.IPAddresses,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: usage,
	}
	return ca.issue(tmpl, pub, opts.NotBefore, opts.Lifetime)
}

// issue fills serial, validity and basic constraints of tmpl and signs it.
func (ca *CA) issue(tmpl *x509.Certificate, pub crypto.PublicKey, notBefore time.Time, lifetime time.Duration) (*x509.Certificate, error) {
	if ca == nil || ca.Cert == nil || ca.Key == nil {
		return nil, errors.New("pki: CA is not initialized")
	}
	if pub == nil {
		return nil, errors.New("pki: public key is required")
	}
	nb, na, err := validity(notBefore, lifetime, DefaultLeafLifetime)
	if err != nil {
		return nil, err
	}
	if na.After(ca.Cert.NotAfter) {
		na = ca.Cert.NotAfter
	}
	if nb.Before(ca.Cert.NotBefore) {
		nb = ca.Cert.NotBefore
	}
	if !na.After(nb) {
		return nil, errors.New("pki: CA validity does not cover the requested period")
	}
	serial, err := NewSerial()
	if err != nil {
		return nil, err
	}
	tmpl.SerialNumber = serial
	tmpl.NotBefore = nb
	tmpl.NotAfter = na
	tmpl.BasicConstraintsValid = true
	tmpl.IsCA = false
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("pki: create certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse certificate: %w", err)
	}
	return cert, nil
}

// NewSerial returns a random positive 128-bit serial number.
func NewSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	for {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, fmt.Errorf("pki: serial: %w", err)
		}
		if n.Sign() > 0 {
			return n, nil
		}
	}
}

func validity(notBefore time.Time, lifetime, def time.Duration) (time.Time, time.Time, error) {
	if lifetime < 0 {
		return time.Time{}, time.Time{}, errors.New("pki: negative lifetime")
	}
	if lifetime == 0 {
		lifetime = def
	}
	if notBefore.IsZero() {
		notBefore = time.Now().Add(-backdate)
	}
	notBefore = notBefore.UTC().Truncate(time.Second)
	return notBefore, notBefore.Add(lifetime), nil
}
