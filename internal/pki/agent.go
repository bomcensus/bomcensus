// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net/url"
	"time"
)

const (
	// AgentURIScheme and AgentURIHost form the URI SAN of an agent
	// certificate: bomcensus://agent/<id>.
	AgentURIScheme = "bomcensus"
	AgentURIHost   = "agent"

	// MaxAgentIDLen bounds agent ids so they fit in a common name.
	MaxAgentIDLen = 64

	// MaxCSRSize bounds the DER size accepted by ParseAgentCSR.
	MaxCSRSize = 4096
)

// GenerateAgentKey creates an Ed25519 agent identity key.
func GenerateAgentKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pki: generate agent key: %w", err)
	}
	return priv, nil
}

// CreateAgentCSR returns a DER-encoded CSR for an agent identity key. The
// CSR carries no identity; the server assigns the agent id.
func CreateAgentCSR(key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("pki: invalid Ed25519 private key")
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "bomcensus-agent"},
	}, key)
	if err != nil {
		return nil, fmt.Errorf("pki: create CSR: %w", err)
	}
	return der, nil
}

// ParseAgentCSR parses a DER CSR, checks its self-signature and requires an
// Ed25519 public key. Subject and requested extensions are ignored by
// IssueAgent.
func ParseAgentCSR(der []byte) (*x509.CertificateRequest, error) {
	if len(der) == 0 || len(der) > MaxCSRSize {
		return nil, fmt.Errorf("pki: CSR size %d out of range", len(der))
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse CSR: %w", err)
	}
	if err := validateAgentCSR(csr); err != nil {
		return nil, err
	}
	return csr, nil
}

func validateAgentCSR(csr *x509.CertificateRequest) error {
	if csr == nil {
		return errors.New("pki: CSR is required")
	}
	if _, ok := csr.PublicKey.(ed25519.PublicKey); !ok || csr.PublicKeyAlgorithm != x509.Ed25519 {
		return fmt.Errorf("pki: CSR public key is %v, want Ed25519", csr.PublicKeyAlgorithm)
	}
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("pki: CSR signature: %w", err)
	}
	return nil
}

// AgentOptions configures IssueAgent.
type AgentOptions struct {
	// NotBefore defaults to the current time minus a few minutes.
	NotBefore time.Time
	// Lifetime defaults to DefaultLeafLifetime.
	Lifetime time.Duration
}

// IssueAgent issues an agent identity certificate for the key in csr. The
// agent id is written as common name and as URI SAN bomcensus://agent/<id>.
// The certificate is valid for clientAuth (connect mode) and serverAuth
// (listen mode listener).
func (ca *CA) IssueAgent(csr *x509.CertificateRequest, agentID string, opts AgentOptions) (*x509.Certificate, error) {
	if err := validateAgentCSR(csr); err != nil {
		return nil, err
	}
	if err := ValidateAgentID(agentID); err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: agentID},
		URIs:        []*url.URL{AgentURI(agentID)},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	return ca.issue(tmpl, csr.PublicKey, opts.NotBefore, opts.Lifetime)
}

// AgentURI returns bomcensus://agent/<id>.
func AgentURI(agentID string) *url.URL {
	return &url.URL{Scheme: AgentURIScheme, Host: AgentURIHost, Path: "/" + agentID}
}

// ValidateAgentID accepts 1 to MaxAgentIDLen characters of [A-Za-z0-9._-].
func ValidateAgentID(id string) error {
	if id == "" || len(id) > MaxAgentIDLen {
		return fmt.Errorf("pki: agent id length %d out of range", len(id))
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return fmt.Errorf("pki: agent id has invalid character at offset %d", i)
		}
	}
	return nil
}

// AgentIDFromCert returns the agent id of an agent certificate. It requires
// exactly one bomcensus agent URI SAN, a matching common name and an
// Ed25519 public key. It does not verify the chain; see VerifyAgent.
func AgentIDFromCert(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", errors.New("pki: certificate is required")
	}
	if _, ok := cert.PublicKey.(ed25519.PublicKey); !ok {
		return "", errors.New("pki: agent certificate key is not Ed25519")
	}
	var id string
	found := 0
	for _, u := range cert.URIs {
		if u.Scheme != AgentURIScheme {
			continue
		}
		found++
		if u.Host != AgentURIHost || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" ||
			len(u.Path) < 2 || u.Path[0] != '/' {
			return "", fmt.Errorf("pki: malformed agent URI %q", u.String())
		}
		id = u.Path[1:]
	}
	if found != 1 {
		return "", fmt.Errorf("pki: certificate has %d agent URIs, want 1", found)
	}
	if err := ValidateAgentID(id); err != nil {
		return "", err
	}
	if cert.Subject.CommonName != id {
		return "", errors.New("pki: agent certificate common name does not match URI")
	}
	return id, nil
}
