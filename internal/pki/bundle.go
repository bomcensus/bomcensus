// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pki

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
)

const (
	pemTypeCertificate = "CERTIFICATE"

	bundleRoleHeader    = "Bomcensus-Role"
	bundleVersionHeader = "Bomcensus-Bundle-Version"
	roleAnchor          = "agent-tls-anchor"
	roleAgentCA         = "agent-ca"
)

// TrustBundle is what an agent trusts after enrollment: the Agent TLS
// anchors it verifies the server against and the Agent CA that issues agent
// certificates. Version increases with every change; an agent never replaces
// its bundle with one of a lower or equal version.
type TrustBundle struct {
	Version uint64
	Anchors []*x509.Certificate
	AgentCA *x509.Certificate
}

// Validate checks that the bundle has at least one anchor and a CA as the
// Agent CA.
func (b *TrustBundle) Validate() error {
	if b == nil {
		return errors.New("pki: trust bundle is nil")
	}
	if len(b.Anchors) == 0 {
		return errors.New("pki: trust bundle has no anchors")
	}
	for i, a := range b.Anchors {
		if a == nil {
			return fmt.Errorf("pki: trust bundle anchor %d is nil", i)
		}
	}
	if b.AgentCA == nil {
		return errors.New("pki: trust bundle has no Agent CA")
	}
	if !b.AgentCA.BasicConstraintsValid || !b.AgentCA.IsCA {
		return errors.New("pki: trust bundle Agent CA is not a CA certificate")
	}
	return nil
}

// HasAnchor reports whether one of the anchors has the given SPKI hash.
func (b *TrustBundle) HasAnchor(pin [32]byte) bool {
	for _, a := range b.Anchors {
		if SPKIHash(a) == pin {
			return true
		}
	}
	return false
}

type bundleJSON struct {
	Version uint64   `json:"version"`
	Anchors []string `json:"anchors"`
	AgentCA string   `json:"agent_ca"`
}

// MarshalJSON encodes the bundle as
// {"version":N,"anchors":["<PEM>",...],"agent_ca":"<PEM>"}.
func (b TrustBundle) MarshalJSON() ([]byte, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	j := bundleJSON{Version: b.Version, AgentCA: string(EncodeCertificatesPEM(b.AgentCA))}
	for _, a := range b.Anchors {
		j.Anchors = append(j.Anchors, string(EncodeCertificatesPEM(a)))
	}
	return json.Marshal(j)
}

// UnmarshalJSON decodes the form written by MarshalJSON and validates it.
func (b *TrustBundle) UnmarshalJSON(data []byte) error {
	var j bundleJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return fmt.Errorf("pki: trust bundle: %w", err)
	}
	out := TrustBundle{Version: j.Version}
	for i, s := range j.Anchors {
		c, err := parseSingleCertPEM([]byte(s))
		if err != nil {
			return fmt.Errorf("pki: trust bundle anchor %d: %w", i, err)
		}
		out.Anchors = append(out.Anchors, c)
	}
	if j.AgentCA != "" {
		c, err := parseSingleCertPEM([]byte(j.AgentCA))
		if err != nil {
			return fmt.Errorf("pki: trust bundle Agent CA: %w", err)
		}
		out.AgentCA = c
	}
	if err := out.Validate(); err != nil {
		return err
	}
	*b = out
	return nil
}

// EncodePEM writes the bundle as CERTIFICATE blocks with headers naming
// each block's role and the bundle version.
func (b *TrustBundle) EncodePEM() ([]byte, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	ver := strconv.FormatUint(b.Version, 10)
	write := func(role string, c *x509.Certificate) error {
		return pem.Encode(&buf, &pem.Block{
			Type:    pemTypeCertificate,
			Headers: map[string]string{bundleRoleHeader: role, bundleVersionHeader: ver},
			Bytes:   c.Raw,
		})
	}
	for _, a := range b.Anchors {
		if err := write(roleAnchor, a); err != nil {
			return nil, fmt.Errorf("pki: encode trust bundle: %w", err)
		}
	}
	if err := write(roleAgentCA, b.AgentCA); err != nil {
		return nil, fmt.Errorf("pki: encode trust bundle: %w", err)
	}
	return buf.Bytes(), nil
}

// DecodeTrustBundlePEM parses the output of EncodePEM.
func DecodeTrustBundlePEM(data []byte) (*TrustBundle, error) {
	var (
		b       TrustBundle
		version string
		rest    = data
	)
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != pemTypeCertificate {
			return nil, fmt.Errorf("pki: trust bundle: unexpected PEM block %q", blk.Type)
		}
		v := blk.Headers[bundleVersionHeader]
		if version == "" {
			version = v
		} else if v != version {
			return nil, errors.New("pki: trust bundle: inconsistent versions")
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("pki: trust bundle: %w", err)
		}
		switch blk.Headers[bundleRoleHeader] {
		case roleAnchor:
			b.Anchors = append(b.Anchors, c)
		case roleAgentCA:
			if b.AgentCA != nil {
				return nil, errors.New("pki: trust bundle: more than one Agent CA")
			}
			b.AgentCA = c
		default:
			return nil, fmt.Errorf("pki: trust bundle: unknown role %q", blk.Headers[bundleRoleHeader])
		}
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("pki: trust bundle: trailing data")
	}
	n, err := strconv.ParseUint(version, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("pki: trust bundle: version: %w", err)
	}
	b.Version = n
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return &b, nil
}
