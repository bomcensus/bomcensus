// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package state

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/bomcensus/bomcensus/internal/pki"
)

// ErrNotEnrolled is returned by LoadEnrollment when the directory holds no
// enrollment.
var ErrNotEnrolled = errors.New("state: not enrolled")

// Enrollment states.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
)

// Enrollment holds the parameters fixed at enrollment. It contains no
// secret.
type Enrollment struct {
	Kind string `json:"kind"`
	// ServerURL is the server address in connect mode (https://host:port).
	ServerURL string `json:"server_url,omitempty"`
	// ServerName is the name the server certificates are checked against.
	ServerName    string `json:"server_name"`
	ConnectMode   string `json:"connect_mode"`
	ListenAddress string `json:"listen_address,omitempty"`
	TLSMode       string `json:"tls_mode"`
	// Pin is the ca-hash of the enrollment string, unpadded base64url.
	Pin        string    `json:"pin"`
	AgentID    string    `json:"agent_id"`
	Status     string    `json:"status"`
	EnrolledAt time.Time `json:"enrolled_at"`
}

// LoadEnrollment returns the stored enrollment or ErrNotEnrolled.
func (d *Dir) LoadEnrollment() (*Enrollment, error) {
	var e Enrollment
	ok, err := d.readJSON(enrollmentName, &e)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNotEnrolled
	}
	if err := pki.ValidateAgentID(e.AgentID); err != nil {
		return nil, fmt.Errorf("state: %s: %w", enrollmentName, err)
	}
	if e.Status != StatusPending && e.Status != StatusApproved {
		return nil, fmt.Errorf("state: %s: unknown status %q", enrollmentName, e.Status)
	}
	if _, err := e.PinHash(); err != nil {
		return nil, fmt.Errorf("state: %s: %w", enrollmentName, err)
	}
	return &e, nil
}

// PinHash decodes Pin.
func (e *Enrollment) PinHash() ([32]byte, error) {
	var h [32]byte
	b, err := base64.RawURLEncoding.Strict().DecodeString(e.Pin)
	if err != nil || len(b) != len(h) {
		return h, errors.New("invalid pin")
	}
	copy(h[:], b)
	return h, nil
}

// SetPin encodes h into Pin.
func (e *Enrollment) SetPin(h [32]byte) { e.Pin = base64.RawURLEncoding.EncodeToString(h[:]) }

// SaveEnrollment stores e.
func (d *Dir) SaveEnrollment(e *Enrollment) error {
	return d.writeJSON(enrollmentName, e, 0o600)
}

// Identity is the agent identity key and, once approved, its certificate.
type Identity struct {
	Key  ed25519.PrivateKey
	Cert *x509.Certificate
}

// LoadIdentity reads the identity key and certificate. Both live in one
// file so that a key change and its certificate are replaced together.
func (d *Dir) LoadIdentity() (*Identity, error) {
	return d.loadIdentity(identityName)
}

// SaveIdentity stores id with mode 0600.
func (d *Dir) SaveIdentity(id *Identity) error {
	return d.saveIdentity(identityName, id)
}

// LoadNextKey returns a key generated for a certificate renewal with a new
// key that has not completed yet, or nil.
func (d *Dir) LoadNextKey() (ed25519.PrivateKey, error) {
	id, err := d.loadIdentity(nextKeyName)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return id.Key, nil
}

// SaveNextKey stores a key before it is sent in a renewal CSR, so that it
// survives a crash after the server switched to it.
func (d *Dir) SaveNextKey(key ed25519.PrivateKey) error {
	return d.saveIdentity(nextKeyName, &Identity{Key: key})
}

// RemoveNextKey deletes the pending renewal key.
func (d *Dir) RemoveNextKey() error { return d.Remove(nextKeyName) }

func (d *Dir) loadIdentity(name string) (*Identity, error) {
	b, err := d.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("state: read %s: %w", name, err)
	}
	var id Identity
	rest := b
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		switch blk.Type {
		case "PRIVATE KEY":
			if id.Key != nil {
				return nil, fmt.Errorf("state: %s: more than one key", name)
			}
			k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
			if err != nil {
				return nil, fmt.Errorf("state: %s: %w", name, err)
			}
			ek, ok := k.(ed25519.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("state: %s: key is not Ed25519", name)
			}
			id.Key = ek
		case "CERTIFICATE":
			if id.Cert != nil {
				return nil, fmt.Errorf("state: %s: more than one certificate", name)
			}
			c, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				return nil, fmt.Errorf("state: %s: %w", name, err)
			}
			id.Cert = c
		default:
			return nil, fmt.Errorf("state: %s: unexpected PEM block %q", name, blk.Type)
		}
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("state: %s: trailing data", name)
	}
	if id.Key == nil {
		return nil, fmt.Errorf("state: %s: no key", name)
	}
	if id.Cert != nil && !pki.KeyMatches(id.Cert, id.Key) {
		return nil, fmt.Errorf("state: %s: certificate does not match the key", name)
	}
	return &id, nil
}

func (d *Dir) saveIdentity(name string, id *Identity) error {
	if id == nil || len(id.Key) != ed25519.PrivateKeySize {
		return errors.New("state: identity key is required")
	}
	if id.Cert != nil && !pki.KeyMatches(id.Cert, id.Key) {
		return errors.New("state: certificate does not match the identity key")
	}
	b, err := pki.EncodePrivateKeyPEM(id.Key)
	if err != nil {
		return err
	}
	if id.Cert != nil {
		b = append(b, pki.EncodeCertificatesPEM(id.Cert)...)
	}
	return d.WriteFile(name, b, 0o600)
}

// LoadTrustBundle returns the stored trust bundle or nil.
func (d *Dir) LoadTrustBundle() (*pki.TrustBundle, error) {
	b, err := d.ReadFile(bundleName)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("state: read %s: %w", bundleName, err)
	}
	tb, err := pki.DecodeTrustBundlePEM(b)
	if err != nil {
		return nil, fmt.Errorf("state: %s: %w", bundleName, err)
	}
	return tb, nil
}

// SaveTrustBundle stores tb.
func (d *Dir) SaveTrustBundle(tb *pki.TrustBundle) error {
	b, err := tb.EncodePEM()
	if err != nil {
		return err
	}
	return d.WriteFile(bundleName, b, 0o644)
}

// LoadExtraRoots returns the CA certificates trusted in addition to the OS
// store in the system TLS mode, or nil.
func (d *Dir) LoadExtraRoots() ([]*x509.Certificate, error) {
	b, err := d.ReadFile(extraRootsName)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("state: read %s: %w", extraRootsName, err)
	}
	certs, err := pki.ParseCertificatesPEM(b)
	if err != nil {
		return nil, fmt.Errorf("state: %s: %w", extraRootsName, err)
	}
	return certs, nil
}

// SaveExtraRoots stores CA certificates for the system TLS mode.
func (d *Dir) SaveExtraRoots(certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return d.Remove(extraRootsName)
	}
	return d.WriteFile(extraRootsName, pki.EncodeCertificatesPEM(certs...), 0o644)
}

// LoadServerConfig decodes the last configuration received from the server
// into v. It reports false when none is stored.
func (d *Dir) LoadServerConfig(v any) (bool, error) { return d.readJSON(configName, v) }

// SaveServerConfig stores the last configuration received from the server.
func (d *Dir) SaveServerConfig(v any) error { return d.writeJSON(configName, v, 0o600) }

// Sections records per-section collection state.
type Sections struct {
	// Digests holds the digest of each section as last uploaded.
	Digests map[string]string `json:"digests"`
	// LastRun holds the time each section was last collected.
	LastRun map[string]time.Time `json:"last_run"`
}

// LoadSections returns the stored section state (empty maps when absent).
func (d *Dir) LoadSections() (*Sections, error) {
	s := &Sections{}
	if _, err := d.readJSON(sectionsName, s); err != nil {
		return nil, err
	}
	if s.Digests == nil {
		s.Digests = map[string]string{}
	}
	if s.LastRun == nil {
		s.LastRun = map[string]time.Time{}
	}
	return s, nil
}

// SaveSections stores s.
func (d *Dir) SaveSections(s *Sections) error { return d.writeJSON(sectionsName, s, 0o600) }

// Revocation records that the server answered with agent_revoked, so that
// a restarted agent waits before asking again.
type Revocation struct {
	// Count is the number of runs that ended with the answer.
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// LoadRevocation returns the stored revocation record or nil.
func (d *Dir) LoadRevocation() (*Revocation, error) {
	var r Revocation
	ok, err := d.readJSON(revokedName, &r)
	if err != nil || !ok {
		return nil, err
	}
	return &r, nil
}

// SaveRevocation stores r.
func (d *Dir) SaveRevocation(r *Revocation) error { return d.writeJSON(revokedName, r, 0o600) }

// ClearRevocation removes the revocation record.
func (d *Dir) ClearRevocation() error { return d.Remove(revokedName) }

// LoadProbeCache returns the probe's opaque cache or nil.
func (d *Dir) LoadProbeCache() (json.RawMessage, error) {
	b, err := d.ReadFile(cacheName)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("state: read %s: %w", cacheName, err)
	}
	if !json.Valid(b) {
		// A damaged cache only costs re-hashing.
		return nil, nil
	}
	return b, nil
}

// SaveProbeCache stores the probe's opaque cache.
func (d *Dir) SaveProbeCache(c json.RawMessage) error {
	if len(c) == 0 {
		return d.Remove(cacheName)
	}
	return d.WriteFile(cacheName, c, 0o600)
}
