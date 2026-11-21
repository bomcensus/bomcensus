// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pkisvc

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/bomcensus/bomcensus/internal/pki"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// FormatSerial is how agent certificate serials are stored
// (store.AgentCert.Serial): lowercase hexadecimal without leading zeros.
func FormatSerial(n *big.Int) string { return n.Text(16) }

// IssueAgentCertificate issues an agent certificate for the key in the DER
// CSR and records it. The agent must exist.
func (s *Service) IssueAgentCertificate(ctx context.Context, csrDER []byte, agentID string) (*x509.Certificate, error) {
	return s.IssueAgentCertificateWith(ctx, s.st, csrDER, agentID)
}

// IssueAgentCertificateWith is IssueAgentCertificate recording the
// certificate through certs, for example the store of a transaction that
// also creates the agent.
func (s *Service) IssueAgentCertificateWith(ctx context.Context, certs store.AgentCerts, csrDER []byte, agentID string) (*x509.Certificate, error) {
	csr, err := pki.ParseAgentCSR(csrDER)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	sn, err := s.current()
	if err != nil {
		return nil, err
	}
	cert, err := sn.agentCA.IssueAgent(csr, agentID, pki.AgentOptions{
		NotBefore: s.now().Add(-backdate),
		Lifetime:  s.cfg.AgentCertLifetime,
	})
	if err != nil {
		return nil, err
	}
	if err := certs.InsertAgentCert(ctx, store.AgentCert{
		Serial:    FormatSerial(cert.SerialNumber),
		AgentID:   agentID,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
	}); err != nil {
		return nil, err
	}
	return cert, nil
}

// revocationCache answers revocation lookups from memory.
//
// It holds the set of revoked certificates, loaded in full at the first
// refresh and every revFullEvery refreshes, and in between extended with the
// certificates revoked since the previous load (with revOverlap to cover
// clock skew between replicas and commit delays). A revoked serial stays
// revoked until the certificate expires. Serials found unrevoked in the
// store are remembered as known; serials the store does not know (never
// issued by this server's Agent CA, or not recorded) are remembered as
// revoked. Both are dropped after revIdle refresh intervals without
// lookups.
type revocationCache struct {
	mu sync.Mutex
	// loaded is set after the first full load; until then known serials
	// are not answered from memory.
	loaded bool
	// since is where the next incremental load starts.
	since time.Time
	loads int
	// revoked maps a serial to its expiry; zero when not known yet.
	revoked map[string]time.Time
	// known and unknown map a serial to its last lookup.
	known   map[string]time.Time
	unknown map[string]time.Time
}

func newRevocationCache() revocationCache {
	return revocationCache{
		revoked: map[string]time.Time{},
		known:   map[string]time.Time{},
		unknown: map[string]time.Time{},
	}
}

// Revocation cache tuning.
const (
	// revIdle is how long a known or unknown entry is kept without
	// lookups, in refresh intervals.
	revIdle = 20
	// revFullEvery is how many refreshes pass between full loads.
	revFullEvery = 20
	// revOverlap is subtracted from the start of a load to give the next
	// incremental load's since.
	revOverlap = 5 * time.Minute
)

// IsAgentCertRevoked reports whether the agent certificate with this serial,
// or its agent, is revoked. A serial the server never issued counts as
// revoked. Revocations made on another replica take effect within one
// refresh interval. Before the first refresh, serials that are not revoked
// are looked up in the store every time. On a store error it returns true
// together with the error.
func (s *Service) IsAgentCertRevoked(ctx context.Context, serial *big.Int) (bool, error) {
	key := FormatSerial(serial)
	now := s.now()
	c := &s.rev
	c.mu.Lock()
	if _, ok := c.revoked[key]; ok {
		c.mu.Unlock()
		return true, nil
	}
	if _, ok := c.unknown[key]; ok {
		c.unknown[key] = now
		c.mu.Unlock()
		return true, nil
	}
	if _, ok := c.known[key]; ok && c.loaded {
		c.known[key] = now
		c.mu.Unlock()
		return false, nil
	}
	c.mu.Unlock()

	revoked, err := s.st.IsAgentCertRevoked(ctx, key)
	notFound := errors.Is(err, store.ErrNotFound)
	if err != nil && !notFound {
		return true, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case notFound:
		c.unknown[key] = now
		return true, nil
	case revoked:
		if _, ok := c.revoked[key]; !ok {
			c.revoked[key] = time.Time{}
		}
		return true, nil
	}
	if _, ok := c.revoked[key]; ok {
		// A refresh or NoteAgentRevoked marked it meanwhile.
		return true, nil
	}
	if c.loaded {
		c.known[key] = now
	}
	return false, nil
}

// NoteAgentRevoked marks every certificate of a revoked agent as revoked in
// this replica's cache at once. Call it after revoking the agent in the
// store.
func (s *Service) NoteAgentRevoked(ctx context.Context, agentID string) error {
	certs, err := s.st.ListAgentCerts(ctx, agentID)
	if err != nil {
		return err
	}
	c := &s.rev
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, cert := range certs {
		c.revoked[cert.Serial] = cert.NotAfter
		delete(c.known, cert.Serial)
	}
	return nil
}

// refreshRevocations loads the revoked certificates (in full or since the
// previous load), drops expired ones and forgets idle lookups.
func (s *Service) refreshRevocations(ctx context.Context) {
	c := &s.rev
	c.mu.Lock()
	full := !c.loaded || c.loads%revFullEvery == 0
	since := c.since
	c.mu.Unlock()
	if full {
		since = time.Time{}
	}

	start := s.now()
	certs, err := s.st.ListRevokedAgentCerts(ctx, since)
	if err != nil {
		if ctx.Err() == nil {
			s.log.Warn("revocation refresh failed", "full", full, "err", err)
		}
		return
	}
	idle := start.Add(-revIdle * s.cfg.RefreshInterval)

	c.mu.Lock()
	defer c.mu.Unlock()
	for _, cert := range certs {
		if cert.NotAfter.After(start) {
			c.revoked[cert.Serial] = cert.NotAfter
			delete(c.known, cert.Serial)
		}
	}
	for k, notAfter := range c.revoked {
		if !notAfter.IsZero() && !notAfter.After(start) {
			delete(c.revoked, k)
		}
	}
	for _, m := range []map[string]time.Time{c.known, c.unknown} {
		for k, used := range m {
			if used.Before(idle) {
				delete(m, k)
			}
		}
	}
	c.loaded = true
	c.loads++
	c.since = start.Add(-revOverlap)
}
