// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pkisvc

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/bomcensus/bomcensus/internal/pki"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// Endpoint modes reported by Status.
const (
	ModeAuto   = "auto"
	ModeManual = "manual"
	ModeOff    = "off"
)

// EndpointStatus describes the certificate of one TLS configuration.
type EndpointStatus struct {
	Mode    string
	Subject string
	Issuer  string
	Names   []string
	// ExpiresAt is the leaf expiry; zero when the endpoint is off.
	ExpiresAt time.Time
}

// PendingAnchor describes a prepared Agent TLS trust anchor.
type PendingAnchor struct {
	SPKIHash   [32]byte
	Subject    string
	ExpiresAt  time.Time
	PreparedAt time.Time
	// Internal is true when the anchor is a new internal CA; activation
	// then switches Agent TLS to automatic mode.
	Internal bool
	// Staged is true when a manual certificate under this anchor has been
	// uploaded and activation can use it.
	Staged bool
}

// Status is the state shown in the console.
type Status struct {
	Web              EndpointStatus
	Agent            EndpointStatus
	AnchorHash       [32]byte
	AgentCAExpiresAt time.Time
	BundleVersion    int64
	// UnsyncedAgents is -1 when no counter is configured.
	UnsyncedAgents int
	Pending        *PendingAnchor
}

// SPKIString formats an SPKI hash as in enrollment strings (unpadded
// base64url).
func SPKIString(h [32]byte) string { return base64.RawURLEncoding.EncodeToString(h[:]) }

func spkiString(c *x509.Certificate) string { return SPKIString(pki.SPKIHash(c)) }

func endpointStatus(mode store.TLSMode, chain []*x509.Certificate) EndpointStatus {
	st := EndpointStatus{Mode: string(mode), Names: []string{}}
	if len(chain) > 0 {
		leaf := chain[0]
		st.Subject = leaf.Subject.String()
		st.Issuer = leaf.Issuer.String()
		st.Names = certNames(leaf)
		st.ExpiresAt = leaf.NotAfter
	}
	return st
}

// Status reloads the snapshot and describes it.
func (s *Service) Status(ctx context.Context) (Status, error) {
	if err := s.Refresh(ctx); err != nil {
		return Status{}, err
	}
	sn, err := s.current()
	if err != nil {
		return Status{}, err
	}
	out := Status{
		Agent:            endpointStatus(sn.agentMode, sn.agentChain),
		AnchorHash:       pki.SPKIHash(sn.anchor),
		AgentCAExpiresAt: sn.agentCA.Cert.NotAfter,
		BundleVersion:    sn.bundleVersion,
		UnsyncedAgents:   -1,
	}
	if s.cfg.WebTLS {
		out.Web = endpointStatus(sn.webMode, sn.webChain)
	} else {
		out.Web = EndpointStatus{Mode: ModeOff, Names: []string{}}
	}
	if s.cfg.UnsyncedAgents != nil {
		if out.UnsyncedAgents, err = s.cfg.UnsyncedAgents(ctx); err != nil {
			return Status{}, err
		}
	}
	if p := sn.pending; p != nil {
		staged, err := s.get(ctx, s.st, ObjAgentTLSLeafPending)
		if err != nil {
			return Status{}, err
		}
		out.Pending = &PendingAnchor{
			SPKIHash:   pki.SPKIHash(p.chain[0]),
			Subject:    p.chain[0].Subject.String(),
			ExpiresAt:  p.chain[0].NotAfter,
			PreparedAt: p.createdAt,
			Internal:   p.key != nil,
			Staged:     staged != nil,
		}
	}
	return out, nil
}

// withTx runs fn in a transaction, retrying a few times when a versioned
// write lost against another replica, and reloads the snapshot afterwards.
func (s *Service) withTx(ctx context.Context, fn func(tx store.Store) error) error {
	var err error
	for range 3 {
		err = s.st.WithTx(ctx, fn)
		if !errors.Is(err, store.ErrConflict) {
			break
		}
	}
	if err != nil {
		return err
	}
	return s.Refresh(ctx)
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// SetWebAuto switches Web/API TLS to automatic mode and issues a new
// certificate from the internal web CA, creating the CA when needed.
func (s *Service) SetWebAuto(ctx context.Context) error {
	if !s.cfg.WebTLS {
		return ErrWebTLSOff
	}
	return s.withTx(ctx, func(tx store.Store) error {
		ca, err := s.ensureCA(ctx, tx, store.PKIWebCA)
		if err != nil {
			return err
		}
		chain, key, err := s.issueLeaf(ca, x509.ExtKeyUsageServerAuth, s.cfg.WebServerNames)
		if err != nil {
			return err
		}
		if err := s.replace(ctx, tx, store.PKIWebLeaf, chain, key, store.PKIStateActive); err != nil {
			return err
		}
		return tx.PutTLSSetting(ctx, store.TLSSetting{Endpoint: store.TLSEndpointWeb, Mode: store.TLSModeAuto, UpdatedAt: s.now()})
	})
}

// SetWebManual validates an administrator-supplied chain (leaf first) and
// key and makes it the Web/API certificate.
func (s *Service) SetWebManual(ctx context.Context, chainPEM, keyPEM []byte) error {
	if !s.cfg.WebTLS {
		return ErrWebTLSOff
	}
	pair, err := pki.ParseManualPair(chainPEM, keyPEM, x509.ExtKeyUsageServerAuth, s.now())
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	err = s.withTx(ctx, func(tx store.Store) error {
		if err := s.replace(ctx, tx, store.PKIWebLeaf, pair.Chain, pair.Key, store.PKIStateActive); err != nil {
			return err
		}
		return tx.PutTLSSetting(ctx, store.TLSSetting{Endpoint: store.TLSEndpointWeb, Mode: store.TLSModeManual, UpdatedAt: s.now()})
	})
	if err == nil {
		s.log.Info("web TLS certificate replaced", "mode", ModeManual, "subject", pair.Chain[0].Subject.String(), "expires_at", pair.NotAfter)
	}
	return err
}

// SetAgentAuto switches Agent TLS to automatic mode and reissues both
// certificates from the internal Agent TLS CA. The internal CA must be the
// current trust anchor, otherwise enrolled agents would stop trusting the
// server; ErrAnchorMismatch then (prepare and activate a new internal anchor
// instead).
func (s *Service) SetAgentAuto(ctx context.Context) error {
	return s.withTx(ctx, func(tx store.Store) error {
		ca, err := s.loadCA(ctx, tx, store.PKIAgentTLSCA)
		if err != nil {
			return err
		}
		anchor, err := s.get(ctx, tx, ObjAgentTLSAnchor)
		if err != nil {
			return err
		}
		if ca == nil || anchor == nil || pki.SPKIHash(ca.Cert) != pki.SPKIHash(anchor.chain[0]) {
			return fmt.Errorf("%w: the internal Agent TLS CA is not the current trust anchor; prepare and activate a new internal anchor instead", ErrAnchorMismatch)
		}
		if err := s.issueAgentLeaves(ctx, tx, ca); err != nil {
			return err
		}
		return tx.PutTLSSetting(ctx, store.TLSSetting{Endpoint: store.TLSEndpointAgent, Mode: store.TLSModeAuto, UpdatedAt: s.now()})
	})
}

func (s *Service) issueAgentLeaves(ctx context.Context, tx store.PKI, ca *pki.CA) error {
	chain, key, err := s.issueLeaf(ca, x509.ExtKeyUsageServerAuth, s.cfg.AgentServerNames)
	if err != nil {
		return err
	}
	if err := s.replace(ctx, tx, store.PKIAgentTLSLeaf, chain, key, store.PKIStateActive); err != nil {
		return err
	}
	chain, key, err = s.issueLeaf(ca, x509.ExtKeyUsageClientAuth, s.cfg.AgentServerNames)
	if err != nil {
		return err
	}
	return s.replace(ctx, tx, store.PKIAgentTLSClient, chain, key, store.PKIStateActive)
}

func chainHas(chain []*x509.Certificate, h [32]byte) bool {
	for _, c := range chain {
		if pki.SPKIHash(c) == h {
			return true
		}
	}
	return false
}

// SetAgentManual validates administrator-supplied Agent TLS certificates and
// stores them. chainPEM/keyPEM is the server certificate. clientChainPEM and
// clientKeyPEM are the client certificate presented to listen-mode agents;
// when both are empty the server certificate is used and must allow client
// authentication too.
//
// Both chains must contain the current trust anchor: they take effect at
// once. If they contain the prepared anchor instead, they are staged and take
// effect when the anchor change is activated (staged is true). Otherwise the
// result is ErrAnchorMismatch.
func (s *Service) SetAgentManual(ctx context.Context, chainPEM, keyPEM, clientChainPEM, clientKeyPEM []byte) (staged bool, err error) {
	now := s.now()
	server, err := pki.ParseManualPair(chainPEM, keyPEM, x509.ExtKeyUsageServerAuth, now)
	if err != nil {
		return false, fmt.Errorf("%w: server certificate: %w", ErrInvalid, err)
	}
	var client *pki.ManualPair
	switch {
	case len(clientChainPEM) > 0 && len(clientKeyPEM) > 0:
		if client, err = pki.ParseManualPair(clientChainPEM, clientKeyPEM, x509.ExtKeyUsageClientAuth, now); err != nil {
			return false, fmt.Errorf("%w: client certificate: %w", ErrInvalid, err)
		}
	case len(clientChainPEM) > 0 || len(clientKeyPEM) > 0:
		return false, invalid("the client certificate chain and its private key must be given together")
	default:
		if client, err = pki.ValidatePair(server.Chain, server.Key, x509.ExtKeyUsageClientAuth, now); err != nil {
			return false, invalid("the server certificate does not allow client authentication, which the server needs to dial listen-mode agents; supply a separate client certificate under the same trust anchor")
		}
	}

	err = s.withTx(ctx, func(tx store.Store) error {
		staged = false
		anchor, err := s.get(ctx, tx, ObjAgentTLSAnchor)
		if err != nil {
			return err
		}
		if anchor == nil {
			return fmt.Errorf("pkisvc: %s is missing", ObjAgentTLSAnchor)
		}
		pending, err := s.get(ctx, tx, store.PKIAgentTLSAnchorPending)
		if err != nil {
			return err
		}
		cur := pki.SPKIHash(anchor.chain[0])
		switch {
		case chainHas(server.Chain, cur) && chainHas(client.Chain, cur):
			if err := s.replace(ctx, tx, store.PKIAgentTLSLeaf, server.Chain, server.Key, store.PKIStateActive); err != nil {
				return err
			}
			if err := s.replace(ctx, tx, store.PKIAgentTLSClient, client.Chain, client.Key, store.PKIStateActive); err != nil {
				return err
			}
			return tx.PutTLSSetting(ctx, store.TLSSetting{Endpoint: store.TLSEndpointAgent, Mode: store.TLSModeManual, UpdatedAt: s.now()})
		case pending != nil && chainHas(server.Chain, pki.SPKIHash(pending.chain[0])) && chainHas(client.Chain, pki.SPKIHash(pending.chain[0])):
			staged = true
			if err := s.replace(ctx, tx, ObjAgentTLSLeafPending, server.Chain, server.Key, store.PKIStatePending); err != nil {
				return err
			}
			return s.replace(ctx, tx, ObjAgentTLSClientPending, client.Chain, client.Key, store.PKIStatePending)
		default:
			return fmt.Errorf("%w: neither chain contains a certificate whose SPKI hash is the current (or prepared) anchor %s", ErrAnchorMismatch, SPKIString(cur))
		}
	})
	if err == nil {
		s.log.Info("agent TLS certificate replaced", "mode", ModeManual, "staged", staged, "subject", server.Chain[0].Subject.String(), "expires_at", server.NotAfter)
	}
	return staged, err
}
