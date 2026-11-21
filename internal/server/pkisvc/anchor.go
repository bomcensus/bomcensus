// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pkisvc

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/bomcensus/bomcensus/internal/pki"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// An anchor change has two steps (SECURITY.md §4.1). PrepareAnchor adds the
// new anchor to the trust bundle and bumps its version so agents pick it up.
// ActivateAnchor switches the Agent TLS certificates to the new anchor, drops
// the old one and bumps the version again. CancelAnchor drops the prepared
// anchor.
//
// A prepared anchor is either a new internal CA (activation switches Agent
// TLS to automatic mode and issues new certificates from it) or an
// administrator-supplied certificate (activation needs manual certificates
// under it, uploaded with SetAgentManual beforehand, and switches to manual
// mode).

// PrepareAnchor prepares a new Agent TLS trust anchor. With certPEM empty a
// new internal CA is created. Otherwise certPEM holds the new anchor, or a
// chain whose topmost certificate is the new anchor.
func (s *Service) PrepareAnchor(ctx context.Context, certPEM []byte) error {
	var top *x509.Certificate
	var key crypto.Signer
	if len(certPEM) > 0 {
		certs, err := pki.ParseCertificatesPEM(certPEM)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInvalid, err)
		}
		if len(certs) == 0 {
			return invalid("no certificate given")
		}
		top = certs[len(certs)-1]
		if now := s.now(); now.Before(top.NotBefore) || now.After(top.NotAfter) {
			return invalid("the anchor certificate is not valid now (valid %s to %s)", top.NotBefore, top.NotAfter)
		}
	} else {
		ca, err := s.newCA(caNames[store.PKIAgentTLSCA])
		if err != nil {
			return err
		}
		top, key = ca.Cert, ca.Key
	}
	err := s.withTx(ctx, func(tx store.Store) error {
		anchor, err := s.get(ctx, tx, ObjAgentTLSAnchor)
		if err != nil {
			return err
		}
		if anchor != nil && pki.SPKIHash(anchor.chain[0]) == pki.SPKIHash(top) {
			return invalid("the certificate is already the current anchor")
		}
		if _, err := s.put(ctx, tx, store.PKIAgentTLSAnchorPending, []*x509.Certificate{top}, key, store.PKIStatePending, 0); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return ErrAnchorPending
			}
			return err
		}
		if err := s.removeStaged(ctx, tx); err != nil {
			return err
		}
		_, err = tx.BumpTrustBundleVersion(ctx)
		return err
	})
	if err == nil {
		s.log.Info("agent TLS anchor prepared", "spki", spkiString(top), "internal", key != nil)
	}
	return err
}

func (s *Service) removeStaged(ctx context.Context, tx store.PKI) error {
	if err := s.remove(ctx, tx, ObjAgentTLSLeafPending); err != nil {
		return err
	}
	return s.remove(ctx, tx, ObjAgentTLSClientPending)
}

// ActivateAnchor makes the prepared anchor current. Unless force is set it
// fails with ErrAgentsNotSynced while agents have not synchronized the
// bundle that contains the new anchor; those agents would lose their
// connection.
func (s *Service) ActivateAnchor(ctx context.Context, force bool) error {
	if !force {
		if s.cfg.UnsyncedAgents == nil {
			return errors.New("pkisvc: no unsynchronized agent counter configured")
		}
		n, err := s.cfg.UnsyncedAgents(ctx)
		if err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("%w: %d agents", ErrAgentsNotSynced, n)
		}
	}
	var hash [32]byte
	err := s.withTx(ctx, func(tx store.Store) error {
		pending, err := s.get(ctx, tx, store.PKIAgentTLSAnchorPending)
		if err != nil {
			return err
		}
		if pending == nil {
			return ErrNoPendingAnchor
		}
		hash = pki.SPKIHash(pending.chain[0])
		mode := store.TLSModeManual
		if pending.key != nil {
			ca, err := pki.LoadCA(pending.chain[0], pending.key)
			if err != nil {
				return err
			}
			if err := s.replace(ctx, tx, store.PKIAgentTLSCA, []*x509.Certificate{ca.Cert}, ca.Key, store.PKIStateActive); err != nil {
				return err
			}
			if err := s.issueAgentLeaves(ctx, tx, ca); err != nil {
				return err
			}
			mode = store.TLSModeAuto
		} else {
			leaf, err := s.get(ctx, tx, ObjAgentTLSLeafPending)
			if err != nil {
				return err
			}
			client, err := s.get(ctx, tx, ObjAgentTLSClientPending)
			if err != nil {
				return err
			}
			if leaf == nil || client == nil {
				return ErrNotStaged
			}
			if err := s.replace(ctx, tx, store.PKIAgentTLSLeaf, leaf.chain, leaf.key, store.PKIStateActive); err != nil {
				return err
			}
			if err := s.replace(ctx, tx, store.PKIAgentTLSClient, client.chain, client.key, store.PKIStateActive); err != nil {
				return err
			}
		}
		if err := s.replace(ctx, tx, ObjAgentTLSAnchor, pending.chain[:1], nil, store.PKIStateActive); err != nil {
			return err
		}
		if err := tx.PutTLSSetting(ctx, store.TLSSetting{Endpoint: store.TLSEndpointAgent, Mode: mode, UpdatedAt: s.now()}); err != nil {
			return err
		}
		if err := tx.DeletePKIObject(ctx, pending.name, pending.version); err != nil {
			return err
		}
		if err := s.removeStaged(ctx, tx); err != nil {
			return err
		}
		_, err = tx.BumpTrustBundleVersion(ctx)
		return err
	})
	if err == nil {
		s.log.Info("agent TLS anchor activated", "spki", SPKIString(hash), "forced", force)
	}
	return err
}

// CancelAnchor drops the prepared anchor and any certificates staged for it.
func (s *Service) CancelAnchor(ctx context.Context) error {
	err := s.withTx(ctx, func(tx store.Store) error {
		pending, err := s.get(ctx, tx, store.PKIAgentTLSAnchorPending)
		if err != nil {
			return err
		}
		if pending == nil {
			return ErrNoPendingAnchor
		}
		if err := tx.DeletePKIObject(ctx, pending.name, pending.version); err != nil {
			return err
		}
		if err := s.removeStaged(ctx, tx); err != nil {
			return err
		}
		_, err = tx.BumpTrustBundleVersion(ctx)
		return err
	})
	if err == nil {
		s.log.Info("agent TLS anchor change cancelled")
	}
	return err
}
