// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package core

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/bomcensus/bomcensus/internal/agent/state"
	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/pki"
)

// bundleFromAPI converts and validates a trust bundle of the protocol.
// The bundle format of internal/pki has a single Agent CA; the first entry
// of agent_cas is used.
func bundleFromAPI(tb agentapi.TrustBundle) (*pki.TrustBundle, error) {
	if tb.Serial < 0 {
		return nil, errors.New("trust bundle: negative serial")
	}
	out := &pki.TrustBundle{Version: uint64(tb.Serial)}
	for i, der := range tb.Anchors {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("trust bundle: anchor %d: %w", i, err)
		}
		out.Anchors = append(out.Anchors, c)
	}
	if len(tb.AgentCas) == 0 {
		return nil, errors.New("trust bundle: no Agent CA")
	}
	ca, err := x509.ParseCertificate(tb.AgentCas[0])
	if err != nil {
		return nil, fmt.Errorf("trust bundle: Agent CA: %w", err)
	}
	out.AgentCA = ca
	if err := out.Validate(); err != nil {
		return nil, err
	}
	return out, nil
}

// checkAgentCert verifies an issued certificate: it belongs to key and
// agentID and chains to the Agent CA.
func checkAgentCert(certDER, caDER []byte, key ed25519.PrivateKey, agentID string) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("agent certificate: %w", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("Agent CA: %w", err)
	}
	if !pki.KeyMatches(cert, key) {
		return nil, errors.New("agent certificate is not for the identity key")
	}
	id, err := pki.VerifyAgent([]*x509.Certificate{cert}, ca, x509.ExtKeyUsageClientAuth)
	if err != nil {
		return nil, err
	}
	if id != agentID {
		return nil, fmt.Errorf("agent certificate is for %q, not %q", id, agentID)
	}
	return cert, nil
}

// acceptResult validates an approved enrollment result for key and stores
// identity, trust bundle and enrollment (in that order, so the enrollment
// record is written last).
func acceptResult(st *state.Dir, enr *state.Enrollment, key ed25519.PrivateKey, res agentapi.EnrollResult) (*state.Identity, *pki.TrustBundle, error) {
	if res.AgentId != enr.AgentID {
		return nil, nil, fmt.Errorf("enrollment result is for %q, not %q", res.AgentId, enr.AgentID)
	}
	if res.Certificate == nil || res.AgentCa == nil || res.TrustBundle == nil {
		return nil, nil, errors.New("approved enrollment result is incomplete")
	}
	cert, err := checkAgentCert(*res.Certificate, *res.AgentCa, key, enr.AgentID)
	if err != nil {
		return nil, nil, err
	}
	tb, err := bundleFromAPI(*res.TrustBundle)
	if err != nil {
		return nil, nil, err
	}
	id := &state.Identity{Key: key, Cert: cert}
	if err := st.SaveIdentity(id); err != nil {
		return nil, nil, err
	}
	if err := st.SaveTrustBundle(tb); err != nil {
		return nil, nil, err
	}
	enr.Status = state.StatusApproved
	if err := st.SaveEnrollment(enr); err != nil {
		return nil, nil, err
	}
	return id, tb, nil
}

// waitApproved polls GET /enroll/result until the enrollment is approved.
func (r *Runtime) waitApproved(ctx context.Context) error {
	r.log.Info("enrollment is pending approval", "agent_id", r.AgentID())
	var backoff time.Duration
	for {
		wait := r.opts.PendingInterval
		resp, err := r.client.GetEnrollResultWithResponse(ctx)
		var res agentapi.EnrollResult
		if err == nil {
			err = DecodeResponse(resp.HTTPResponse, resp.Body, http.StatusOK, &res)
		}
		if err == nil {
			backoff = 0
			switch res.Status {
			case agentapi.EnrollStatusApproved:
				enr := r.Enrollment()
				id, tb, err := acceptResult(r.st, &enr, r.identity().Key, res)
				if err != nil {
					return fmt.Errorf("enrollment result: %w", err)
				}
				r.mu.Lock()
				r.enr = enr
				r.bundle = tb
				r.mu.Unlock()
				r.setIdentity(id)
				r.lc.reset()
				r.log.Info("enrollment approved", "agent_id", enr.AgentID)
				return nil
			case agentapi.EnrollStatusRejected:
				return ErrNotApproved
			}
			if res.RetryAfterSeconds != nil && *res.RetryAfterSeconds > 0 {
				wait = time.Duration(*res.RetryAfterSeconds) * time.Second
			}
		} else {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			backoff = nextBackoff(backoff, r.opts.MaxBackoff)
			wait = backoff
			r.log.Warn("enrollment result request failed", "error", err, "retry_in", wait)
		}
		if !sleep(ctx, wait) {
			return ctx.Err()
		}
	}
}

// renewIfDue renews the certificate after two thirds of its lifetime.
func (r *Runtime) renewIfDue(ctx context.Context) error {
	c := r.Certificate()
	if c == nil {
		return nil
	}
	due := c.NotBefore.Add(c.NotAfter.Sub(c.NotBefore) * 2 / 3)
	if r.opts.Now().Before(due) {
		return nil
	}
	return r.RenewCert(ctx, false)
}

func (r *Runtime) handleRenew(ctx context.Context, d agentapi.Directive) error {
	rd, err := d.AsRenewCertDirective()
	if err != nil {
		return err
	}
	return r.RenewCert(ctx, rd.NewKey)
}

// RenewCert obtains a new certificate, for the current identity key or,
// with newKey, for a fresh key that then becomes the identity key. The new
// key is stored before the request so that it is not lost when the
// response is.
func (r *Runtime) RenewCert(ctx context.Context, newKey bool) error {
	r.renewMu.Lock()
	defer r.renewMu.Unlock()
	if err := r.recoverNextKeyLocked(ctx); err != nil {
		return err
	}
	key := r.identity().Key
	var body agentapi.CertRenewRequest
	if newKey {
		k, err := pki.GenerateAgentKey()
		if err != nil {
			return err
		}
		csr, err := pki.CreateAgentCSR(k)
		if err != nil {
			return err
		}
		if err := r.st.SaveNextKey(k); err != nil {
			return err
		}
		key = k
		body.Csr = &csr
	}
	resp, err := r.client.RenewCertWithResponse(ctx, body)
	var rc agentapi.RenewedCert
	if err == nil {
		err = DecodeResponse(resp.HTTPResponse, resp.Body, http.StatusOK, &rc)
	}
	if err != nil {
		var ae *APIError
		if newKey && errors.As(err, &ae) {
			// A signed refusal: the server did not switch keys.
			_ = r.st.RemoveNextKey()
		}
		return fmt.Errorf("renew certificate: %w", err)
	}
	if err := r.adopt(key, rc); err != nil {
		return err
	}
	r.log.Info("certificate renewed", "new_key", newKey, "not_after", rc.NotAfter)
	return nil
}

func (r *Runtime) adopt(key ed25519.PrivateKey, rc agentapi.RenewedCert) error {
	cert, err := checkAgentCert(rc.Certificate, rc.AgentCa, key, r.AgentID())
	if err != nil {
		return fmt.Errorf("renewed certificate: %w", err)
	}
	id := &state.Identity{Key: key, Cert: cert}
	if err := r.st.SaveIdentity(id); err != nil {
		return err
	}
	if err := r.st.RemoveNextKey(); err != nil {
		return err
	}
	r.setIdentity(id)
	return nil
}

func (r *Runtime) recoverNextKey(ctx context.Context) error {
	r.renewMu.Lock()
	defer r.renewMu.Unlock()
	return r.recoverNextKeyLocked(ctx)
}

// recoverNextKeyLocked resolves a key change interrupted before its result
// was stored: if the server accepts a renewal signed with the new key, the
// server had switched and the new key is adopted; if it refuses the
// signature, the old key is still valid and the new one is dropped.
func (r *Runtime) recoverNextKeyLocked(ctx context.Context) error {
	nk, err := r.st.LoadNextKey()
	if err != nil || nk == nil {
		return err
	}
	c, err := r.clientWithKey(nk)
	if err != nil {
		return err
	}
	resp, err := c.RenewCertWithResponse(ctx, agentapi.CertRenewRequest{})
	var rc agentapi.RenewedCert
	if err == nil {
		err = DecodeResponse(resp.HTTPResponse, resp.Body, http.StatusOK, &rc)
	}
	switch {
	case err == nil:
		r.log.Info("adopting identity key of an interrupted key change")
		return r.adopt(nk, rc)
	case IsStatus(err, http.StatusUnauthorized):
		r.log.Info("discarding identity key of an interrupted key change")
		return r.st.RemoveNextKey()
	}
	return err
}

func (r *Runtime) handleSyncTrustBundle(ctx context.Context, d agentapi.Directive) error {
	sd, err := d.AsSyncTrustBundleDirective()
	if err != nil {
		return err
	}
	if b := r.TrustBundle(); b != nil && sd.Serial > 0 && uint64(sd.Serial) <= b.Version {
		return nil
	}
	return r.SyncTrustBundle(ctx)
}

// SyncTrustBundle fetches the trust bundle and stores it when its serial
// is higher than the current one.
func (r *Runtime) SyncTrustBundle(ctx context.Context) error {
	resp, err := r.client.GetTrustBundleWithResponse(ctx)
	if err != nil {
		return err
	}
	var tb agentapi.TrustBundle
	if err := DecodeResponse(resp.HTTPResponse, resp.Body, http.StatusOK, &tb); err != nil {
		return err
	}
	nb, err := bundleFromAPI(tb)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.bundle != nil && nb.Version <= r.bundle.Version {
		return nil
	}
	if err := r.st.SaveTrustBundle(nb); err != nil {
		return err
	}
	r.bundle = nb
	r.log.Info("trust bundle updated", "serial", nb.Version, "anchors", len(nb.Anchors))
	return nil
}
