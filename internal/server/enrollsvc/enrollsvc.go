// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package enrollsvc implements the server side of agent enrollment
// (SECURITY §4.3 to §4.5): the enroll/start and enroll/finish exchange on
// top of internal/enroll, the Register Key policy, the result of a pending
// enrollment and certificate renewal.
//
// Start and Finish work on exact HTTP body bytes, because the enrollment
// signatures cover hashes of those bytes (docs/PROTOCOL.md §2).
package enrollsvc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/bomcensus/bomcensus/internal/enroll"

	"github.com/bomcensus/bomcensus/agentproto/dto"
	"github.com/bomcensus/bomcensus/internal/pki"
	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/internal/token"
)

// Errors returned to the HTTP layer. Every policy failure is ErrRefused;
// the precise reason is only logged.
var (
	// ErrBadRequest is a malformed request body.
	ErrBadRequest = errors.New("enrollsvc: malformed request")
	// ErrRefused is the uniform answer to an enrollment that is not allowed.
	ErrRefused = errors.New("enrollsvc: enrollment refused")
	// ErrRateLimited means too many recent failures for the Register Key.
	ErrRateLimited = errors.New("enrollsvc: too many failed attempts")
	// ErrKeyMismatch is a renewal CSR for another key than the identity key.
	ErrKeyMismatch = errors.New("enrollsvc: CSR is not for the identity key")
)

// RateLimitError carries the time after which a rate-limited key may try
// again. It matches ErrRateLimited with errors.Is.
type RateLimitError struct{ RetryAfter time.Duration }

func (e *RateLimitError) Error() string        { return ErrRateLimited.Error() }
func (e *RateLimitError) Is(target error) bool { return target == ErrRateLimited }

// PKI is what enrollment needs from the server's certificate service
// (satisfied by *pkisvc.Service).
type PKI interface {
	// Signer returns the key the server signs enrollment exchanges with and
	// its certificate chain up to the trust anchor (leaf first): the Agent
	// TLS server certificate. Both are nil while none is available.
	Signer() (crypto.Signer, []*x509.Certificate)
	// IssueAgentCertificate issues an agent certificate for the key in the
	// DER CSR with the Agent CA and records it (store.AgentCerts) for
	// revocation checks.
	IssueAgentCertificate(ctx context.Context, csrDER []byte, agentID string) (*x509.Certificate, error)
	// AgentCA returns the current Agent CA certificate.
	AgentCA() (*x509.Certificate, error)
	// TrustBundle returns the current trust bundle.
	TrustBundle() (*pki.TrustBundle, error)
}

// Options configures New.
type Options struct {
	Store  store.Store
	PKI    PKI
	Logger *slog.Logger
	// SessionTTL is the lifetime of an enrollment session (default 5 min).
	SessionTTL time.Duration
	// MaxFailures failures of one key id within FailureWindow block further
	// attempts with that key id until the window ends (defaults 10, 10 min).
	MaxFailures   int
	FailureWindow time.Duration
	// PendingRetry is the suggested polling interval of a pending agent
	// (default 10 s). It bounds how long a manual approval takes to reach
	// the agent.
	PendingRetry time.Duration
	Now          func() time.Time
}

// Service is the enrollment state machine.
type Service struct {
	st      store.Store
	pki     PKI
	log     *slog.Logger
	ttl     time.Duration
	retry   time.Duration
	now     func() time.Time
	limiter *limiter
}

// New returns a Service.
func New(o Options) (*Service, error) {
	if o.Store == nil || o.PKI == nil {
		return nil, errors.New("enrollsvc: store and PKI are required")
	}
	s := &Service{st: o.Store, pki: o.PKI, log: o.Logger, ttl: o.SessionTTL, retry: o.PendingRetry, now: o.Now}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.ttl <= 0 {
		s.ttl = 5 * time.Minute
	}
	if s.retry <= 0 {
		s.retry = 10 * time.Second
	}
	if s.now == nil {
		s.now = time.Now
	}
	s.limiter = newLimiter(o.MaxFailures, o.FailureWindow)
	return s, nil
}

// MaxBodySize bounds enroll/start and enroll/finish bodies.
const MaxBodySize = 64 << 10

// sessionState is what the store keeps between start and finish.
type sessionState struct {
	Transcript enroll.Transcript `json:"transcript"`
	Request    []byte            `json:"request"`
	Remote     string            `json:"remote"`
	Reverse    bool              `json:"reverse"`
}

// startRequest is a validated enroll/start body.
type startRequest struct {
	dto.EnrollStartRequest
	csr      *x509.CertificateRequest
	identity ed25519.PublicKey
}

func parseStart(body []byte) (*startRequest, error) {
	var r startRequest
	if err := json.Unmarshal(body, &r.EnrollStartRequest); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	if _, err := token.ParseKeyID(r.KeyId); err != nil {
		return nil, fmt.Errorf("%w: key_id", ErrBadRequest)
	}
	if len(r.AgentNonce) != 32 {
		return nil, fmt.Errorf("%w: agent_nonce must be 32 bytes", ErrBadRequest)
	}
	if !r.Kind.Valid() || !r.ConnectMode.Valid() || !r.TlsMode.Valid() {
		return nil, fmt.Errorf("%w: kind, connect_mode or tls_mode", ErrBadRequest)
	}
	if r.Host.Hostname == "" || r.Host.Arch == "" || r.Host.Os.Family == "" {
		return nil, fmt.Errorf("%w: host facts", ErrBadRequest)
	}
	csr, err := pki.ParseAgentCSR(r.Csr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	r.csr = csr
	r.identity = csr.PublicKey.(ed25519.PublicKey)
	return &r, nil
}

// refusal is a policy failure with the reason that is logged.
type refusal struct{ reason string }

func (r *refusal) Error() string { return r.reason }

func refuse(format string, args ...any) error { return &refusal{reason: fmt.Sprintf(format, args...)} }

// checkPolicy applies the Register Key policy of SECURITY §4.4 to a start
// request. It returns the key, a *refusal, or another error.
func (s *Service) checkPolicy(ctx context.Context, req *startRequest, remote netip.Addr, reverse bool) (store.RegisterKey, error) {
	key, err := s.st.GetRegisterKey(ctx, req.KeyId)
	if errors.Is(err, store.ErrNotFound) {
		return key, refuse("unknown register key")
	}
	if err != nil {
		return key, err
	}
	if err := key.Usable(s.now()); err != nil {
		return key, refuse("%v", err)
	}
	if string(key.Target) != string(req.Kind) {
		return key, refuse("register key is for kind %s, request is %s", key.Target, req.Kind)
	}
	if !remote.IsValid() || !key.AllowsAddr(remote) {
		return key, refuse("source address %s is not allowed", remote)
	}
	listen := req.ConnectMode == dto.Listen
	if listen != reverse {
		return key, refuse("connect mode %s does not match the connection direction", req.ConnectMode)
	}
	if listen && req.Kind == dto.Scanner {
		return key, refuse("scanners support connect mode only")
	}
	if req.TlsMode != dto.Pinned {
		if !key.AllowRelaxedTLS {
			return key, refuse("register key does not allow TLS mode %s", req.TlsMode)
		}
		if listen {
			return key, refuse("relaxed TLS modes are defined for connect mode only")
		}
	}
	if _, err := s.st.GetAgentByIdentityKey(ctx, req.identity); err == nil {
		return key, refuse("identity key is already enrolled")
	} else if !errors.Is(err, store.ErrNotFound) {
		return key, err
	}
	return key, nil
}

// fail logs a failed attempt, counts it for the key id and maps it to the
// error returned to the caller.
func (s *Service) fail(ctx context.Context, step, keyID string, remote netip.Addr, err error) error {
	var rf *refusal
	switch {
	case errors.As(err, &rf):
		s.limiter.fail(keyID, s.now())
		s.log.WarnContext(ctx, "enrollment refused", "step", step, "key_id", keyID, "remote", remote.String(), "reason", rf.reason)
		return ErrRefused
	case errors.Is(err, ErrBadRequest):
		s.limiter.fail(keyID, s.now())
		s.log.WarnContext(ctx, "enrollment request rejected", "step", step, "key_id", keyID, "remote", remote.String(), "error", err)
		return err
	case errors.Is(err, ErrRateLimited):
		s.log.WarnContext(ctx, "enrollment rate limited", "step", step, "key_id", keyID, "remote", remote.String())
		return err
	default:
		s.log.ErrorContext(ctx, "enrollment failed", "step", step, "key_id", keyID, "remote", remote.String(), "error", err)
		return fmt.Errorf("enrollsvc: %s: %w", step, err)
	}
}

func (s *Service) serverKey() ([][]byte, crypto.Signer, error) {
	key, chain := s.pki.Signer()
	if key == nil || len(chain) == 0 {
		return nil, nil, errors.New("no server signing key")
	}
	der := make([][]byte, 0, len(chain))
	for _, c := range chain {
		der = append(der, c.Raw)
	}
	return der, key, nil
}

// Start handles enroll/start. body is the exact request body and remote the
// TCP peer address (in listen mode the address the server dialed). reverse
// tells that the request arrived on a reverse connection. It returns the
// exact response body and the Bomcensus-Enroll-Signature header value.
func (s *Service) Start(ctx context.Context, body []byte, remote netip.Addr, reverse bool) ([]byte, string, error) {
	remote = remote.Unmap()
	req, err := parseStart(body)
	if err != nil {
		keyID := ""
		if req != nil {
			keyID = req.KeyId
		}
		return nil, "", s.fail(ctx, "start", keyID, remote, err)
	}
	if err := s.limiter.check(req.KeyId, s.now()); err != nil {
		return nil, "", s.fail(ctx, "start", req.KeyId, remote, err)
	}
	if _, err := s.checkPolicy(ctx, req, remote, reverse); err != nil {
		return nil, "", s.fail(ctx, "start", req.KeyId, remote, err)
	}

	chain, key, err := s.serverKey()
	if err != nil {
		return nil, "", s.fail(ctx, "start", req.KeyId, remote, err)
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", s.fail(ctx, "start", req.KeyId, remote, err)
	}
	sessionID := uuid.NewString() // random (v4): handed to an unauthenticated peer
	resp, err := json.Marshal(dto.EnrollSession{SessionId: sessionID, ServerNonce: nonce, ServerChain: chain})
	if err != nil {
		return nil, "", s.fail(ctx, "start", req.KeyId, remote, err)
	}
	tr := enroll.NewTranscript(body, resp)
	sig, err := enroll.SignServerStart(key, tr)
	if err != nil {
		return nil, "", s.fail(ctx, "start", req.KeyId, remote, err)
	}
	state, err := json.Marshal(sessionState{Transcript: tr, Request: body, Remote: remote.String(), Reverse: reverse})
	if err != nil {
		return nil, "", s.fail(ctx, "start", req.KeyId, remote, err)
	}
	now := s.now().UTC()
	if _, err := s.st.CreateEnrollSession(ctx, store.EnrollSession{ID: sessionID, State: state, CreatedAt: now, ExpiresAt: now.Add(s.ttl)}); err != nil {
		return nil, "", s.fail(ctx, "start", req.KeyId, remote, err)
	}
	s.log.InfoContext(ctx, "enrollment started", "key_id", req.KeyId, "remote", remote.String(),
		"kind", req.Kind, "hostname", req.Host.Hostname, "connect_mode", req.ConnectMode, "tls_mode", req.TlsMode)
	return resp, sig, nil
}

// Finish handles enroll/finish: it verifies the Register Key signature,
// consumes a use of the key and creates the agent in one transaction, and
// issues the certificate when the key approves automatically. It returns
// the exact response body and the Bomcensus-Enroll-Signature header value.
func (s *Service) Finish(ctx context.Context, body []byte, remote netip.Addr) ([]byte, string, error) {
	remote = remote.Unmap()
	var fin dto.EnrollFinishRequest
	if err := json.Unmarshal(body, &fin); err != nil || fin.SessionId == "" {
		return nil, "", s.fail(ctx, "finish", "", remote, fmt.Errorf("%w: finish body", ErrBadRequest))
	}
	sess, err := s.st.TakeEnrollSession(ctx, fin.SessionId, s.now())
	if errors.Is(err, store.ErrNotFound) {
		return nil, "", s.fail(ctx, "finish", "", remote, refuse("unknown, expired or used session"))
	}
	if err != nil {
		return nil, "", s.fail(ctx, "finish", "", remote, err)
	}
	var st sessionState
	if err := json.Unmarshal(sess.State, &st); err != nil {
		return nil, "", s.fail(ctx, "finish", "", remote, fmt.Errorf("session state: %w", err))
	}
	req, err := parseStart(st.Request)
	if err != nil {
		return nil, "", s.fail(ctx, "finish", "", remote, fmt.Errorf("session request: %w", err))
	}
	keyID := req.KeyId
	if err := s.limiter.check(keyID, s.now()); err != nil {
		return nil, "", s.fail(ctx, "finish", keyID, remote, err)
	}
	if st.Remote != remote.String() {
		return nil, "", s.fail(ctx, "finish", keyID, remote, refuse("finish from %s, start was from %s", remote, st.Remote))
	}
	key, err := s.st.GetRegisterKey(ctx, keyID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, "", s.fail(ctx, "finish", keyID, remote, refuse("unknown register key"))
	}
	if err != nil {
		return nil, "", s.fail(ctx, "finish", keyID, remote, err)
	}
	// The signature is verified before the key policy is evaluated.
	if err := enroll.VerifyAgent(key.PublicKey, st.Transcript, fin.Signature); err != nil {
		return nil, "", s.fail(ctx, "finish", keyID, remote, refuse("%v", err))
	}
	if _, err := s.checkPolicy(ctx, req, remote, st.Reverse); err != nil {
		return nil, "", s.fail(ctx, "finish", keyID, remote, err)
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	var agent store.Agent
	err = s.st.WithTx(ctx, func(tx store.Store) error {
		k, err := tx.ConsumeRegisterKey(ctx, keyID, now)
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrRegisterKeyRevoked) ||
			errors.Is(err, store.ErrRegisterKeyExpired) || errors.Is(err, store.ErrRegisterKeyExhausted) {
			return refuse("%v", err)
		}
		if err != nil {
			return err
		}
		state := store.AgentApproved
		if k.Approval == store.ApprovalManual {
			state = store.AgentPending
		}
		a := store.Agent{
			Kind:          store.AgentKind(req.Kind),
			Hostname:      req.Host.Hostname,
			IdentityKey:   req.identity,
			RegisterKeyID: k.ID,
			State:         state,
			Version:       req.Version,
			OS:            req.Host.Os.Family,
			Arch:          req.Host.Arch,
			ConnectMode:   store.ConnectMode(req.ConnectMode),
			TLSMode:       store.TLSVerifyMode(req.TlsMode),
			Address:       remote.String(),
			EnrolledAt:    now,
		}
		if req.HpkePublicKey != nil {
			a.HPKEPublicKey = *req.HpkePublicKey
		}
		if req.ListenAddress != nil {
			a.ListenAddress = *req.ListenAddress
		}
		agent, err = tx.CreateAgent(ctx, a)
		if errors.Is(err, store.ErrConflict) {
			return refuse("identity key is already enrolled")
		}
		if err != nil {
			return err
		}
		return tx.PutAgentEnrollment(ctx, store.AgentEnrollment{
			AgentID:         agent.ID,
			CSR:             req.Csr,
			AllowRelaxedTLS: k.AllowRelaxedTLS,
			DefaultGroup:    k.DefaultGroup,
			DefaultTags:     k.DefaultTags,
			CreatedAt:       now,
		})
	})
	if err != nil {
		return nil, "", s.fail(ctx, "finish", keyID, remote, err)
	}

	var result dto.EnrollResult
	if agent.State == store.AgentApproved {
		result, err = s.approved(ctx, agent.ID, req.Csr)
		if err != nil {
			// The agent exists; it can fetch its certificate later with
			// GET /enroll/result.
			return nil, "", s.fail(ctx, "finish", keyID, remote, err)
		}
	} else {
		result = s.pending(agent.ID)
	}
	resp, err := json.Marshal(result)
	if err != nil {
		return nil, "", s.fail(ctx, "finish", keyID, remote, err)
	}
	_, signer, err := s.serverKey()
	if err != nil {
		return nil, "", s.fail(ctx, "finish", keyID, remote, err)
	}
	sig, err := enroll.SignResult(signer, st.Transcript, resp)
	if err != nil {
		return nil, "", s.fail(ctx, "finish", keyID, remote, err)
	}
	s.log.InfoContext(ctx, "enrollment finished", "key_id", keyID, "remote", remote.String(),
		"agent_id", agent.ID, "kind", agent.Kind, "status", agent.State, "hostname", agent.Hostname)
	return resp, sig, nil
}

func (s *Service) pending(agentID string) dto.EnrollResult {
	retry := int(s.retry / time.Second)
	return dto.EnrollResult{Status: dto.EnrollStatusPending, AgentId: agentID, RetryAfterSeconds: &retry}
}

// approved issues a certificate and builds the approved result.
func (s *Service) approved(ctx context.Context, agentID string, csrDER []byte) (dto.EnrollResult, error) {
	cert, err := s.pki.IssueAgentCertificate(ctx, csrDER, agentID)
	if err != nil {
		return dto.EnrollResult{}, fmt.Errorf("issue certificate: %w", err)
	}
	ca, err := s.pki.AgentCA()
	if err != nil {
		return dto.EnrollResult{}, fmt.Errorf("agent CA: %w", err)
	}
	tb, err := s.TrustBundle(ctx)
	if err != nil {
		return dto.EnrollResult{}, err
	}
	der, caDER := cert.Raw, ca.Raw
	return dto.EnrollResult{
		Status:      dto.EnrollStatusApproved,
		AgentId:     agentID,
		Certificate: &der,
		AgentCa:     &caDER,
		TrustBundle: &tb,
	}, nil
}

// TrustBundle returns the current trust bundle in its wire form.
func (s *Service) TrustBundle(ctx context.Context) (dto.TrustBundle, error) {
	b, err := s.pki.TrustBundle()
	if err != nil {
		return dto.TrustBundle{}, fmt.Errorf("trust bundle: %w", err)
	}
	if err := b.Validate(); err != nil {
		return dto.TrustBundle{}, fmt.Errorf("trust bundle: %w", err)
	}
	out := dto.TrustBundle{
		Serial:   int64(b.Version),
		Anchors:  make([][]byte, 0, len(b.Anchors)),
		AgentCas: [][]byte{b.AgentCA.Raw},
		IssuedAt: s.now().UTC().Truncate(time.Second),
	}
	for _, a := range b.Anchors {
		out.Anchors = append(out.Anchors, a.Raw)
	}
	return out, nil
}

// agentCSR returns the enrollment CSR (DER) of the agent.
func (s *Service) agentCSR(ctx context.Context, agentID string) ([]byte, error) {
	e, err := s.st.GetAgentEnrollment(ctx, agentID)
	if err != nil {
		return nil, fmt.Errorf("enrollment record of %s: %w", agentID, err)
	}
	return e.CSR, nil
}

// Result answers GET /enroll/result for an authenticated agent: the
// pending answer while it waits for approval, a new certificate once it is
// approved.
func (s *Service) Result(ctx context.Context, agentID string) (dto.EnrollResult, error) {
	a, err := s.st.GetAgent(ctx, agentID)
	if err != nil {
		return dto.EnrollResult{}, fmt.Errorf("enrollsvc: result: %w", err)
	}
	switch a.State {
	case store.AgentPending:
		return s.pending(a.ID), nil
	case store.AgentRevoked:
		s.log.WarnContext(ctx, "enrollment result refused", "agent_id", a.ID, "reason", "agent is revoked")
		return dto.EnrollResult{}, ErrRefused
	}
	csr, err := s.agentCSR(ctx, a.ID)
	if err != nil {
		return dto.EnrollResult{}, fmt.Errorf("enrollsvc: result: %w", err)
	}
	res, err := s.approved(ctx, a.ID, csr)
	if err != nil {
		return dto.EnrollResult{}, fmt.Errorf("enrollsvc: result: %w", err)
	}
	s.log.InfoContext(ctx, "enrollment certificate delivered", "agent_id", a.ID, "key_id", a.RegisterKeyID)
	return res, nil
}

// Renew issues a new certificate for the agent's identity key. csrDER is
// optional; when given it must be a CSR for the current identity key
// (ErrKeyMismatch otherwise). Key rotation is not supported.
func (s *Service) Renew(ctx context.Context, agentID string, csrDER []byte) (dto.RenewedCert, error) {
	a, err := s.st.GetAgent(ctx, agentID)
	if err != nil {
		return dto.RenewedCert{}, fmt.Errorf("enrollsvc: renew: %w", err)
	}
	if a.State != store.AgentApproved {
		return dto.RenewedCert{}, fmt.Errorf("enrollsvc: renew: agent is %s: %w", a.State, store.ErrInvalidState)
	}
	if len(csrDER) > 0 {
		csr, err := pki.ParseAgentCSR(csrDER)
		if err != nil {
			return dto.RenewedCert{}, fmt.Errorf("%w: %v", ErrBadRequest, err)
		}
		if !bytes.Equal(csr.PublicKey.(ed25519.PublicKey), a.IdentityKey) {
			s.log.WarnContext(ctx, "certificate renewal refused", "agent_id", a.ID, "reason", "CSR for another key")
			return dto.RenewedCert{}, ErrKeyMismatch
		}
	} else if csrDER, err = s.agentCSR(ctx, a.ID); err != nil {
		return dto.RenewedCert{}, fmt.Errorf("enrollsvc: renew: %w", err)
	}
	cert, err := s.pki.IssueAgentCertificate(ctx, csrDER, a.ID)
	if err != nil {
		return dto.RenewedCert{}, fmt.Errorf("enrollsvc: renew: issue certificate: %w", err)
	}
	ca, err := s.pki.AgentCA()
	if err != nil {
		return dto.RenewedCert{}, fmt.Errorf("enrollsvc: renew: agent CA: %w", err)
	}
	s.log.InfoContext(ctx, "agent certificate renewed", "agent_id", a.ID, "serial", cert.SerialNumber.Text(16), "not_after", cert.NotAfter)
	return dto.RenewedCert{Certificate: cert.Raw, AgentCa: ca.Raw, NotAfter: cert.NotAfter.UTC()}, nil
}

// Cleanup removes expired enrollment sessions. It is meant to run
// periodically.
func (s *Service) Cleanup(ctx context.Context) (int64, error) {
	n, err := s.st.DeleteExpiredEnrollSessions(ctx, s.now())
	if err != nil {
		return 0, fmt.Errorf("enrollsvc: cleanup: %w", err)
	}
	return n, nil
}
