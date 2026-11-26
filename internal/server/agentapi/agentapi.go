// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package agentapi is the agent-facing side of the server: the operations
// of the agent protocol (Handlers, an agentproto.API) and the HTTP channel
// in front of them (api/openapi/agent.yaml under /agent/v1): the handler
// stack shared by the connect-mode listener and listen-mode reverse
// connections, the connect mode HTTPS server and the reverse dialing of
// listen-mode agents. Other channels reach the operations through Gateway.
//
// The handler stack of the HTTP channel is
//
//	link.AgentVerifier.DeferringMiddleware → peer adapter → msgsig.Middleware → signed agent → router
//
// The router serves the generated strict handlers (httpAPI, which calls
// Handlers), except POST
// /enroll/start and POST /enroll/finish: their signatures cover the exact
// body bytes, which the strict wrapper does not expose, so they are plain
// http.HandlerFuncs.
package agentapi

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"time"

	"github.com/bomcensus/bomcensus/agentproto"
	"github.com/bomcensus/bomcensus/agentproto/dto"
	"github.com/bomcensus/bomcensus/internal/link"
	"github.com/bomcensus/bomcensus/internal/msgsig"
	"github.com/bomcensus/bomcensus/internal/server/dispatch"
	"github.com/bomcensus/bomcensus/internal/server/enrollsvc"
	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/server/scope"
)

// BasePath is the prefix of every agent API path.
const BasePath = "/agent/v1"

// Paths of the message signature policy (docs/PROTOCOL.md §5).
var (
	bypassPaths  = msgsig.Paths{BasePath + "/enroll/start", BasePath + "/enroll/finish", BasePath + "/server-chain"}
	exemptPaths  = msgsig.Paths{BasePath + "/update/bundle/", BasePath + "/probe/"}
	pendingPaths = msgsig.Paths{BasePath + "/enroll/result"}
	// enrollPrefix is what an unenrolled reverse connection may reach.
	enrollPrefix = BasePath + "/enroll/"
)

// PKI is what the agent API needs from the server's certificate service
// (satisfied by *pkisvc.Service).
type PKI interface {
	enrollsvc.PKI
	// AgentServerCertificate returns the Agent TLS server certificate with
	// its chain up to the anchor.
	AgentServerCertificate() (*tls.Certificate, error)
	// AgentClientCertificate returns the Agent TLS client certificate (with
	// chain) the server presents to listen-mode agents.
	AgentClientCertificate() (*tls.Certificate, error)
	// IsAgentCertRevoked reports whether an agent certificate serial is
	// revoked or unknown. It is called on every handshake and request and
	// should answer from memory.
	IsAgentCertRevoked(ctx context.Context, serial *big.Int) (bool, error)
}

// Updates is what the agent API needs from the update service. Bundle and
// Probe are the methods of *updatesvc.Service; CheckUpdate converts its
// Check result to the wire form. store.ErrNotFound is answered with 404.
type Updates interface {
	// CheckUpdate answers the update check of an agent running
	// currentVersion. With no deployed version TargetVersion is nil.
	CheckUpdate(ctx context.Context, currentVersion, os, arch string) (dto.UpdateCheck, error)
	// Bundle returns the release bundle of version holding the files of
	// one platform, and its size.
	Bundle(ctx context.Context, version, os, arch string) (io.ReadCloser, int64, error)
	// Probe returns the probe binary for the platform and its version.
	Probe(ctx context.Context, os, arch string) ([]byte, string, error)
}

// Ingest is what the agent API needs from the ingest service. The sender
// is the authenticated agent or scanner; its enrollment defaults are in
// store.AgentEnrollments. store.ErrInvalid, and errors with a
// Permanent() bool method that returns true, are answered with 400;
// store.ErrNotFound with 404 (scan job result) or 400.
type Ingest interface {
	// Submit stores the raw report (report.Encode format) and queues its
	// ingestion. jobID is the job_id query parameter, empty when absent.
	Submit(ctx context.Context, sender store.Agent, jobID string, raw []byte) (reportID string, err error)
	// IngestK8sInventory stores a cluster inventory sent by a scanner.
	IngestK8sInventory(ctx context.Context, sender store.Agent, inv dto.K8sInventory) error
	// RecordScanResult stores the outcome of a scan job sent by a scanner.
	RecordScanResult(ctx context.Context, sender store.Agent, jobID string, res dto.ScanJobResult) error
}

// Options configures NewHandler.
type Options struct {
	Store    store.Store
	PKI      PKI
	Enroll   *enrollsvc.Service
	Dispatch *dispatch.Service
	// Updates and Ingest may be nil; their operations then answer 503.
	Updates Updates
	Ingest  Ingest
	// Detectors, when set, is the detector table announced to agents and
	// handed to those whose table differs (PROTOCOL.md).
	Detectors DetectorTables
	Logger    *slog.Logger

	// PollTimeout is the longest a poll waits for directives (default 30 s).
	PollTimeout time.Duration
	// PollRecheck is how often a waiting poll re-reads the store, to see
	// directives enqueued by other replicas (default 3 s).
	PollRecheck time.Duration
	// MaxRequestBody caps every signed request body (default
	// msgsig.DefaultMaxRequestBody).
	MaxRequestBody int64
	// MaxReportSize caps report uploads (default MaxRequestBody).
	MaxReportSize int64

	Now func() time.Time
}

// DetectorTables provides the detector table in effect
// (detectorsvc.Service).
type DetectorTables interface {
	// Current returns the digest and canonical JSON of the table.
	Current(ctx context.Context) (digest string, table []byte, err error)
}

// NewAgentVerifier returns the agent certificate verifier backed by p,
// shared by the listener TLS configuration, the handler stack and reverse
// dialing.
func NewAgentVerifier(p PKI) *link.AgentVerifier {
	return &link.AgentVerifier{
		AgentCA: func() *x509.Certificate {
			ca, err := p.AgentCA()
			if err != nil {
				return nil
			}
			return ca
		},
		Revoked: func(serial *big.Int) (bool, error) {
			return p.IsAgentCertRevoked(context.Background(), serial)
		},
	}
}

// New returns the agent protocol service with the handler stack of the
// HTTP channel.
func New(o Options) (*Handlers, error) {
	h, err := newHandlers(o)
	if err != nil {
		return nil, err
	}
	if h.http, err = h.newHTTPHandler(); err != nil {
		return nil, err
	}
	return h, nil
}

// NewHandler returns the complete agent-port handler of the HTTP channel.
func NewHandler(o Options) (http.Handler, error) {
	h, err := New(o)
	if err != nil {
		return nil, err
	}
	return h.HTTP(), nil
}

// HTTP returns the handler stack of the HTTP channel, shared by the
// connect-mode listener and listen-mode reverse connections.
func (h *Handlers) HTTP() http.Handler { return h.http }

// Gateway returns what other channels serve: the operations, run with the
// system data scope, and the agents to authenticate requests with.
func (h *Handlers) Gateway() *agentproto.Server {
	return &agentproto.Server{API: systemScoped{h}, Agents: agents{h}, Logger: h.log}
}

// keyLookup is msgsig's KeyLookup over the agents store.
func (h *Handlers) keyLookup(ctx context.Context, agentID string) (msgsig.AgentKey, error) {
	a, err := h.st.GetAgent(ctx, agentID)
	if errors.Is(err, store.ErrNotFound) {
		return msgsig.AgentKey{}, msgsig.ErrUnknownAgent
	}
	if err != nil {
		return msgsig.AgentKey{}, err
	}
	relaxed := false
	e, err := h.st.GetAgentEnrollment(ctx, agentID)
	switch {
	case err == nil:
		relaxed = e.AllowRelaxedTLS
	case !errors.Is(err, store.ErrNotFound):
		return msgsig.AgentKey{}, err
	}
	key := msgsig.AgentKey{PublicKey: a.IdentityKey}
	switch a.State {
	case store.AgentApproved:
		key.State = msgsig.StateApproved
	case store.AgentPending:
		key.State = msgsig.StatePending
	default:
		key.State = msgsig.StateRevoked
	}
	// An agent can only present a certificate once it has a valid one:
	// a pending agent, or one whose certificate was not delivered yet,
	// authenticates by message signature alone.
	key.RequireTLSClientCert = !relaxed && a.CertNotAfter != nil && a.CertNotAfter.After(h.now())
	requestInfoFrom(ctx).setAgent(a)
	return key, nil
}

// advanceCounter adapts the agents store to msgsig's AdvanceCounter.
func (h *Handlers) advanceCounter(ctx context.Context, agentID string, n uint64) (uint64, bool, error) {
	ok, err := h.st.AdvanceAgentCounter(ctx, agentID, n)
	if err != nil {
		return 0, false, err
	}
	if ok {
		return n, true, nil
	}
	cur, err := h.st.AgentCounter(ctx, agentID)
	if err != nil {
		return 0, false, err
	}
	return cur, false, nil
}

// signer returns the response signer for the current server key, rebuilt
// when the key or its certificate changes.
func (h *Handlers) signer(context.Context) (*msgsig.ServerSigner, error) {
	key, chain := h.pki.Signer()
	if key == nil || len(chain) == 0 {
		return nil, errors.New("agentapi: no server signing key")
	}
	h.signerMu.Lock()
	defer h.signerMu.Unlock()
	if h.signerVal != nil && h.signerKey == key && h.signerLeaf == chain[0] {
		return h.signerVal, nil
	}
	s, err := msgsig.NewServerSigner(chain[0], key)
	if err != nil {
		return nil, err
	}
	h.signerKey, h.signerLeaf, h.signerVal = key, chain[0], s
	return s, nil
}

// agents is agentproto.Agents for gateways.
type agents struct{ h *Handlers }

func (a agents) AgentKey(ctx context.Context, agentID string) (agentproto.AgentKey, error) {
	k, err := a.h.keyLookup(scope.System(ctx), agentID)
	if errors.Is(err, msgsig.ErrUnknownAgent) {
		return agentproto.AgentKey{}, fmt.Errorf("%w: %s", agentproto.ErrUnknownAgent, agentID)
	}
	if err != nil {
		return agentproto.AgentKey{}, err
	}
	out := agentproto.AgentKey{PublicKey: k.PublicKey, RequireCertificate: k.RequireTLSClientCert}
	switch k.State {
	case msgsig.StateApproved:
		out.State = agentproto.StateApproved
	case msgsig.StatePending:
		out.State = agentproto.StatePending
	default:
		out.State = agentproto.StateRevoked
	}
	return out, nil
}

func (a agents) AdvanceCounter(ctx context.Context, agentID string, n uint64) (uint64, bool, error) {
	return a.h.advanceCounter(scope.System(ctx), agentID, n)
}

func (a agents) SigningKey(context.Context) (crypto.Signer, []*x509.Certificate, error) {
	key, chain := a.h.pki.Signer()
	if key == nil || len(chain) == 0 {
		return nil, nil, errors.New("agentapi: no server signing key")
	}
	return key, chain, nil
}

func (a agents) ServerCertificate() (*tls.Certificate, error) {
	return a.h.pki.AgentServerCertificate()
}

func (a agents) VerifyCertificate(chain []*x509.Certificate) (string, error) {
	return a.h.verifier.Verify(chain, x509.ExtKeyUsageClientAuth)
}
