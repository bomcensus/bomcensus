// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package agentapi is the agent-facing HTTP surface of the server
// (api/openapi/agent.yaml under /agent/v1): the handler stack shared by the
// connect-mode listener and listen-mode reverse connections, the connect
// mode HTTPS server and the reverse dialing of listen-mode agents.
//
// The handler stack is
//
//	link.AgentVerifier.DeferringMiddleware → peer adapter → msgsig.Middleware → router
//
// The router serves the generated strict handlers, except POST
// /enroll/start and POST /enroll/finish: their signatures cover the exact
// body bytes, which the strict wrapper does not expose, so they are plain
// http.HandlerFuncs.
package agentapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	gen "github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/link"
	"github.com/bomcensus/bomcensus/internal/msgsig"
	"github.com/bomcensus/bomcensus/internal/server/dispatch"
	"github.com/bomcensus/bomcensus/internal/server/enrollsvc"
	"github.com/bomcensus/bomcensus/internal/server/store"
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
	CheckUpdate(ctx context.Context, currentVersion, os, arch string) (gen.UpdateCheck, error)
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
	IngestK8sInventory(ctx context.Context, sender store.Agent, inv gen.K8sInventory) error
	// RecordScanResult stores the outcome of a scan job sent by a scanner.
	RecordScanResult(ctx context.Context, sender store.Agent, jobID string, res gen.ScanJobResult) error
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
	Logger  *slog.Logger

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

// NewHandler returns the complete agent-port handler.
func NewHandler(o Options) (http.Handler, error) {
	h, err := newHandlers(o)
	if err != nil {
		return nil, err
	}
	mw, err := msgsig.New(msgsig.Config{
		KeyLookup:      h.keyLookup,
		AdvanceCounter: h.advanceCounter,
		Signer:         h.signer,
		Bypass:         bypassPaths,
		Exempt:         exemptPaths,
		PendingAllowed: pendingPaths,
		MaxRequestBody: h.maxRequest,
		Logger:         h.log,
		Now:            h.now,
	})
	if err != nil {
		return nil, err
	}
	strict := gen.NewStrictHandlerWithOptions(h, []gen.StrictMiddlewareFunc{h.agentMiddleware}, gen.StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			writeJSONError(w, http.StatusBadRequest, msgsig.CodeInvalidRequest, err.Error())
		},
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			if clientGone(r, err) {
				// A long poll or upload whose client went away.
				h.log.DebugContext(r.Context(), "agent API request ended by the client", "path", r.URL.Path, "error", err)
			} else {
				h.log.ErrorContext(r.Context(), "agent API handler failed", "path", r.URL.Path, "error", err)
			}
			writeJSONError(w, http.StatusInternalServerError, msgsig.CodeInternal, "internal error")
		},
	})
	r := chi.NewRouter()
	r.NotFound(func(w http.ResponseWriter, _ *http.Request) {
		writeJSONError(w, http.StatusNotFound, "not_found", "not found")
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) {
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	})
	router := gen.HandlerWithOptions(routes{ServerInterface: strict, h: h}, gen.ChiServerOptions{
		BaseURL:    BasePath,
		BaseRouter: r,
		ErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
			writeJSONError(w, http.StatusBadRequest, msgsig.CodeInvalidRequest, err.Error())
		},
	})
	return h.verifier.DeferringMiddleware(signedPath, h.peerAdapter(mw.Wrap(router))), nil
}

// signedPath reports whether msgsig answers the request with a signed
// response, so that a failed client certificate check is left to it
// (agent_revoked, client_certificate_mismatch) instead of a plain 403 the
// agent cannot verify.
func signedPath(r *http.Request) bool { return !bypassPaths.Match(r.URL.Path) }

// clientGone reports whether err is the cancellation of a request whose
// client disconnected.
func clientGone(r *http.Request, err error) bool {
	return errors.Is(err, context.Canceled) && errors.Is(r.Context().Err(), context.Canceled)
}

// routes serves the enrollment exchange with raw handlers and everything
// else through the strict handler.
type routes struct {
	gen.ServerInterface
	h *Handlers
}

func (rt routes) EnrollStart(w http.ResponseWriter, r *http.Request)  { rt.h.serveEnroll(w, r, false) }
func (rt routes) EnrollFinish(w http.ResponseWriter, r *http.Request) { rt.h.serveEnroll(w, r, true) }

// peerAdapter records the connection facts of the request and passes the
// TLS peer identity, or why its certificate failed the per-request check,
// to msgsig. A reverse connection to an agent that presented a temporary
// certificate is restricted to enrollment.
func (h *Handlers) peerAdapter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		info := &requestInfo{
			remote:     remoteAddr(r.RemoteAddr),
			reverse:    link.PeerReverse(ctx),
			unenrolled: link.PeerUnenrolled(ctx),
			target:     reverseTargetFrom(ctx),
		}
		if info.unenrolled && !strings.HasPrefix(r.URL.Path, enrollPrefix) {
			h.log.WarnContext(ctx, "request on unenrolled reverse connection refused", "path", r.URL.Path, "remote", info.remote.String())
			writeJSONError(w, http.StatusForbidden, "enrollment_only", "connection may only be used for enrollment")
			return
		}
		if id, ok := link.PeerAgentID(ctx); ok {
			ctx = msgsig.WithTLSPeerAgentID(ctx, id)
		}
		if err := link.PeerCertError(ctx); err != nil {
			ctx = msgsig.WithTLSPeerFailure(ctx, tlsPeerFailure(err))
			if errors.Is(err, link.ErrRevocationCheck) {
				h.log.ErrorContext(ctx, "client certificate check failed", "path", r.URL.Path, "remote", info.remote.String(), "error", err)
			}
		}
		next.ServeHTTP(w, r.WithContext(withRequestInfo(ctx, info)))
	})
}

func tlsPeerFailure(err error) msgsig.TLSPeerFailure {
	switch {
	case errors.Is(err, link.ErrRevoked):
		return msgsig.TLSPeerRevoked
	case errors.Is(err, link.ErrRevocationCheck):
		return msgsig.TLSPeerCheckFailed
	}
	return msgsig.TLSPeerInvalid
}

// Scanner-only operations.
var scannerOnly = map[string]bool{
	"UploadK8sInventory":  true,
	"SubmitScanJobResult": true,
	"DownloadProbe":       true,
}

// agentMiddleware resolves the authenticated agent record for every
// signed operation and enforces the scanner-only operations.
func (h *Handlers) agentMiddleware(f gen.StrictHandlerFunc, op string) gen.StrictHandlerFunc {
	if op == "GetServerChain" || op == "EnrollStart" || op == "EnrollFinish" {
		return f
	}
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request, req any) (any, error) {
		id, ok := msgsig.AgentFromContext(ctx)
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, msgsig.CodeUnauthorized, "unauthenticated")
			return nil, nil
		}
		info := requestInfoFrom(ctx)
		a, ok := info.agent()
		if !ok || a.ID != id.ID {
			var err error
			if a, err = h.st.GetAgent(ctx, id.ID); err != nil {
				return nil, fmt.Errorf("load agent %s: %w", id.ID, err)
			}
		}
		if scannerOnly[op] && a.Kind != store.AgentKindScanner {
			h.log.WarnContext(ctx, "scanner operation refused", "operation", op, "agent_id", a.ID, "kind", a.Kind)
			writeJSONError(w, http.StatusForbidden, "forbidden", "operation is reserved for scanners")
			return nil, nil
		}
		return f(withAgent(ctx, a), w, r, req)
	}
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

func writeJSONError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(jsonError(code, msg))
}
