// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package agentapi

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/bomcensus/bomcensus/agentproto"
	"github.com/bomcensus/bomcensus/agentproto/dto"
	"github.com/bomcensus/bomcensus/internal/link"
	"github.com/bomcensus/bomcensus/internal/msgsig"
	"github.com/bomcensus/bomcensus/internal/pki"
	"github.com/bomcensus/bomcensus/internal/server/dispatch"
	"github.com/bomcensus/bomcensus/internal/server/enrollsvc"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// Handlers is the server's implementation of the agent protocol
// operations (agentproto.API). The channels in front of it authenticate the
// caller; Handlers checks the agent's state and the operations reserved for
// scanners, and runs the operation.
type Handlers struct {
	st         store.Store
	pki        PKI
	enroll     *enrollsvc.Service
	dispatch   *dispatch.Service
	updates    Updates
	ingest     Ingest
	detectors  DetectorTables
	log        *slog.Logger
	verifier   *link.AgentVerifier
	now        func() time.Time
	pollMax    time.Duration
	recheck    time.Duration
	maxRequest int64
	maxReport  int64

	// http is the handler stack of the HTTP channel.
	http http.Handler

	signerMu   sync.Mutex
	signerKey  crypto.Signer
	signerLeaf *x509.Certificate
	signerVal  *msgsig.ServerSigner
}

var _ agentproto.API = (*Handlers)(nil)

func newHandlers(o Options) (*Handlers, error) {
	if o.Store == nil || o.PKI == nil || o.Enroll == nil || o.Dispatch == nil {
		return nil, errors.New("agentapi: Store, PKI, Enroll and Dispatch are required")
	}
	h := &Handlers{
		st: o.Store, pki: o.PKI, enroll: o.Enroll, dispatch: o.Dispatch, updates: o.Updates, ingest: o.Ingest,
		log: o.Logger, now: o.Now, pollMax: o.PollTimeout, recheck: o.PollRecheck,
		maxRequest: o.MaxRequestBody, maxReport: o.MaxReportSize, detectors: o.Detectors,
	}
	if h.log == nil {
		h.log = slog.New(slog.DiscardHandler)
	}
	if h.now == nil {
		h.now = time.Now
	}
	if h.pollMax <= 0 {
		h.pollMax = 30 * time.Second
	}
	if h.recheck <= 0 {
		h.recheck = 3 * time.Second
	}
	if h.maxRequest <= 0 {
		h.maxRequest = msgsig.DefaultMaxRequestBody
	}
	if h.maxReport <= 0 || h.maxReport > h.maxRequest {
		h.maxReport = h.maxRequest
	}
	h.verifier = NewAgentVerifier(o.PKI)
	return h, nil
}

func apiError(status int, code, msg string) *agentproto.Error {
	return &agentproto.Error{Status: status, Code: code, Message: msg}
}

func errUnavailable() *agentproto.Error {
	return apiError(http.StatusServiceUnavailable, agentproto.CodeUnavailable, "service not available")
}

func errEmptyBody() *agentproto.Error {
	return apiError(http.StatusBadRequest, agentproto.CodeInvalidRequest, "empty body")
}

// Operations with rules of their own.
const (
	opGetEnrollResult     = "GetEnrollResult"
	opUploadK8sInventory  = "UploadK8sInventory"
	opSubmitScanJobResult = "SubmitScanJobResult"
	opDownloadProbe       = "DownloadProbe"
)

// Scanner-only operations.
var scannerOnly = map[string]bool{
	opUploadK8sInventory:  true,
	opSubmitScanJobResult: true,
	opDownloadProbe:       true,
}

// caller returns the authenticated agent of an operation: the record the
// channel loaded while authenticating the request, or a fresh one. It
// refuses agents whose state does not allow op, and scanner operations of
// agents that are not scanners.
func (h *Handlers) caller(ctx context.Context, op string) (store.Agent, error) {
	id, ok := agentproto.AgentFrom(ctx)
	if !ok {
		return store.Agent{}, apiError(http.StatusUnauthorized, agentproto.CodeUnauthorized, "unauthenticated")
	}
	a, ok := requestInfoFrom(ctx).agent()
	if !ok || a.ID != id {
		var err error
		a, err = h.st.GetAgent(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			return store.Agent{}, apiError(http.StatusUnauthorized, agentproto.CodeUnauthorized, "unknown agent")
		}
		if err != nil {
			return store.Agent{}, fmt.Errorf("load agent %s: %w", id, err)
		}
	}
	switch a.State {
	case store.AgentApproved:
	case store.AgentPending:
		if op != opGetEnrollResult {
			return store.Agent{}, apiError(http.StatusForbidden, agentproto.CodeAgentPending, "agent is pending approval")
		}
	default:
		return store.Agent{}, apiError(http.StatusForbidden, agentproto.CodeAgentRevoked, "agent is revoked")
	}
	if scannerOnly[op] && a.Kind != store.AgentKindScanner {
		h.log.WarnContext(ctx, "scanner operation refused", "operation", op, "agent_id", a.ID, "kind", a.Kind)
		return store.Agent{}, apiError(http.StatusForbidden, agentproto.CodeForbidden, "operation is reserved for scanners")
	}
	return a, nil
}

// ── enrollment ──────────────────────────────────────────────────────────

// EnrollStart implements agentproto.API on the exact request body.
func (h *Handlers) EnrollStart(ctx context.Context, body []byte) (*agentproto.SignedMessage, error) {
	if len(body) > enrollsvc.MaxBodySize {
		return nil, apiError(http.StatusRequestEntityTooLarge, agentproto.CodeBodyTooLarge, "request body too large")
	}
	peer := agentproto.PeerFrom(ctx)
	resp, sig, err := h.enroll.Start(ctx, body, peer.RemoteAddr, peer.Reverse)
	if err != nil {
		return nil, enrollError(err)
	}
	return &agentproto.SignedMessage{Body: resp, Signature: sig}, nil
}

// EnrollFinish implements agentproto.API on the exact request body.
func (h *Handlers) EnrollFinish(ctx context.Context, body []byte) (*agentproto.SignedMessage, error) {
	if len(body) > enrollsvc.MaxBodySize {
		return nil, apiError(http.StatusRequestEntityTooLarge, agentproto.CodeBodyTooLarge, "request body too large")
	}
	resp, sig, err := h.enroll.Finish(ctx, body, agentproto.PeerFrom(ctx).RemoteAddr)
	if err != nil {
		return nil, enrollError(err)
	}
	return &agentproto.SignedMessage{Body: resp, Signature: sig}, nil
}

// enrollError maps an enrollment failure to its answer.
func enrollError(err error) error {
	var rl *enrollsvc.RateLimitError
	switch {
	case errors.As(err, &rl):
		e := apiError(http.StatusTooManyRequests, agentproto.CodeRateLimited, "too many failed attempts")
		e.RetryAfter = rl.RetryAfter
		return e
	case errors.Is(err, enrollsvc.ErrRefused):
		return apiError(http.StatusForbidden, agentproto.CodeEnrollmentRefused, "enrollment refused")
	case errors.Is(err, enrollsvc.ErrBadRequest):
		return apiError(http.StatusBadRequest, agentproto.CodeInvalidRequest, "malformed enrollment request")
	}
	return apiError(http.StatusInternalServerError, agentproto.CodeInternal, "internal error")
}

// GetEnrollResult implements agentproto.API.
func (h *Handlers) GetEnrollResult(ctx context.Context) (*dto.EnrollResult, error) {
	a, err := h.caller(ctx, opGetEnrollResult)
	if err != nil {
		return nil, err
	}
	res, err := h.enroll.Result(ctx, a.ID)
	if errors.Is(err, enrollsvc.ErrRefused) {
		return nil, apiError(http.StatusForbidden, agentproto.CodeEnrollmentRefused, "enrollment refused")
	}
	if err != nil {
		return nil, err
	}
	return &res, nil
}

// RenewCert implements agentproto.API.
func (h *Handlers) RenewCert(ctx context.Context, req *dto.CertRenewRequest) (*dto.RenewedCert, error) {
	a, err := h.caller(ctx, "RenewCert")
	if err != nil {
		return nil, err
	}
	var csr []byte
	if req != nil && req.Csr != nil {
		csr = *req.Csr
	}
	res, err := h.enroll.Renew(ctx, a.ID, csr)
	switch {
	case errors.Is(err, enrollsvc.ErrKeyMismatch), errors.Is(err, enrollsvc.ErrBadRequest):
		return nil, apiError(http.StatusBadRequest, agentproto.CodeInvalidRequest, err.Error())
	case errors.Is(err, store.ErrInvalidState):
		return nil, apiError(http.StatusForbidden, agentproto.CodeForbidden, "agent is not approved")
	case err != nil:
		return nil, err
	}
	return &res, nil
}

// GetTrustBundle implements agentproto.API.
func (h *Handlers) GetTrustBundle(ctx context.Context) (*dto.TrustBundle, error) {
	if _, err := h.caller(ctx, "GetTrustBundle"); err != nil {
		return nil, err
	}
	tb, err := h.enroll.TrustBundle(ctx)
	if err != nil {
		return nil, err
	}
	return &tb, nil
}

// GetServerChain implements agentproto.API.
func (h *Handlers) GetServerChain(context.Context) (*dto.ServerChain, error) {
	_, chain := h.pki.Signer()
	if len(chain) == 0 {
		return nil, errors.New("no server signing key")
	}
	out := dto.ServerChain{ChainPem: make([]string, 0, len(chain))}
	for _, cert := range chain {
		out.ChainPem = append(out.ChainPem, string(pki.EncodeCertificatesPEM(cert)))
	}
	return &out, nil
}

// ── uploads ─────────────────────────────────────────────────────────────

// UploadReport implements agentproto.API.
func (h *Handlers) UploadReport(ctx context.Context, params dto.UploadReportParams, report io.Reader) (*dto.ReportAccepted, error) {
	a, err := h.caller(ctx, "UploadReport")
	if err != nil {
		return nil, err
	}
	if h.ingest == nil {
		return nil, errUnavailable()
	}
	if report == nil {
		return nil, errEmptyBody()
	}
	raw, err := io.ReadAll(io.LimitReader(report, h.maxReport+1))
	if err != nil {
		return nil, fmt.Errorf("read report: %w", err)
	}
	if int64(len(raw)) > h.maxReport {
		return nil, apiError(http.StatusRequestEntityTooLarge, agentproto.CodeBodyTooLarge, "report too large")
	}
	if len(raw) == 0 {
		return nil, errEmptyBody()
	}
	jobID := ""
	if params.JobId != nil {
		jobID = *params.JobId
	}
	id, err := h.ingest.Submit(ctx, a, jobID, raw)
	if invalidInput(err) {
		h.log.WarnContext(ctx, "report rejected", "agent_id", a.ID, "error", err)
		return nil, apiError(http.StatusBadRequest, agentproto.CodeInvalidRequest, "invalid report")
	}
	if err != nil {
		return nil, fmt.Errorf("submit report: %w", err)
	}
	return &dto.ReportAccepted{ReportId: id}, nil
}

// UploadK8sInventory implements agentproto.API.
func (h *Handlers) UploadK8sInventory(ctx context.Context, inv *dto.K8sInventory) error {
	a, err := h.caller(ctx, opUploadK8sInventory)
	if err != nil {
		return err
	}
	if h.ingest == nil {
		return errUnavailable()
	}
	if inv == nil {
		return errEmptyBody()
	}
	err = h.ingest.IngestK8sInventory(ctx, a, *inv)
	if invalidInput(err) || errors.Is(err, store.ErrNotFound) {
		return apiError(http.StatusBadRequest, agentproto.CodeInvalidRequest, err.Error())
	}
	if err != nil {
		return fmt.Errorf("ingest inventory: %w", err)
	}
	return nil
}

// SubmitScanJobResult implements agentproto.API.
func (h *Handlers) SubmitScanJobResult(ctx context.Context, jobID string, res *dto.ScanJobResult) error {
	a, err := h.caller(ctx, opSubmitScanJobResult)
	if err != nil {
		return err
	}
	if h.ingest == nil {
		return errUnavailable()
	}
	if res == nil {
		return errEmptyBody()
	}
	err = h.ingest.RecordScanResult(ctx, a, jobID, *res)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return apiError(http.StatusNotFound, agentproto.CodeNotFound, "unknown scan job")
	case invalidInput(err):
		return apiError(http.StatusBadRequest, agentproto.CodeInvalidRequest, err.Error())
	case err != nil:
		return fmt.Errorf("record scan result: %w", err)
	}
	return nil
}

// ── update ──────────────────────────────────────────────────────────────

// CheckUpdate implements agentproto.API.
func (h *Handlers) CheckUpdate(ctx context.Context, params dto.CheckUpdateParams) (*dto.UpdateCheck, error) {
	a, err := h.caller(ctx, "CheckUpdate")
	if err != nil {
		return nil, err
	}
	if !params.Os.Valid() || !params.Arch.Valid() {
		return nil, apiError(http.StatusBadRequest, agentproto.CodeInvalidRequest, "unsupported platform")
	}
	if h.updates == nil {
		s, err := h.st.GetUpdateSettings(ctx)
		if err != nil {
			return nil, err
		}
		return &dto.UpdateCheck{CheckIntervalMinutes: s.CheckIntervalMinutes}, nil
	}
	res, err := h.updates.CheckUpdate(ctx, a.Version, string(params.Os), string(params.Arch))
	if err != nil {
		return nil, fmt.Errorf("check update: %w", err)
	}
	return &res, nil
}

// DownloadUpdateBundle implements agentproto.API.
func (h *Handlers) DownloadUpdateBundle(ctx context.Context, version string, params dto.DownloadUpdateBundleParams) (*agentproto.Download, error) {
	if _, err := h.caller(ctx, "DownloadUpdateBundle"); err != nil {
		return nil, err
	}
	if h.updates == nil {
		return nil, errUnavailable()
	}
	rc, size, err := h.updates.Bundle(ctx, version, string(params.Os), string(params.Arch))
	if errors.Is(err, store.ErrNotFound) {
		return nil, apiError(http.StatusNotFound, agentproto.CodeNotFound, "no such release")
	}
	if err != nil {
		return nil, fmt.Errorf("open bundle: %w", err)
	}
	return &agentproto.Download{Body: rc, Size: size}, nil
}

// DownloadProbe implements agentproto.API.
func (h *Handlers) DownloadProbe(ctx context.Context, os dto.TargetOs, arch dto.TargetArch) (*agentproto.Download, error) {
	if _, err := h.caller(ctx, opDownloadProbe); err != nil {
		return nil, err
	}
	if h.updates == nil {
		return nil, errUnavailable()
	}
	probe, version, err := h.updates.Probe(ctx, string(os), string(arch))
	if errors.Is(err, store.ErrNotFound) {
		return nil, apiError(http.StatusNotFound, agentproto.CodeNotFound, "no probe for this platform")
	}
	if err != nil {
		return nil, fmt.Errorf("open probe: %w", err)
	}
	return &agentproto.Download{Body: io.NopCloser(bytes.NewReader(probe)), Size: int64(len(probe)), Version: version}, nil
}

// ── helpers ─────────────────────────────────────────────────────────────

// invalidInput reports whether an ingest error is the uploader's fault.
func invalidInput(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, store.ErrInvalid) {
		return true
	}
	var p interface{ Permanent() bool }
	return errors.As(err, &p) && p.Permanent()
}

// ownCAs returns the CA certificates the server may present to agents: those
// in the chains of the Agent TLS server and client certificates, and the
// trust bundle anchors (the current one and a prepared one, whose
// certificates may already be in use).
func (h *Handlers) ownCAs() []*x509.Certificate {
	var out []*x509.Certificate
	if b, err := h.pki.TrustBundle(); err == nil && b != nil {
		out = append(out, b.Anchors...)
	}
	for _, get := range []func() (*tls.Certificate, error){h.pki.AgentServerCertificate, h.pki.AgentClientCertificate} {
		c, err := get()
		if err != nil || c == nil {
			continue
		}
		for _, der := range c.Certificate[min(1, len(c.Certificate)):] {
			if ca, err := x509.ParseCertificate(der); err == nil {
				out = append(out, ca)
			}
		}
	}
	return out
}
