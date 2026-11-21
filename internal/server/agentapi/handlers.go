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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/bomcensus/bomcensus/internal/enroll"
	gen "github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/link"
	"github.com/bomcensus/bomcensus/internal/msgsig"
	"github.com/bomcensus/bomcensus/internal/pki"
	"github.com/bomcensus/bomcensus/internal/server/dispatch"
	"github.com/bomcensus/bomcensus/internal/server/enrollsvc"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// Handlers implements the generated strict server interface.
type Handlers struct {
	st         store.Store
	pki        PKI
	enroll     *enrollsvc.Service
	dispatch   *dispatch.Service
	updates    Updates
	ingest     Ingest
	log        *slog.Logger
	verifier   *link.AgentVerifier
	now        func() time.Time
	pollMax    time.Duration
	recheck    time.Duration
	maxRequest int64
	maxReport  int64

	signerMu   sync.Mutex
	signerKey  crypto.Signer
	signerLeaf *x509.Certificate
	signerVal  *msgsig.ServerSigner
}

var _ gen.StrictServerInterface = (*Handlers)(nil)

func newHandlers(o Options) (*Handlers, error) {
	if o.Store == nil || o.PKI == nil || o.Enroll == nil || o.Dispatch == nil {
		return nil, errors.New("agentapi: Store, PKI, Enroll and Dispatch are required")
	}
	h := &Handlers{
		st: o.Store, pki: o.PKI, enroll: o.Enroll, dispatch: o.Dispatch, updates: o.Updates, ingest: o.Ingest,
		log: o.Logger, now: o.Now, pollMax: o.PollTimeout, recheck: o.PollRecheck,
		maxRequest: o.MaxRequestBody, maxReport: o.MaxReportSize,
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

func apiError(code, msg string) gen.Error { return gen.Error{Code: code, Message: msg} }

var errUnavailable = apiError("unavailable", "service not available")

// ── enrollment ──────────────────────────────────────────────────────────

// serveEnroll handles POST /enroll/start and POST /enroll/finish on the
// exact body bytes and writes the exact bytes that were signed.
func (h *Handlers) serveEnroll(w http.ResponseWriter, r *http.Request, finish bool) {
	ctx := r.Context()
	info := requestInfoFrom(ctx)
	body, err := io.ReadAll(io.LimitReader(r.Body, enrollsvc.MaxBodySize+1))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, msgsig.CodeInvalidRequest, "read body")
		return
	}
	if len(body) > enrollsvc.MaxBodySize {
		writeJSONError(w, http.StatusRequestEntityTooLarge, msgsig.CodeBodyTooLarge, "request body too large")
		return
	}
	reverse := info.reverse && info.target != nil
	var resp []byte
	var sig string
	if finish {
		resp, sig, err = h.enroll.Finish(ctx, body, info.remote)
	} else {
		if reverse {
			if err := info.target.checkStart(body); err != nil {
				h.log.WarnContext(ctx, "enrollment refused", "step", "start", "remote", info.remote.String(),
					"listen_target", info.target.id, "reason", err.Error())
				writeJSONError(w, http.StatusForbidden, "enrollment_refused", "enrollment refused")
				return
			}
		}
		resp, sig, err = h.enroll.Start(ctx, body, info.remote, reverse)
	}
	if err != nil {
		var rl *enrollsvc.RateLimitError
		switch {
		case errors.As(err, &rl):
			w.Header().Set("Retry-After", strconv.Itoa(int(rl.RetryAfter/time.Second)+1))
			writeJSONError(w, http.StatusTooManyRequests, "rate_limited", "too many failed attempts")
		case errors.Is(err, enrollsvc.ErrRefused):
			writeJSONError(w, http.StatusForbidden, "enrollment_refused", "enrollment refused")
		case errors.Is(err, enrollsvc.ErrBadRequest):
			writeJSONError(w, http.StatusBadRequest, msgsig.CodeInvalidRequest, "malformed enrollment request")
		default:
			writeJSONError(w, http.StatusInternalServerError, msgsig.CodeInternal, "internal error")
		}
		return
	}
	if finish && reverse {
		h.afterReverseEnroll(ctx, info.target, resp)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(enroll.HeaderSignature, sig)
	w.Header().Set("Content-Length", strconv.Itoa(len(resp)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
	if finish && reverse {
		info.target.maybeReconnect(w, resp)
	}
}

// afterReverseEnroll binds the listen target to the enrolled agent.
func (h *Handlers) afterReverseEnroll(ctx context.Context, t *reverseTarget, resp []byte) {
	var res gen.EnrollResult
	if err := json.Unmarshal(resp, &res); err != nil || res.AgentId == "" {
		return
	}
	if err := t.bind(ctx, res.AgentId); err != nil {
		h.log.ErrorContext(ctx, "bind listen target", "listen_target", t.id, "agent_id", res.AgentId, "error", err)
	}
}

// EnrollStart is served by serveEnroll; the strict wrapper re-encodes the
// body, which would break the enrollment signatures.
func (h *Handlers) EnrollStart(context.Context, gen.EnrollStartRequestObject) (gen.EnrollStartResponseObject, error) {
	return gen.EnrollStartdefaultJSONResponse{StatusCode: http.StatusInternalServerError,
		Body: apiError(msgsig.CodeInternal, "enroll/start is served on the raw body")}, nil
}

// EnrollFinish is served by serveEnroll, see EnrollStart.
func (h *Handlers) EnrollFinish(context.Context, gen.EnrollFinishRequestObject) (gen.EnrollFinishResponseObject, error) {
	return gen.EnrollFinishdefaultJSONResponse{StatusCode: http.StatusInternalServerError,
		Body: apiError(msgsig.CodeInternal, "enroll/finish is served on the raw body")}, nil
}

// GetEnrollResult implements gen.StrictServerInterface.
func (h *Handlers) GetEnrollResult(ctx context.Context, _ gen.GetEnrollResultRequestObject) (gen.GetEnrollResultResponseObject, error) {
	a := agentFrom(ctx)
	res, err := h.enroll.Result(ctx, a.ID)
	if errors.Is(err, enrollsvc.ErrRefused) {
		return gen.GetEnrollResult403JSONResponse{ForbiddenJSONResponse: gen.ForbiddenJSONResponse(apiError("enrollment_refused", "enrollment refused"))}, nil
	}
	if err != nil {
		return nil, err
	}
	if info := requestInfoFrom(ctx); info.unenrolled && info.target != nil && res.Status == gen.EnrollStatusApproved {
		info.target.reconnectSoon()
	}
	return gen.GetEnrollResult200JSONResponse(res), nil
}

// RenewCert implements gen.StrictServerInterface.
func (h *Handlers) RenewCert(ctx context.Context, req gen.RenewCertRequestObject) (gen.RenewCertResponseObject, error) {
	var csr []byte
	if req.Body != nil && req.Body.Csr != nil {
		csr = *req.Body.Csr
	}
	res, err := h.enroll.Renew(ctx, agentFrom(ctx).ID, csr)
	switch {
	case errors.Is(err, enrollsvc.ErrKeyMismatch), errors.Is(err, enrollsvc.ErrBadRequest):
		return gen.RenewCert400JSONResponse{BadRequestJSONResponse: gen.BadRequestJSONResponse(apiError(msgsig.CodeInvalidRequest, err.Error()))}, nil
	case errors.Is(err, store.ErrInvalidState):
		return gen.RenewCert403JSONResponse{ForbiddenJSONResponse: gen.ForbiddenJSONResponse(apiError("forbidden", "agent is not approved"))}, nil
	case err != nil:
		return nil, err
	}
	return gen.RenewCert200JSONResponse(res), nil
}

// GetTrustBundle implements gen.StrictServerInterface.
func (h *Handlers) GetTrustBundle(ctx context.Context, _ gen.GetTrustBundleRequestObject) (gen.GetTrustBundleResponseObject, error) {
	tb, err := h.enroll.TrustBundle(ctx)
	if err != nil {
		return nil, err
	}
	return gen.GetTrustBundle200JSONResponse(tb), nil
}

// GetServerChain implements gen.StrictServerInterface.
func (h *Handlers) GetServerChain(context.Context, gen.GetServerChainRequestObject) (gen.GetServerChainResponseObject, error) {
	_, chain := h.pki.Signer()
	if len(chain) == 0 {
		return nil, errors.New("no server signing key")
	}
	out := gen.ServerChain{ChainPem: make([]string, 0, len(chain))}
	for _, cert := range chain {
		out.ChainPem = append(out.ChainPem, string(pki.EncodeCertificatesPEM(cert)))
	}
	return gen.GetServerChain200JSONResponse(out), nil
}

// ── uploads ─────────────────────────────────────────────────────────────

// UploadReport implements gen.StrictServerInterface.
func (h *Handlers) UploadReport(ctx context.Context, req gen.UploadReportRequestObject) (gen.UploadReportResponseObject, error) {
	if h.ingest == nil {
		return gen.UploadReportdefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: errUnavailable}, nil
	}
	if req.Body == nil {
		return gen.UploadReport400JSONResponse{BadRequestJSONResponse: gen.BadRequestJSONResponse(apiError(msgsig.CodeInvalidRequest, "empty body"))}, nil
	}
	raw, err := io.ReadAll(io.LimitReader(req.Body, h.maxReport+1))
	if err != nil {
		return nil, fmt.Errorf("read report: %w", err)
	}
	if int64(len(raw)) > h.maxReport {
		return gen.UploadReport413JSONResponse{PayloadTooLargeJSONResponse: gen.PayloadTooLargeJSONResponse(apiError(msgsig.CodeBodyTooLarge, "report too large"))}, nil
	}
	if len(raw) == 0 {
		return gen.UploadReport400JSONResponse{BadRequestJSONResponse: gen.BadRequestJSONResponse(apiError(msgsig.CodeInvalidRequest, "empty body"))}, nil
	}
	jobID := ""
	if req.Params.JobId != nil {
		jobID = *req.Params.JobId
	}
	a := agentFrom(ctx)
	id, err := h.ingest.Submit(ctx, a, jobID, raw)
	if invalidInput(err) {
		h.log.WarnContext(ctx, "report rejected", "agent_id", a.ID, "error", err)
		return gen.UploadReport400JSONResponse{BadRequestJSONResponse: gen.BadRequestJSONResponse(apiError(msgsig.CodeInvalidRequest, "invalid report"))}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("submit report: %w", err)
	}
	return gen.UploadReport202JSONResponse(gen.ReportAccepted{ReportId: id}), nil
}

// UploadK8sInventory implements gen.StrictServerInterface.
func (h *Handlers) UploadK8sInventory(ctx context.Context, req gen.UploadK8sInventoryRequestObject) (gen.UploadK8sInventoryResponseObject, error) {
	if h.ingest == nil {
		return gen.UploadK8sInventorydefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: errUnavailable}, nil
	}
	if req.Body == nil {
		return gen.UploadK8sInventory400JSONResponse{BadRequestJSONResponse: gen.BadRequestJSONResponse(apiError(msgsig.CodeInvalidRequest, "empty body"))}, nil
	}
	err := h.ingest.IngestK8sInventory(ctx, agentFrom(ctx), *req.Body)
	if invalidInput(err) || errors.Is(err, store.ErrNotFound) {
		return gen.UploadK8sInventory400JSONResponse{BadRequestJSONResponse: gen.BadRequestJSONResponse(apiError(msgsig.CodeInvalidRequest, err.Error()))}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ingest inventory: %w", err)
	}
	return gen.UploadK8sInventory204Response{}, nil
}

// SubmitScanJobResult implements gen.StrictServerInterface.
func (h *Handlers) SubmitScanJobResult(ctx context.Context, req gen.SubmitScanJobResultRequestObject) (gen.SubmitScanJobResultResponseObject, error) {
	if h.ingest == nil {
		return gen.SubmitScanJobResultdefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: errUnavailable}, nil
	}
	if req.Body == nil {
		return gen.SubmitScanJobResult400JSONResponse{BadRequestJSONResponse: gen.BadRequestJSONResponse(apiError(msgsig.CodeInvalidRequest, "empty body"))}, nil
	}
	err := h.ingest.RecordScanResult(ctx, agentFrom(ctx), req.Id, *req.Body)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return gen.SubmitScanJobResult404JSONResponse{NotFoundJSONResponse: gen.NotFoundJSONResponse(apiError("not_found", "unknown scan job"))}, nil
	case invalidInput(err):
		return gen.SubmitScanJobResult400JSONResponse{BadRequestJSONResponse: gen.BadRequestJSONResponse(apiError(msgsig.CodeInvalidRequest, err.Error()))}, nil
	case err != nil:
		return nil, fmt.Errorf("record scan result: %w", err)
	}
	return gen.SubmitScanJobResult204Response{}, nil
}

// ── update ──────────────────────────────────────────────────────────────

// CheckUpdate implements gen.StrictServerInterface.
func (h *Handlers) CheckUpdate(ctx context.Context, req gen.CheckUpdateRequestObject) (gen.CheckUpdateResponseObject, error) {
	if !req.Params.Os.Valid() || !req.Params.Arch.Valid() {
		return gen.CheckUpdate400JSONResponse{BadRequestJSONResponse: gen.BadRequestJSONResponse(apiError(msgsig.CodeInvalidRequest, "unsupported platform"))}, nil
	}
	if h.updates == nil {
		s, err := h.st.GetUpdateSettings(ctx)
		if err != nil {
			return nil, err
		}
		return gen.CheckUpdate200JSONResponse(gen.UpdateCheck{CheckIntervalMinutes: s.CheckIntervalMinutes}), nil
	}
	res, err := h.updates.CheckUpdate(ctx, agentFrom(ctx).Version, string(req.Params.Os), string(req.Params.Arch))
	if err != nil {
		return nil, fmt.Errorf("check update: %w", err)
	}
	return gen.CheckUpdate200JSONResponse(res), nil
}

// DownloadUpdateBundle implements gen.StrictServerInterface.
func (h *Handlers) DownloadUpdateBundle(ctx context.Context, req gen.DownloadUpdateBundleRequestObject) (gen.DownloadUpdateBundleResponseObject, error) {
	if h.updates == nil {
		return gen.DownloadUpdateBundledefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: errUnavailable}, nil
	}
	rc, size, err := h.updates.Bundle(ctx, req.Version, string(req.Params.Os), string(req.Params.Arch))
	if errors.Is(err, store.ErrNotFound) {
		return gen.DownloadUpdateBundle404JSONResponse{NotFoundJSONResponse: gen.NotFoundJSONResponse(apiError("not_found", "no such release"))}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open bundle: %w", err)
	}
	return gen.DownloadUpdateBundle200ApplicationxTarResponse{Body: rc, ContentLength: size}, nil
}

// DownloadProbe implements gen.StrictServerInterface.
func (h *Handlers) DownloadProbe(ctx context.Context, req gen.DownloadProbeRequestObject) (gen.DownloadProbeResponseObject, error) {
	if h.updates == nil {
		return gen.DownloadProbedefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: errUnavailable}, nil
	}
	probe, version, err := h.updates.Probe(ctx, string(req.Os), string(req.Arch))
	if errors.Is(err, store.ErrNotFound) {
		return gen.DownloadProbe404JSONResponse{NotFoundJSONResponse: gen.NotFoundJSONResponse(apiError("not_found", "no probe for this platform"))}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open probe: %w", err)
	}
	return gen.DownloadProbe200ApplicationoctetStreamResponse{Body: bytes.NewReader(probe), ContentLength: int64(len(probe)),
		Headers: gen.DownloadProbe200ResponseHeaders{BomcensusProbeVersion: version}}, nil
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

// ownFingerprints returns the fingerprints of the certificates the server
// presents to agents: the Agent TLS server and client leaves.
func (h *Handlers) ownFingerprints() [][32]byte {
	var out [][32]byte
	for _, get := range []func() (*tls.Certificate, error){h.pki.AgentServerCertificate, h.pki.AgentClientCertificate} {
		c, err := get()
		if err != nil || c == nil || len(c.Certificate) == 0 {
			continue
		}
		if c.Leaf != nil {
			out = append(out, pki.Fingerprint(c.Leaf))
			continue
		}
		if leaf, err := x509.ParseCertificate(c.Certificate[0]); err == nil {
			out = append(out, pki.Fingerprint(leaf))
		}
	}
	return out
}
