// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package agentapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bomcensus/bomcensus/agentproto"
	"github.com/bomcensus/bomcensus/agentproto/dto"
	"github.com/bomcensus/bomcensus/internal/enroll"
	gen "github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/link"
	"github.com/bomcensus/bomcensus/internal/msgsig"
	"github.com/bomcensus/bomcensus/internal/server/enrollsvc"
	"github.com/bomcensus/bomcensus/server/scope"
)

// newHTTPHandler builds the handler stack of the HTTP channel.
func (h *Handlers) newHTTPHandler() (http.Handler, error) {
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
	strict := gen.NewStrictHandlerWithOptions(httpAPI{h}, nil, gen.StrictHTTPServerOptions{
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
	return h.verifier.DeferringMiddleware(signedPath, h.peerAdapter(mw.Wrap(signedAgent(router)))), nil
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
		ctx := scope.System(r.Context())
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
		ctx = agentproto.WithPeer(ctx, agentproto.Peer{RemoteAddr: info.remote, Reverse: info.reverse && info.target != nil})
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

// signedAgent passes the agent msgsig authenticated to the operations.
func signedAgent(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a, ok := msgsig.AgentFromContext(r.Context()); ok {
			r = r.WithContext(agentproto.WithAgent(r.Context(), a.ID))
		}
		next.ServeHTTP(w, r)
	})
}

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
	reverse := info.reverse && info.target != nil
	var msg *agentproto.SignedMessage
	if finish {
		msg, err = h.EnrollFinish(ctx, body)
	} else {
		if reverse && len(body) <= enrollsvc.MaxBodySize {
			if err := info.target.checkStart(body); err != nil {
				h.log.WarnContext(ctx, "enrollment refused", "step", "start", "remote", info.remote.String(),
					"listen_target", info.target.id, "reason", err.Error())
				writeJSONError(w, http.StatusForbidden, "enrollment_refused", "enrollment refused")
				return
			}
		}
		msg, err = h.EnrollStart(ctx, body)
	}
	if err != nil {
		writeError(w, err)
		return
	}
	if finish && reverse {
		h.afterReverseEnroll(ctx, info.target, msg.Body)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(enroll.HeaderSignature, msg.Signature)
	w.Header().Set("Content-Length", strconv.Itoa(len(msg.Body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(msg.Body)
	if finish && reverse {
		info.target.maybeReconnect(w, msg.Body)
	}
}

// afterReverseEnroll binds the listen target to the enrolled agent.
func (h *Handlers) afterReverseEnroll(ctx context.Context, t *reverseTarget, resp []byte) {
	var res dto.EnrollResult
	if err := json.Unmarshal(resp, &res); err != nil || res.AgentId == "" {
		return
	}
	if err := t.bind(ctx, res.AgentId); err != nil {
		h.log.ErrorContext(ctx, "bind listen target", "listen_target", t.id, "agent_id", res.AgentId, "error", err)
	}
}

func writeJSONError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(jsonError(code, msg))
}

// writeError writes an operation error; errors that are not
// *agentproto.Error are internal errors.
func writeError(w http.ResponseWriter, err error) {
	e, ok := agentproto.AsError(err)
	if !ok {
		e = apiError(http.StatusInternalServerError, msgsig.CodeInternal, "internal error")
	}
	if e.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(e.RetryAfter/time.Second)+1))
	}
	writeJSONError(w, e.Status, e.Code, e.Message)
}

// httpAPI serves the strict handlers with Handlers.
type httpAPI struct{ h *Handlers }

var _ gen.StrictServerInterface = httpAPI{}

// failure is the response of a failed operation: the error response of an
// *agentproto.Error, or the error itself for the strict wrapper to answer
// with 500.
func failure(err error) (errorResponse, error) {
	if e, ok := agentproto.AsError(err); ok {
		return errorResponse{e}, nil
	}
	return errorResponse{}, err
}

// errorResponse writes an *agentproto.Error as the response of any
// operation.
type errorResponse struct{ e *agentproto.Error }

func (r errorResponse) visit(w http.ResponseWriter) error {
	if r.e.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(r.e.RetryAfter/time.Second)+1))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(r.e.Status)
	return json.NewEncoder(w).Encode(dto.Error{Code: r.e.Code, Message: r.e.Message})
}

func (r errorResponse) VisitRenewCertResponse(w http.ResponseWriter) error       { return r.visit(w) }
func (r errorResponse) VisitEnrollFinishResponse(w http.ResponseWriter) error    { return r.visit(w) }
func (r errorResponse) VisitGetEnrollResultResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r errorResponse) VisitEnrollStartResponse(w http.ResponseWriter) error     { return r.visit(w) }
func (r errorResponse) VisitUploadK8sInventoryResponse(w http.ResponseWriter) error {
	return r.visit(w)
}
func (r errorResponse) VisitPollResponse(w http.ResponseWriter) error          { return r.visit(w) }
func (r errorResponse) VisitDownloadProbeResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r errorResponse) VisitUploadReportResponse(w http.ResponseWriter) error  { return r.visit(w) }
func (r errorResponse) VisitSubmitScanJobResultResponse(w http.ResponseWriter) error {
	return r.visit(w)
}
func (r errorResponse) VisitGetServerChainResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r errorResponse) VisitGetTrustBundleResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r errorResponse) VisitDownloadUpdateBundleResponse(w http.ResponseWriter) error {
	return r.visit(w)
}
func (r errorResponse) VisitCheckUpdateResponse(w http.ResponseWriter) error { return r.visit(w) }

// EnrollStart is served by serveEnroll; the strict wrapper re-encodes the
// body, which would break the enrollment signatures.
func (httpAPI) EnrollStart(context.Context, gen.EnrollStartRequestObject) (gen.EnrollStartResponseObject, error) {
	return gen.EnrollStartdefaultJSONResponse{StatusCode: http.StatusInternalServerError,
		Body: dto.Error{Code: msgsig.CodeInternal, Message: "enroll/start is served on the raw body"}}, nil
}

// EnrollFinish is served by serveEnroll, see EnrollStart.
func (httpAPI) EnrollFinish(context.Context, gen.EnrollFinishRequestObject) (gen.EnrollFinishResponseObject, error) {
	return gen.EnrollFinishdefaultJSONResponse{StatusCode: http.StatusInternalServerError,
		Body: dto.Error{Code: msgsig.CodeInternal, Message: "enroll/finish is served on the raw body"}}, nil
}

func (x httpAPI) GetEnrollResult(ctx context.Context, _ gen.GetEnrollResultRequestObject) (gen.GetEnrollResultResponseObject, error) {
	res, err := x.h.GetEnrollResult(ctx)
	if err != nil {
		return failure(err)
	}
	if info := requestInfoFrom(ctx); info.unenrolled && info.target != nil && res.Status == dto.EnrollStatusApproved {
		info.target.reconnectSoon()
	}
	return gen.GetEnrollResult200JSONResponse(*res), nil
}

func (x httpAPI) RenewCert(ctx context.Context, req gen.RenewCertRequestObject) (gen.RenewCertResponseObject, error) {
	res, err := x.h.RenewCert(ctx, req.Body)
	if err != nil {
		return failure(err)
	}
	return gen.RenewCert200JSONResponse(*res), nil
}

func (x httpAPI) GetTrustBundle(ctx context.Context, _ gen.GetTrustBundleRequestObject) (gen.GetTrustBundleResponseObject, error) {
	res, err := x.h.GetTrustBundle(ctx)
	if err != nil {
		return failure(err)
	}
	return gen.GetTrustBundle200JSONResponse(*res), nil
}

func (x httpAPI) GetServerChain(ctx context.Context, _ gen.GetServerChainRequestObject) (gen.GetServerChainResponseObject, error) {
	res, err := x.h.GetServerChain(ctx)
	if err != nil {
		return failure(err)
	}
	return gen.GetServerChain200JSONResponse(*res), nil
}

func (x httpAPI) Poll(ctx context.Context, req gen.PollRequestObject) (gen.PollResponseObject, error) {
	res, err := x.h.Poll(ctx, req.Body)
	if err != nil {
		return failure(err)
	}
	return gen.Poll200JSONResponse(*res), nil
}

func (x httpAPI) UploadReport(ctx context.Context, req gen.UploadReportRequestObject) (gen.UploadReportResponseObject, error) {
	res, err := x.h.UploadReport(ctx, req.Params, req.Body)
	if err != nil {
		return failure(err)
	}
	return gen.UploadReport202JSONResponse(*res), nil
}

func (x httpAPI) UploadK8sInventory(ctx context.Context, req gen.UploadK8sInventoryRequestObject) (gen.UploadK8sInventoryResponseObject, error) {
	if err := x.h.UploadK8sInventory(ctx, req.Body); err != nil {
		return failure(err)
	}
	return gen.UploadK8sInventory204Response{}, nil
}

func (x httpAPI) SubmitScanJobResult(ctx context.Context, req gen.SubmitScanJobResultRequestObject) (gen.SubmitScanJobResultResponseObject, error) {
	if err := x.h.SubmitScanJobResult(ctx, req.Id, req.Body); err != nil {
		return failure(err)
	}
	return gen.SubmitScanJobResult204Response{}, nil
}

func (x httpAPI) CheckUpdate(ctx context.Context, req gen.CheckUpdateRequestObject) (gen.CheckUpdateResponseObject, error) {
	res, err := x.h.CheckUpdate(ctx, req.Params)
	if err != nil {
		return failure(err)
	}
	return gen.CheckUpdate200JSONResponse(*res), nil
}

func (x httpAPI) DownloadUpdateBundle(ctx context.Context, req gen.DownloadUpdateBundleRequestObject) (gen.DownloadUpdateBundleResponseObject, error) {
	d, err := x.h.DownloadUpdateBundle(ctx, req.Version, req.Params)
	if err != nil {
		return failure(err)
	}
	return gen.DownloadUpdateBundle200ApplicationxTarResponse{Body: d.Body, ContentLength: d.Size}, nil
}

func (x httpAPI) DownloadProbe(ctx context.Context, req gen.DownloadProbeRequestObject) (gen.DownloadProbeResponseObject, error) {
	d, err := x.h.DownloadProbe(ctx, req.Os, req.Arch)
	if err != nil {
		return failure(err)
	}
	return gen.DownloadProbe200ApplicationoctetStreamResponse{Body: d.Body, ContentLength: d.Size,
		Headers: gen.DownloadProbe200ResponseHeaders{BomcensusProbeVersion: d.Version}}, nil
}
