// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package adminapi serves the console: the admin API under /api/v1 and the
// built console files.
package adminapi

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/apierr"
	"github.com/bomcensus/bomcensus/internal/server/auth"
	"github.com/bomcensus/bomcensus/internal/server/auth/authz"
)

// BasePath is where the API is mounted.
const BasePath = "/api/v1"

// Body size limits.
const (
	DefaultMaxBodyBytes   = 1 << 20
	DefaultMaxUploadBytes = 2 << 30
)

// uploadPath is the release upload, the only route with the larger limit.
const uploadPath = BasePath + "/releases"

// Options configures NewRouter.
type Options struct {
	// Handlers implements every operation.
	Handlers gen.StrictServerInterface
	Auth     *auth.Service
	Logger   *slog.Logger
	// Console is the built console (index.html, 200.html, _nuxt/...). Nil
	// serves no console.
	Console fs.FS
	// MaxBodyBytes defaults to DefaultMaxBodyBytes, MaxUploadBytes (release
	// upload only) to DefaultMaxUploadBytes.
	MaxBodyBytes   int64
	MaxUploadBytes int64
}

// NewRouter returns the handler of the console listener.
//
// Every operation except login requires a session. The check, together with
// authz.Check, is done in one place: a strict-handler middleware that sees the
// operation name.
func NewRouter(o Options) http.Handler {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.MaxBodyBytes <= 0 {
		o.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if o.MaxUploadBytes <= 0 {
		o.MaxUploadBytes = DefaultMaxUploadBytes
	}
	rt := &router{opts: o, log: o.Logger}

	r := chi.NewRouter()
	r.Use(securityHeaders, rt.logRequests, rt.recoverPanics)
	r.Route(BasePath, func(api chi.Router) {
		api.Use(noStore, rt.limitBody, rt.resolveSession, rt.checkCSRF)
		api.NotFound(func(w http.ResponseWriter, r *http.Request) {
			apierr.Write(w, http.StatusNotFound, gen.Error{Code: apierr.CodeNotFound, Message: "no such endpoint"})
		})
		api.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
			apierr.Write(w, http.StatusMethodNotAllowed, gen.Error{Code: apierr.CodeMethod, Message: "method not allowed"})
		})
		strict := gen.NewStrictHandlerWithOptions(o.Handlers,
			[]gen.StrictMiddlewareFunc{authorize},
			gen.StrictHTTPServerOptions{
				RequestErrorHandlerFunc:  rt.requestError,
				ResponseErrorHandlerFunc: rt.responseError,
			})
		gen.HandlerWithOptions(strict, gen.ChiServerOptions{
			BaseRouter:       api,
			ErrorHandlerFunc: rt.paramError,
		})
	})
	console := &consoleHandler{fsys: o.Console}
	r.NotFound(console.ServeHTTP)
	r.MethodNotAllowed(console.ServeHTTP)
	return r
}

type router struct {
	opts Options
	log  *slog.Logger
}

// authorize requires a principal for every operation but login and passes
// the operation through authz.Check.
func authorize(f gen.StrictHandlerFunc, operationID string) gen.StrictHandlerFunc {
	if operationID == "Login" {
		return f
	}
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request, req any) (any, error) {
		switch err := authz.Check(ctx, operationID, r.URL.Path); {
		case errors.Is(err, authz.ErrUnauthenticated):
			return nil, apierr.Unauthenticated("login required")
		case errors.Is(err, authz.ErrForbidden):
			return nil, apierr.Forbidden("not allowed")
		case err != nil:
			return nil, err
		}
		return f(ctx, w, r, req)
	}
}

// requestError renders a body that could not be decoded.
func (rt *router) requestError(w http.ResponseWriter, r *http.Request, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		apierr.Render(w, err)
		return
	}
	apierr.Write(w, http.StatusBadRequest, gen.Error{Code: apierr.CodeInvalidArgument, Message: err.Error()})
}

// paramError renders a path or query parameter that could not be parsed.
func (rt *router) paramError(w http.ResponseWriter, r *http.Request, err error) {
	apierr.Write(w, http.StatusBadRequest, gen.Error{Code: apierr.CodeInvalidArgument, Message: err.Error()})
}

// responseError renders an error returned by a handler. Server errors are
// logged with their cause; the client gets a generic message.
func (rt *router) responseError(w http.ResponseWriter, r *http.Request, err error) {
	status, body := apierr.From(err)
	if status >= 500 && !errors.Is(err, context.Canceled) {
		rt.log.ErrorContext(r.Context(), "api request failed", "method", r.Method, "path", r.URL.Path, "error", err)
	}
	apierr.Write(w, status, body)
}

func (rt *router) limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := rt.opts.MaxBodyBytes
		if r.Method == http.MethodPost && r.URL.Path == uploadPath {
			limit = rt.opts.MaxUploadBytes
		}
		if r.ContentLength > limit {
			apierr.Render(w, &http.MaxBytesError{Limit: limit})
			return
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}

func (rt *router) resolveSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, err := rt.opts.Auth.Resolve(r)
		if err != nil {
			rt.log.ErrorContext(r.Context(), "session lookup failed", "error", err)
			apierr.Render(w, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (rt *router) checkCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := rt.opts.Auth.CheckCSRF(r); err != nil {
			rt.log.WarnContext(r.Context(), "request rejected", "method", r.Method, "path", r.URL.Path,
				"client", auth.RequestInfoFrom(r.Context()).ClientAddr, "reason", err.Error())
			apierr.Write(w, http.StatusForbidden, gen.Error{Code: apierr.CodeForbidden, Message: "cross-site request rejected"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (rt *router) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		status := ww.Status()
		if status == 0 {
			status = http.StatusOK
		}
		level := slog.LevelInfo
		if !strings.HasPrefix(r.URL.Path, BasePath+"/") {
			level = slog.LevelDebug
		}
		rt.log.Log(r.Context(), level, "http request", "method", r.Method, "path", r.URL.Path,
			"status", status, "bytes", ww.BytesWritten(), "duration", time.Since(start).String(),
			"remote", r.RemoteAddr)
	})
}

func (rt *router) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			v := recover()
			if v == nil {
				return
			}
			if v == http.ErrAbortHandler {
				panic(v)
			}
			rt.log.ErrorContext(r.Context(), "panic in http handler", "method", r.Method, "path", r.URL.Path,
				"panic", v, "stack", string(debug.Stack()))
			apierr.Write(w, http.StatusInternalServerError, gen.Error{Code: apierr.CodeInternal, Message: "internal error"})
		}()
		next.ServeHTTP(w, r)
	})
}

func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "frame-ancestors 'none'")
		h.Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}
