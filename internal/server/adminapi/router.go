// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package adminapi serves the console: the admin API under /api/v1 and the
// built console files.
package adminapi

import (
	"context"
	"errors"
	"fmt"
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
	"github.com/bomcensus/bomcensus/internal/server/session"
	"github.com/bomcensus/bomcensus/server/auth"
	"github.com/bomcensus/bomcensus/server/authz"
	"github.com/bomcensus/bomcensus/server/scope"
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

// loginPath is the built-in login, checked for CSRF without a session.
const loginPath = BasePath + "/auth/login"

// Options configures NewRouter.
type Options struct {
	// Handlers implements every operation.
	Handlers gen.StrictServerInterface
	// Session is the built-in cookie login. Nil disables cookie sessions;
	// requests are then authenticated by Middleware alone.
	Session *session.Service
	// TrustProxy makes the client address and TLS state of requests
	// (auth.RequestInfo) come from X-Forwarded-For and X-Forwarded-Proto.
	TrustProxy bool
	// Middleware runs on every API request after the session cookie was
	// resolved and before authorization. An authenticating middleware puts
	// the principal into the context with auth.WithPrincipal.
	Middleware []func(http.Handler) http.Handler
	// Authorizer decides every operation that needs a principal. Nil is
	// authz.AllowAll.
	Authorizer authz.Authorizer
	// Mounts are extra handlers by path prefix outside BasePath (for
	// example an OIDC callback). They get the security headers, request
	// logging and panic recovery, nothing else.
	Mounts map[string]http.Handler
	Logger *slog.Logger
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
// Every operation except the public ones (authz.IsPublic) requires a
// principal. That check and the Authorizer run in one place: a strict-handler
// middleware that sees the operation name. The scope of the decision is put
// into the context of the handler.
func NewRouter(o Options) (http.Handler, error) {
	if o.Authorizer == nil {
		o.Authorizer = authz.AllowAll
	}
	for prefix := range o.Mounts {
		if !strings.HasPrefix(prefix, "/") || prefix == "/" || prefix == "/api" || strings.HasPrefix(prefix, "/api/") {
			return nil, fmt.Errorf("adminapi: mount %q: must be a path below / outside /api", prefix)
		}
	}
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
	for prefix, h := range o.Mounts {
		r.Mount(prefix, h)
	}
	r.Route(BasePath, func(api chi.Router) {
		api.Use(noStore, rt.limitBody, rt.requestInfo)
		if o.Session != nil {
			api.Use(rt.resolveSession)
		}
		api.Use(o.Middleware...)
		api.NotFound(func(w http.ResponseWriter, r *http.Request) {
			apierr.Write(w, http.StatusNotFound, gen.Error{Code: apierr.CodeNotFound, Message: "no such endpoint"})
		})
		api.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
			apierr.Write(w, http.StatusMethodNotAllowed, gen.Error{Code: apierr.CodeMethod, Message: "method not allowed"})
		})
		strict := gen.NewStrictHandlerWithOptions(o.Handlers,
			[]gen.StrictMiddlewareFunc{rt.authorize},
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
	return r, nil
}

type router struct {
	opts Options
	log  *slog.Logger
}

// authorize requires a principal for every operation but the public ones,
// asks the Authorizer and puts the decided scope into the context. Public
// operations run with the empty scope.
func (rt *router) authorize(f gen.StrictHandlerFunc, operationID string) gen.StrictHandlerFunc {
	if authz.IsPublic(operationID) {
		return func(ctx context.Context, w http.ResponseWriter, r *http.Request, req any) (any, error) {
			return f(scope.With(ctx, scope.Of()), w, r, req)
		}
	}
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request, req any) (any, error) {
		p, ok := auth.FromContext(ctx)
		if !ok {
			return nil, apierr.Unauthenticated("login required")
		}
		d, err := rt.opts.Authorizer.Authorize(ctx, p, authz.Request{
			Operation: operationID,
			Method:    r.Method,
			Path:      r.URL.Path,
			Params:    urlParams(r),
		})
		switch {
		case errors.Is(err, authz.ErrForbidden):
			rt.log.WarnContext(ctx, "request denied", "operation", operationID, "principal", p.ID(), "error", err)
			return nil, apierr.Forbidden("not allowed")
		case err != nil:
			return nil, fmt.Errorf("authorize %s: %w", operationID, err)
		}
		return f(scope.With(ctx, d.Scope), w, r, req)
	}
}

// urlParams returns the path parameters chi matched for r.
func urlParams(r *http.Request) map[string]string {
	rc := chi.RouteContext(r.Context())
	if rc == nil || len(rc.URLParams.Keys) == 0 {
		return nil
	}
	m := make(map[string]string, len(rc.URLParams.Keys))
	for i, k := range rc.URLParams.Keys {
		m[k] = rc.URLParams.Values[i]
	}
	return m
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

// requestInfo records the client address and transport security.
func (rt *router) requestInfo(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := auth.WithRequestInfo(r.Context(), session.RequestInfo(r, rt.opts.TrustProxy))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// resolveSession authenticates the session cookie. Requests authenticated
// that way, and the login request, must pass the CSRF check; requests
// authenticated by other means (Middleware) do not carry ambient
// credentials and are not checked.
func (rt *router) resolveSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, err := rt.opts.Session.Resolve(r)
		if err != nil {
			rt.log.ErrorContext(r.Context(), "session lookup failed", "error", err)
			apierr.Render(w, err)
			return
		}
		r = r.WithContext(ctx)
		if !session.Authenticated(ctx) && r.URL.Path != loginPath {
			next.ServeHTTP(w, r)
			return
		}
		if err := rt.opts.Session.CheckCSRF(r); err != nil {
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
