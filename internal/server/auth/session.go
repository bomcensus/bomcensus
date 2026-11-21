// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

// CookieName is the session cookie.
const CookieName = "bomcensus_session"

// DefaultSessionLifetime is how long a session is valid after login. It is
// not extended by use.
const DefaultSessionLifetime = 12 * time.Hour

// sessionIDLen is the length of store session IDs: 32 bytes in unpadded
// base64url.
const sessionIDLen = 43

// ThrottledError is returned by Login while the client or the username is
// locked out after too many failures.
type ThrottledError struct {
	RetryAfter time.Duration
}

func (e *ThrottledError) Error() string {
	return fmt.Sprintf("auth: too many failed logins, retry in %s", e.RetryAfter.Round(time.Second))
}

// Config configures a Service.
type Config struct {
	Provider Provider
	Sessions store.Sessions
	Logger   *slog.Logger
	// TrustProxy makes the service believe X-Forwarded-For,
	// X-Forwarded-Proto and X-Forwarded-Host. Set it only when the listener
	// is reachable through a reverse proxy alone.
	TrustProxy bool
	// SessionLifetime defaults to DefaultSessionLifetime.
	SessionLifetime time.Duration
	// Limiter defaults to NewLimiter(LimiterConfig{}).
	Limiter *Limiter
	Now     func() time.Time
}

// Service logs users in and out and resolves session cookies.
type Service struct {
	provider   Provider
	sessions   store.Sessions
	logger     *slog.Logger
	trustProxy bool
	lifetime   time.Duration
	limiter    *Limiter
	now        func() time.Time
}

// NewService returns a Service.
func NewService(cfg Config) *Service {
	s := &Service{
		provider:   cfg.Provider,
		sessions:   cfg.Sessions,
		logger:     cfg.Logger,
		trustProxy: cfg.TrustProxy,
		lifetime:   cfg.SessionLifetime,
		limiter:    cfg.Limiter,
		now:        cfg.Now,
	}
	if s.logger == nil {
		s.logger = slog.New(slog.DiscardHandler)
	}
	if s.lifetime <= 0 {
		s.lifetime = DefaultSessionLifetime
	}
	if s.limiter == nil {
		s.limiter = NewLimiter(LimiterConfig{Now: cfg.Now})
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s
}

// Login checks the credentials and creates a session. It returns the cookie
// to set. Failures are ErrInvalidCredentials or *ThrottledError; both are
// logged with the client address.
func (s *Service) Login(ctx context.Context, username, password string) (Principal, *http.Cookie, error) {
	ri := RequestInfoFrom(ctx)
	keys := []string{"addr:" + ri.ClientAddr, "user:" + strings.ToLower(username)}
	if wait, ok := s.limiter.Attempt(keys...); !ok {
		s.logger.WarnContext(ctx, "login throttled", "username", username, "client", ri.ClientAddr,
			"retry_after", wait.Round(time.Second).String())
		return Principal{}, nil, &ThrottledError{RetryAfter: wait}
	}
	p, err := s.provider.Authenticate(ctx, username, password)
	if errors.Is(err, ErrInvalidCredentials) {
		s.logger.WarnContext(ctx, "login failed", "username", username, "client", ri.ClientAddr)
		return Principal{}, nil, ErrInvalidCredentials
	}
	if err != nil {
		return Principal{}, nil, fmt.Errorf("auth: authenticate: %w", err)
	}
	s.limiter.Succeeded(keys...)
	sess, err := s.sessions.CreateSession(ctx, p.ID, p.Name, s.now().Add(s.lifetime))
	if err != nil {
		return Principal{}, nil, fmt.Errorf("auth: create session: %w", err)
	}
	s.logger.InfoContext(ctx, "login", "principal", p.ID, "client", ri.ClientAddr)
	return p, s.cookie(sess.ID, sess.ExpiresAt, ri.Secure), nil
}

// Logout deletes the session of ctx, if any, and returns the cookie that
// clears it in the browser.
func (s *Service) Logout(ctx context.Context) (*http.Cookie, error) {
	if id := sessionIDFrom(ctx); id != "" {
		if err := s.sessions.DeleteSession(ctx, id); err != nil {
			return nil, fmt.Errorf("auth: delete session: %w", err)
		}
		if p, ok := FromContext(ctx); ok {
			s.logger.InfoContext(ctx, "logout", "principal", p.ID, "client", RequestInfoFrom(ctx).ClientAddr)
		}
	}
	c := s.cookie("", time.Unix(0, 0), RequestInfoFrom(ctx).Secure)
	c.MaxAge = -1
	return c, nil
}

// Resolve returns the context for r: request information and, when the
// request carries a valid session cookie, the principal. A missing, unknown
// or expired session is not an error; the context then has no principal.
func (s *Service) Resolve(r *http.Request) (context.Context, error) {
	ri := s.requestInfo(r)
	ctx := WithRequestInfo(r.Context(), ri)
	c, err := r.Cookie(CookieName)
	if err != nil || len(c.Value) != sessionIDLen {
		return ctx, nil
	}
	sess, err := s.sessions.GetSession(ctx, c.Value, s.now())
	if errors.Is(err, store.ErrNotFound) {
		return ctx, nil
	}
	if err != nil {
		return ctx, fmt.Errorf("auth: get session: %w", err)
	}
	ctx = WithPrincipal(ctx, Principal{ID: sess.PrincipalID, Name: sess.PrincipalName})
	return withSessionID(ctx, sess.ID), nil
}

// PurgeExpired deletes expired sessions.
func (s *Service) PurgeExpired(ctx context.Context) (int64, error) {
	return s.sessions.DeleteExpiredSessions(ctx, s.now())
}

func (s *Service) cookie(value string, expires time.Time, secure bool) *http.Cookie {
	c := &http.Cookie{
		Name:     CookieName,
		Value:    value,
		Path:     "/",
		Expires:  expires.UTC(),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	}
	if value != "" {
		c.MaxAge = max(1, int(expires.Sub(s.now()).Seconds()))
	}
	return c
}

// requestInfo derives the client address and transport security of r.
func (s *Service) requestInfo(r *http.Request) RequestInfo {
	ri := RequestInfo{Secure: r.TLS != nil}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ri.ClientAddr = host
	} else {
		ri.ClientAddr = r.RemoteAddr
	}
	if !s.trustProxy {
		return ri
	}
	if proto := lastHeaderValue(r.Header, "X-Forwarded-Proto"); proto != "" {
		ri.Secure = strings.EqualFold(proto, "https")
	}
	// The proxy appends the address it saw; earlier entries come from the
	// client and are not trusted.
	if xff := lastHeaderValue(r.Header, "X-Forwarded-For"); xff != "" {
		if a, err := netip.ParseAddr(xff); err == nil {
			ri.ClientAddr = a.Unmap().String()
		}
	}
	return ri
}

// requestHost is the host the client addressed.
func (s *Service) requestHost(r *http.Request) string {
	if s.trustProxy {
		if h := firstHeaderValue(r.Header, "X-Forwarded-Host"); h != "" {
			return h
		}
	}
	return r.Host
}

// lastHeaderValue returns the last comma-separated element over all values
// of the header.
func lastHeaderValue(h http.Header, name string) string {
	vs := h.Values(name)
	if len(vs) == 0 {
		return ""
	}
	v := vs[len(vs)-1]
	if i := strings.LastIndexByte(v, ','); i >= 0 {
		v = v[i+1:]
	}
	return strings.TrimSpace(v)
}

func firstHeaderValue(h http.Header, name string) string {
	v := h.Get(name)
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}
