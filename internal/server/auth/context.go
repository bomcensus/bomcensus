// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package auth authenticates console users and keeps their sessions.
//
// The middleware puts the authenticated Principal into the request context;
// handlers and services read the user only from there (FromContext).
// Authorization is a separate step in package authz.
package auth

import "context"

// Principal is an authenticated user.
type Principal struct {
	// ID is stable and stored as created_by on records.
	ID   string
	Name string
}

// RequestInfo describes the HTTP request a context belongs to.
type RequestInfo struct {
	// ClientAddr is the client IP address (from the trusted proxy header when
	// the service trusts a proxy).
	ClientAddr string
	// Secure is set when the client connection uses TLS.
	Secure bool
}

type principalKey struct{}

type requestKey struct{}

type sessionKey struct{}

// WithPrincipal returns ctx carrying p.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// FromContext returns the principal of ctx, if any.
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok && p.ID != ""
}

// WithRequestInfo returns ctx carrying ri.
func WithRequestInfo(ctx context.Context, ri RequestInfo) context.Context {
	return context.WithValue(ctx, requestKey{}, ri)
}

// RequestInfoFrom returns the request information of ctx; zero when none.
func RequestInfoFrom(ctx context.Context) RequestInfo {
	ri, _ := ctx.Value(requestKey{}).(RequestInfo)
	return ri
}

func withSessionID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, sessionKey{}, id)
}

func sessionIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(sessionKey{}).(string)
	return id
}
