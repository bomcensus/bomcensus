// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package auth defines who is calling the admin API.
//
// Authentication puts a Principal into the request context with
// WithPrincipal. The built-in cookie session does that for console logins;
// any http middleware passed in server.Options.APIMiddleware can do the same
// for tokens, client certificates or proxy headers. Handlers and services
// read the caller only through FromContext. Authorization is a separate step
// (package authz).
package auth

import (
	"context"
	"errors"
)

// Principal is an authenticated caller. Implementations may carry anything
// an Authorizer needs (roles, groups, tenants, token claims); bomcensus uses
// only ID and Name.
type Principal interface {
	// ID is stable and stored with the records the principal creates
	// (created_by). It must not be empty.
	ID() string
	// Name is shown in logs and API responses.
	Name() string
}

// User is the Principal of the built-in login.
type User struct {
	UserID   string
	UserName string
}

// ID implements Principal.
func (u User) ID() string { return u.UserID }

// Name implements Principal.
func (u User) Name() string { return u.UserName }

// PasswordProvider checks a username and password for the built-in login
// (POST /api/v1/auth/login). LDAP or a user database are implementations;
// the default is the single user from the server configuration.
type PasswordProvider interface {
	// Authenticate returns the principal for the credentials or
	// ErrInvalidCredentials.
	Authenticate(ctx context.Context, username, password string) (Principal, error)
}

// ErrInvalidCredentials is returned when a username and password do not
// match a user.
var ErrInvalidCredentials = errors.New("auth: invalid credentials")

// RequestInfo describes the HTTP request a context belongs to.
type RequestInfo struct {
	// ClientAddr is the client IP address (from the trusted proxy header when
	// the server trusts a proxy).
	ClientAddr string
	// Secure is set when the client connection uses TLS.
	Secure bool
}

type principalKey struct{}

type requestKey struct{}

// WithPrincipal returns ctx carrying p.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// FromContext returns the principal of ctx. ok is false when there is none
// or its ID is empty.
func FromContext(ctx context.Context) (p Principal, ok bool) {
	p, _ = ctx.Value(principalKey{}).(Principal)
	if p == nil || p.ID() == "" {
		return nil, false
	}
	return p, true
}

// IDFrom returns the ID of the principal of ctx, or "" when there is none.
func IDFrom(ctx context.Context) string {
	if p, ok := FromContext(ctx); ok {
		return p.ID()
	}
	return ""
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
