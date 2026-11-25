// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package tokenauth is an example of the admin API extension points: a
// middleware that authenticates bearer tokens and an Authorizer with roles
// and tenants.
//
// A real deployment would verify JWTs or ask an identity provider in
// Middleware; the Principal type and the Authorizer stay the same.
package tokenauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/bomcensus/bomcensus/server/apierror"
	"github.com/bomcensus/bomcensus/server/auth"
	"github.com/bomcensus/bomcensus/server/authz"
	"github.com/bomcensus/bomcensus/server/scope"
)

// Roles.
const (
	// RoleViewer may read: the Get*, List* and Export* operations.
	RoleViewer = "viewer"
	// RoleOperator may also change the records of its tenants.
	RoleOperator = "operator"
	// RoleAdmin may do everything, including the server settings.
	RoleAdmin = "admin"
)

// User is the principal of a token. Tenants are scope ids; "*" is every
// tenant.
type User struct {
	UserID  string
	Role    string
	Tenants []string
}

// ID implements auth.Principal.
func (u User) ID() string { return "token:" + u.UserID }

// Name implements auth.Principal.
func (u User) Name() string { return u.UserID }

// ParseTokens parses "token=user:role:tenant1|tenant2,..." (the format of
// the example's EXAMPLE_TOKENS variable).
func ParseTokens(s string) (map[string]User, error) {
	out := map[string]User{}
	for _, entry := range strings.Split(s, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		tok, rest, ok := strings.Cut(entry, "=")
		parts := strings.Split(rest, ":")
		if !ok || tok == "" || len(parts) != 3 || parts[0] == "" {
			return nil, fmt.Errorf("tokenauth: entry %q: want token=user:role:tenants", entry)
		}
		switch parts[1] {
		case RoleViewer, RoleOperator, RoleAdmin:
		default:
			return nil, fmt.Errorf("tokenauth: entry %q: unknown role %q", entry, parts[1])
		}
		out[tok] = User{UserID: parts[0], Role: parts[1], Tenants: strings.Split(parts[2], "|")}
	}
	return out, nil
}

// Middleware authenticates "Authorization: Bearer <token>". A request
// without a token passes unauthenticated (the server answers 401 to
// every operation but the public ones); a wrong token gets 401 here.
func Middleware(tokens map[string]User) func(http.Handler) http.Handler {
	type entry struct {
		hash [32]byte
		user User
	}
	var known []entry
	for t, u := range tokens {
		known = append(known, entry{sha256.Sum256([]byte(t)), u})
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			if h == "" {
				next.ServeHTTP(w, r)
				return
			}
			tok, ok := strings.CutPrefix(h, "Bearer ")
			if !ok {
				apierror.Unauthenticated(w, "bearer token required")
				return
			}
			sum := sha256.Sum256([]byte(tok))
			for _, e := range known {
				if subtle.ConstantTimeCompare(sum[:], e.hash[:]) == 1 {
					next.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), e.user)))
					return
				}
			}
			apierror.Unauthenticated(w, "unknown token")
		})
	}
}

// adminOnly are the changes of global data that every tenant shares:
// server settings, PKI, releases, feeds and detection directories.
var adminOnly = map[string]bool{
	authz.OpUploadRelease:        true,
	authz.OpSetUpdateSettings:    true,
	authz.OpChangeAgentTlsAnchor: true,
	authz.OpUpdateTlsEndpoint:    true,
	authz.OpPutIntegrityPolicy:   true,
	authz.OpCreateFeedServer:     true,
	authz.OpUpdateFeedServer:     true,
	authz.OpDeleteFeedServer:     true,
	authz.OpTrustFeedServerKey:   true,
	authz.OpRematchFeedServer:    true,
	authz.OpCreateDetectDir:      true,
	authz.OpUpdateDetectDir:      true,
	authz.OpDeleteDetectDir:      true,
}

// Authorizer decides by role and gives the request the user's tenants as
// its data scope.
type Authorizer struct{}

var _ authz.Authorizer = Authorizer{}

// Authorize implements authz.Authorizer.
func (Authorizer) Authorize(_ context.Context, p auth.Principal, req authz.Request) (authz.Decision, error) {
	u, ok := p.(User)
	if !ok {
		return authz.Decision{}, fmt.Errorf("principal %s is not a token user: %w", p.ID(), authz.ErrForbidden)
	}
	read := readOnly(req.Operation)
	switch {
	case u.Role == RoleAdmin:
	case adminOnly[req.Operation]:
		return authz.Decision{}, fmt.Errorf("%s needs the admin role: %w", req.Operation, authz.ErrForbidden)
	case u.Role == RoleViewer && !read:
		return authz.Decision{}, fmt.Errorf("%s needs the operator role: %w", req.Operation, authz.ErrForbidden)
	}
	if slices.Contains(u.Tenants, "*") {
		return authz.Decision{Scope: scope.All()}, nil
	}
	return authz.Decision{Scope: scope.Of(u.Tenants...)}, nil
}

func readOnly(op string) bool {
	for _, p := range []string{"Get", "List", "Export"} {
		if strings.HasPrefix(op, p) {
			return true
		}
	}
	return false
}
