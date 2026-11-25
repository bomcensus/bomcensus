// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package authz is the authorization step of the admin API.
//
// Every operation except the public ones (Public) needs a principal
// (auth.FromContext). For those, the server calls the Authorizer once per
// request, before the handler runs, with the operation id from
// api/openapi/admin.yaml (the Op* constants). The Decision carries the data
// scope the request may see; the store applies it to every query, so an
// Authorizer decides per operation and per tenant without knowing how the
// data is stored.
package authz

import (
	"context"
	"errors"

	"github.com/bomcensus/bomcensus/server/auth"
	"github.com/bomcensus/bomcensus/server/scope"
)

// ErrForbidden is returned (wrapped) by an Authorizer that denies a request.
// The API answers 403; any other error answers 500.
var ErrForbidden = errors.New("authz: forbidden")

// Request is the operation a principal wants to perform.
type Request struct {
	// Operation is the operationId (one of the Op* constants).
	Operation string
	Method    string
	// Path is the request path, Params its path parameters by name (as
	// in admin.yaml, for example "id").
	Path   string
	Params map[string]string
}

// Decision is the outcome of an allowed request.
type Decision struct {
	// Scope is the data the request may read and change. The zero value
	// is the empty scope: lists are empty and every scoped record is not
	// found. Global data (advisories, PKI, releases, server settings) is
	// not scoped; deny the operations that change it instead.
	Scope scope.Scope
}

// Authorizer decides whether a principal may perform an operation.
type Authorizer interface {
	// Authorize returns the decision for p, which is never nil. A denial
	// is an error wrapping ErrForbidden.
	Authorize(ctx context.Context, p auth.Principal, req Request) (Decision, error)
}

// AuthorizerFunc adapts a function to Authorizer.
type AuthorizerFunc func(ctx context.Context, p auth.Principal, req Request) (Decision, error)

// Authorize implements Authorizer.
func (f AuthorizerFunc) Authorize(ctx context.Context, p auth.Principal, req Request) (Decision, error) {
	return f(ctx, p, req)
}

// AllowAll allows every operation on all data. It is the default.
var AllowAll Authorizer = AuthorizerFunc(func(context.Context, auth.Principal, Request) (Decision, error) {
	return Decision{Scope: scope.All()}, nil
})

// IsPublic reports whether op needs no principal (security: [] in
// admin.yaml). The Authorizer is not called for it.
func IsPublic(op string) bool { return publicOps[op] }

// Operations returns every operation id, sorted.
func Operations() []string { return append([]string(nil), operations...) }
