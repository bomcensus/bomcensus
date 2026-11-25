// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package scope is the data scope of a request: the set of scope ids whose
// records it may see.
//
// Every scoped record (Register Keys, scan targets, Kubernetes clusters,
// credentials, and the agents and assets that derive from them) belongs to
// exactly one scope id. The admin API puts the scope of the authorization
// decision into the request context; the store reads it on every query of a
// scoped table and fails when the context has none, so a missing scope is
// an error and never a leak. Background work runs with System.
package scope

import (
	"context"
	"errors"
	"regexp"
	"slices"
)

// Default is the scope id of records created without one, and of all
// records that existed before scopes.
const Default = "default"

// ErrNone is returned by the store for a scoped query whose context has no
// scope.
var ErrNone = errors.New("scope: no data scope in context")

// ErrInvalidID is returned for a malformed scope id.
var ErrInvalidID = errors.New("scope: invalid scope id")

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// ValidID reports whether id is a well-formed scope id: 1 to 128 characters
// of letters, digits, '.', '_', ':' and '-', starting with a letter or digit.
func ValidID(id string) bool { return idPattern.MatchString(id) }

// Scope is a set of scope ids, or all of them. The zero value is empty.
type Scope struct {
	all bool
	ids []string
}

// All is the scope of every record.
func All() Scope { return Scope{all: true} }

// Of is the scope of the given ids. Malformed ids are dropped; no ids is
// the empty scope.
func Of(ids ...string) Scope {
	s := Scope{}
	for _, id := range ids {
		if ValidID(id) && !slices.Contains(s.ids, id) {
			s.ids = append(s.ids, id)
		}
	}
	slices.Sort(s.ids)
	return s
}

// IsAll reports whether s contains every scope id.
func (s Scope) IsAll() bool { return s.all }

// IsEmpty reports whether s contains no scope id.
func (s Scope) IsEmpty() bool { return !s.all && len(s.ids) == 0 }

// IDs returns the ids of a scope that is not All, sorted.
func (s Scope) IDs() []string { return slices.Clone(s.ids) }

// Contains reports whether id is in s.
func (s Scope) Contains(id string) bool {
	return s.all || slices.Contains(s.ids, id)
}

// Single returns the only id of s. ok is false for All or for zero or
// several ids.
func (s Scope) Single() (id string, ok bool) {
	if s.all || len(s.ids) != 1 {
		return "", false
	}
	return s.ids[0], true
}

type key struct{}

// With returns ctx carrying s.
func With(ctx context.Context, s Scope) context.Context {
	return context.WithValue(ctx, key{}, s)
}

// System returns ctx carrying All, for server work that is not done on
// behalf of a principal (jobs, the agent API, scanners).
func System(ctx context.Context) context.Context { return With(ctx, All()) }

// From returns the scope of ctx. ok is false when ctx has none.
func From(ctx context.Context) (s Scope, ok bool) {
	s, ok = ctx.Value(key{}).(Scope)
	return s, ok
}

// Require returns the scope of ctx or ErrNone.
func Require(ctx context.Context) (Scope, error) {
	s, ok := From(ctx)
	if !ok {
		return Scope{}, ErrNone
	}
	return s, nil
}

// Resolve picks the scope id of a new record: requested when it is set and
// in s, otherwise the only id of s, otherwise Default when s is All. It
// fails with ErrInvalidID for a malformed id and with ErrOutside when the
// id is not in s or no id can be chosen.
func Resolve(s Scope, requested string) (string, error) {
	if requested != "" {
		if !ValidID(requested) {
			return "", ErrInvalidID
		}
		if !s.Contains(requested) {
			return "", ErrOutside
		}
		return requested, nil
	}
	if id, ok := s.Single(); ok {
		return id, nil
	}
	if s.all {
		return Default, nil
	}
	return "", ErrOutside
}

// ErrOutside is returned for a scope id the request may not use.
var ErrOutside = errors.New("scope: outside the request scope")
