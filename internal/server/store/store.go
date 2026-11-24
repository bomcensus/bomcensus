// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package store defines what the server needs from its database, cut by use
// case, together with the domain types. Implementations live in subpackages;
// nothing outside them knows which database is used.
package store

import (
	"context"
	"errors"
)

// ErrNotFound is returned when a requested record does not exist.
var ErrNotFound = errors.New("store: not found")

// ErrConflict is returned when a write violates a uniqueness rule.
var ErrConflict = errors.New("store: conflict")

// Store is the whole persistence surface of the server.
type Store interface {
	Inventory
	Manage
	Vulns
	Findings
	Triage
	GoSymbols

	// WithTx runs fn in a transaction. The Store passed to fn is bound to that
	// transaction. Returning an error rolls back. Nested calls join the outer
	// transaction.
	WithTx(ctx context.Context, fn func(Store) error) error
}

// Page selects a slice of a list result.
type Page struct {
	Limit  int
	Offset int
}

// Normalize applies the default and maximum page size.
func (p Page) Normalize() Page {
	if p.Limit <= 0 {
		p.Limit = 200
	}
	if p.Limit > 1000 {
		p.Limit = 1000
	}
	if p.Offset < 0 {
		p.Offset = 0
	}
	return p
}
