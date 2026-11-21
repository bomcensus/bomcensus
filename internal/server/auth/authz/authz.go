// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package authz is the single authorization check of the console API. Roles
// can be added here later without changing handlers.
package authz

import (
	"context"
	"errors"

	"github.com/bomcensus/bomcensus/internal/server/auth"
)

// ErrUnauthenticated is returned when the context has no principal.
var ErrUnauthenticated = errors.New("authz: not authenticated")

// ErrForbidden is returned when the principal may not perform the action.
var ErrForbidden = errors.New("authz: forbidden")

// Check reports whether the principal of ctx may perform action on
// resource. Every authenticated principal is allowed everything for now.
func Check(ctx context.Context, action, resource string) error {
	if _, ok := auth.FromContext(ctx); !ok {
		return ErrUnauthenticated
	}
	return nil
}
