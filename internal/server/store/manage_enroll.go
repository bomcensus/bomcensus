// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package store

import (
	"context"
	"time"
)

// EnrollSession carries the state between enroll/start and enroll/finish.
type EnrollSession struct {
	// ID is handed to an unauthenticated peer, so it is a random UUID (v4),
	// not a time-ordered one.
	ID        string
	State     []byte // opaque to the store
	CreatedAt time.Time
	ExpiresAt time.Time
}

// EnrollSessions stores short-lived enrollment sessions.
type EnrollSessions interface {
	// CreateEnrollSession stores s. ID is generated when empty; CreatedAt
	// defaults to now.
	CreateEnrollSession(ctx context.Context, s EnrollSession) (EnrollSession, error)
	// TakeEnrollSession deletes the session and returns it. A session can be
	// taken once. An expired session is deleted and reported as ErrNotFound.
	TakeEnrollSession(ctx context.Context, id string, now time.Time) (EnrollSession, error)
	// DeleteExpiredEnrollSessions removes sessions that expired at or before
	// now.
	DeleteExpiredEnrollSessions(ctx context.Context, now time.Time) (int64, error)
}
