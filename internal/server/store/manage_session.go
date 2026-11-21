// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package store

import (
	"context"
	"time"
)

// Session is a console login.
type Session struct {
	// ID is the bearer value put in the session cookie: 32 random bytes,
	// unpadded base64url. Only its SHA-256 hash is stored, so a database
	// leak does not reveal usable sessions.
	ID            string
	PrincipalID   string
	PrincipalName string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

// Sessions stores console logins.
type Sessions interface {
	// CreateSession generates a random session ID and stores the session.
	CreateSession(ctx context.Context, principalID, principalName string, expiresAt time.Time) (Session, error)
	// GetSession returns ErrNotFound when the session does not exist or has
	// expired at now.
	GetSession(ctx context.Context, id string, now time.Time) (Session, error)
	// DeleteSession is idempotent.
	DeleteSession(ctx context.Context, id string) error
	// DeleteExpiredSessions removes sessions that expired at or before now
	// and returns how many were removed.
	DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error)
}
