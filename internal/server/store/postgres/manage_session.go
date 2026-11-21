// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

func mgSessionHash(id string) []byte {
	h := sha256.Sum256([]byte(id))
	return h[:]
}

// CreateSession implements store.Sessions.
func (d *DB) CreateSession(ctx context.Context, principalID, principalName string, expiresAt time.Time) (store.Session, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return store.Session{}, fmt.Errorf("postgres: create session: %w", err)
	}
	s := store.Session{
		ID:            base64.RawURLEncoding.EncodeToString(raw[:]),
		PrincipalID:   principalID,
		PrincipalName: principalName,
		CreatedAt:     mgNow(),
		ExpiresAt:     expiresAt.UTC(),
	}
	_, err := d.q.Exec(ctx, `
		INSERT INTO sessions (id_hash, principal_id, principal_name, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5)`,
		mgSessionHash(s.ID), s.PrincipalID, s.PrincipalName, s.CreatedAt, s.ExpiresAt)
	if err != nil {
		return store.Session{}, mgErr("create session", err)
	}
	return s, nil
}

// GetSession implements store.Sessions.
func (d *DB) GetSession(ctx context.Context, id string, now time.Time) (store.Session, error) {
	s := store.Session{ID: id}
	err := d.q.QueryRow(ctx, `
		SELECT principal_id, principal_name, created_at, expires_at
		FROM sessions WHERE id_hash = $1 AND expires_at > $2`,
		mgSessionHash(id), now.UTC()).
		Scan(&s.PrincipalID, &s.PrincipalName, &s.CreatedAt, &s.ExpiresAt)
	if err != nil {
		return store.Session{}, mgErr("get session", err)
	}
	s.CreatedAt, s.ExpiresAt = s.CreatedAt.UTC(), s.ExpiresAt.UTC()
	return s, nil
}

// DeleteSession implements store.Sessions.
func (d *DB) DeleteSession(ctx context.Context, id string) error {
	_, err := d.q.Exec(ctx, `DELETE FROM sessions WHERE id_hash = $1`, mgSessionHash(id))
	return mgErr("delete session", err)
}

// DeleteExpiredSessions implements store.Sessions.
func (d *DB) DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	tag, err := d.q.Exec(ctx, `DELETE FROM sessions WHERE expires_at <= $1`, now.UTC())
	if err != nil {
		return 0, mgErr("delete expired sessions", err)
	}
	return tag.RowsAffected(), nil
}
