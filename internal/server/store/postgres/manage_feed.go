// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

// GetFeedInstance implements store.FeedServers.
func (d *DB) GetFeedInstance(ctx context.Context) (store.FeedInstance, error) {
	var in store.FeedInstance
	err := d.q.QueryRow(ctx, `SELECT public_key, encrypted_key, created_at FROM feed_instance`).
		Scan(&in.PublicKey, &in.EncryptedKey, &in.CreatedAt)
	if err != nil {
		return store.FeedInstance{}, mgErr("get feed instance", err)
	}
	in.CreatedAt = in.CreatedAt.UTC()
	return in, nil
}

// CreateFeedInstance implements store.FeedServers.
func (d *DB) CreateFeedInstance(ctx context.Context, in store.FeedInstance) (store.FeedInstance, error) {
	_, err := d.q.Exec(ctx, `
		INSERT INTO feed_instance (public_key, encrypted_key, created_at) VALUES ($1, $2, $3)
		ON CONFLICT (id) DO NOTHING`,
		in.PublicKey, in.EncryptedKey, mgOrNow(in.CreatedAt))
	if err != nil {
		return store.FeedInstance{}, mgErr("create feed instance", err)
	}
	return d.GetFeedInstance(ctx)
}

const mgFeedColumns = `id, name, url, builtin, active, enabled, telemetry,
	coalesce(server_key, ''), key_trusted_at, coalesce(presented_key, ''), presented_at,
	status, last_error, last_error_at, last_ok_at, grade, session_expires_at,
	revision, rules_digest, sources::text, status_checked_at, created_at, updated_at`

func mgScanFeedServer(r mgRow) (store.FeedServer, error) {
	var s store.FeedServer
	var sources []byte
	err := r.Scan(&s.ID, &s.Name, &s.URL, &s.Builtin, &s.Active, &s.Enabled, &s.Telemetry,
		&s.ServerKey, &s.KeyTrustedAt, &s.PresentedKey, &s.PresentedAt,
		&s.Status, &s.LastError, &s.LastErrorAt, &s.LastOKAt, &s.Grade, &s.SessionExpiresAt,
		&s.Revision, &s.RulesDigest, &sources, &s.StatusCheckedAt, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return store.FeedServer{}, err
	}
	if err := json.Unmarshal(sources, &s.Sources); err != nil {
		return store.FeedServer{}, fmt.Errorf("feed server sources: %w", err)
	}
	s.KeyTrustedAt, s.PresentedAt = mgUTCPtr(s.KeyTrustedAt), mgUTCPtr(s.PresentedAt)
	s.LastErrorAt, s.LastOKAt = mgUTCPtr(s.LastErrorAt), mgUTCPtr(s.LastOKAt)
	s.SessionExpiresAt, s.StatusCheckedAt = mgUTCPtr(s.SessionExpiresAt), mgUTCPtr(s.StatusCheckedAt)
	s.CreatedAt, s.UpdatedAt = s.CreatedAt.UTC(), s.UpdatedAt.UTC()
	return s, nil
}

// ListFeedServers implements store.FeedServers.
func (d *DB) ListFeedServers(ctx context.Context) ([]store.FeedServer, error) {
	rows, err := d.q.Query(ctx, `SELECT `+mgFeedColumns+` FROM feed_servers ORDER BY builtin DESC, name, id`)
	if err != nil {
		return nil, mgErr("list feed servers", err)
	}
	defer rows.Close()
	out := []store.FeedServer{}
	for rows.Next() {
		s, err := mgScanFeedServer(rows)
		if err != nil {
			return nil, mgErr("list feed servers", err)
		}
		out = append(out, s)
	}
	return out, mgErr("list feed servers", rows.Err())
}

// GetFeedServer implements store.FeedServers.
func (d *DB) GetFeedServer(ctx context.Context, id string) (store.FeedServer, error) {
	s, err := mgScanFeedServer(d.q.QueryRow(ctx, `SELECT `+mgFeedColumns+` FROM feed_servers WHERE id = $1`, id))
	return s, mgErr("get feed server", err)
}

// GetActiveFeedServer implements store.FeedServers.
func (d *DB) GetActiveFeedServer(ctx context.Context) (store.FeedServer, error) {
	s, err := mgScanFeedServer(d.q.QueryRow(ctx, `SELECT `+mgFeedColumns+` FROM feed_servers WHERE active`))
	return s, mgErr("get active feed server", err)
}

// CreateFeedServer implements store.FeedServers.
func (d *DB) CreateFeedServer(ctx context.Context, in store.FeedServerCreate) (store.FeedServer, error) {
	id, err := mgNewID()
	if err != nil {
		return store.FeedServer{}, err
	}
	now := mgNow()
	s, err := mgScanFeedServer(d.q.QueryRow(ctx, `
		INSERT INTO feed_servers (id, name, url, telemetry, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $5)
		RETURNING `+mgFeedColumns,
		id, in.Name, in.URL, in.Telemetry, now))
	return s, mgErr("create feed server", err)
}

// UpdateFeedServer implements store.FeedServers.
func (d *DB) UpdateFeedServer(ctx context.Context, id string, u store.FeedServerUpdate) (store.FeedServer, error) {
	var out store.FeedServer
	err := d.mgInTx(ctx, func(tx *DB) error {
		cur, err := tx.lockFeedServer(ctx, id)
		if err != nil {
			return err
		}
		if u.Enabled != nil && !*u.Enabled && cur.Active {
			return fmt.Errorf("postgres: update feed server: the active server cannot be disabled: %w", store.ErrInvalidState)
		}
		out, err = mgScanFeedServer(tx.q.QueryRow(ctx, `
			UPDATE feed_servers SET
				name = coalesce($2, name),
				enabled = coalesce($3, enabled),
				telemetry = coalesce($4, telemetry),
				updated_at = $5
			WHERE id = $1
			RETURNING `+mgFeedColumns,
			id, u.Name, u.Enabled, u.Telemetry, mgNow()))
		return mgErr("update feed server", err)
	})
	return out, err
}

func (d *DB) lockFeedServer(ctx context.Context, id string) (store.FeedServer, error) {
	s, err := mgScanFeedServer(d.q.QueryRow(ctx, `SELECT `+mgFeedColumns+` FROM feed_servers WHERE id = $1 FOR UPDATE`, id))
	return s, mgErr("get feed server", err)
}

// DeleteFeedServer implements store.FeedServers.
func (d *DB) DeleteFeedServer(ctx context.Context, id string) error {
	return d.mgInTx(ctx, func(tx *DB) error {
		cur, err := tx.lockFeedServer(ctx, id)
		if err != nil {
			return err
		}
		if cur.Builtin || cur.Active {
			return fmt.Errorf("postgres: delete feed server: built-in or active: %w", store.ErrInvalidState)
		}
		_, err = tx.q.Exec(ctx, `DELETE FROM feed_servers WHERE id = $1`, id)
		return mgDeleteErr("delete feed server", err)
	})
}

// ActivateFeedServer implements store.FeedServers.
func (d *DB) ActivateFeedServer(ctx context.Context, id string) (store.FeedServer, error) {
	var out store.FeedServer
	err := d.mgInTx(ctx, func(tx *DB) error {
		// Lock every row so that two activations serialize.
		if _, err := tx.q.Exec(ctx, `SELECT id FROM feed_servers FOR UPDATE`); err != nil {
			return mgErr("activate feed server", err)
		}
		cur, err := tx.GetFeedServer(ctx, id)
		if err != nil {
			return err
		}
		if !cur.Enabled {
			return fmt.Errorf("postgres: activate feed server: disabled: %w", store.ErrInvalidState)
		}
		now := mgNow()
		if _, err := tx.q.Exec(ctx, `UPDATE feed_servers SET active = false, updated_at = $2 WHERE active AND id <> $1`, id, now); err != nil {
			return mgErr("activate feed server", err)
		}
		out, err = mgScanFeedServer(tx.q.QueryRow(ctx, `
			UPDATE feed_servers SET active = true, updated_at = $2 WHERE id = $1 RETURNING `+mgFeedColumns, id, now))
		return mgErr("activate feed server", err)
	})
	return out, err
}

// TrustFeedServerKey implements store.FeedServers.
func (d *DB) TrustFeedServerKey(ctx context.Context, id, key string) (string, error) {
	now := mgNow()
	if _, err := d.q.Exec(ctx, `
		UPDATE feed_servers SET server_key = $2, key_trusted_at = $3, updated_at = $3
		WHERE id = $1 AND server_key IS NULL`,
		id, key, now); err != nil {
		return "", mgErr("trust feed server key", err)
	}
	// A separate statement sees a key another replica stored concurrently.
	var stored *string
	if err := d.q.QueryRow(ctx, `SELECT server_key FROM feed_servers WHERE id = $1`, id).Scan(&stored); err != nil {
		return "", mgErr("trust feed server key", err)
	}
	if stored == nil {
		return "", fmt.Errorf("postgres: trust feed server key: not stored: %w", store.ErrConflict)
	}
	return *stored, nil
}

// RecordFeedServerKeyChange implements store.FeedServers.
func (d *DB) RecordFeedServerKeyChange(ctx context.Context, id, presented string) error {
	now := mgNow()
	tag, err := d.q.Exec(ctx, `
		UPDATE feed_servers SET status = 'key_changed', presented_key = $2,
			presented_at = CASE WHEN presented_key IS DISTINCT FROM $2 THEN $3 ELSE presented_at END,
			grade = '', session_expires_at = NULL, updated_at = $3
		WHERE id = $1`,
		id, presented, now)
	return mgExactlyOne("record feed server key change", tag, err)
}

// AcceptFeedServerKey implements store.FeedServers.
func (d *DB) AcceptFeedServerKey(ctx context.Context, id, key string) (store.FeedServer, error) {
	var out store.FeedServer
	err := d.mgInTx(ctx, func(tx *DB) error {
		cur, err := tx.lockFeedServer(ctx, id)
		if err != nil {
			return err
		}
		if cur.PresentedKey == "" || cur.PresentedKey != key {
			return fmt.Errorf("postgres: accept feed server key: not the presented key: %w", store.ErrInvalidState)
		}
		now := mgNow()
		out, err = mgScanFeedServer(tx.q.QueryRow(ctx, `
			UPDATE feed_servers SET server_key = presented_key, key_trusted_at = $2,
				presented_key = NULL, presented_at = NULL,
				status = 'never', last_error = '', last_error_at = NULL, updated_at = $2
			WHERE id = $1 RETURNING `+mgFeedColumns, id, now))
		return mgErr("accept feed server key", err)
	})
	return out, err
}

// RecordFeedServerOK implements store.FeedServers.
func (d *DB) RecordFeedServerOK(ctx context.Context, id string, s store.FeedSession) error {
	now := mgNow()
	_, err := d.q.Exec(ctx, `
		UPDATE feed_servers SET status = 'connected', last_ok_at = $2, last_error = '', last_error_at = NULL,
			grade = $3, session_expires_at = $4, updated_at = $2
		WHERE id = $1 AND status <> 'key_changed'`,
		id, now, s.Grade, mgTimePtr(&s.ExpiresAt))
	return mgErr("record feed server ok", err)
}

// RecordFeedServerError implements store.FeedServers.
func (d *DB) RecordFeedServerError(ctx context.Context, id, msg string) error {
	now := mgNow()
	_, err := d.q.Exec(ctx, `
		UPDATE feed_servers SET status = 'error', last_error = $2, last_error_at = $3,
			session_expires_at = NULL, updated_at = $3
		WHERE id = $1 AND status <> 'key_changed'`,
		id, msg, now)
	return mgErr("record feed server error", err)
}

// RecordFeedData implements store.FeedServers.
func (d *DB) RecordFeedData(ctx context.Context, id string, fd store.FeedData) error {
	sources := fd.Sources
	if sources == nil {
		sources = []store.FeedSource{}
	}
	b, err := json.Marshal(sources)
	if err != nil {
		return fmt.Errorf("postgres: record feed data: %w", err)
	}
	now := mgNow()
	tag, err := d.q.Exec(ctx, `
		UPDATE feed_servers SET revision = $2, rules_digest = $3, sources = $4::text::jsonb,
			status_checked_at = $5, updated_at = $5
		WHERE id = $1`,
		id, fd.Revision, fd.RulesDigest, string(b), now)
	return mgExactlyOne("record feed data", tag, err)
}
