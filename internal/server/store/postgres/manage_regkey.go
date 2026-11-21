// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

const mgRegisterKeyColumns = `id, name, public_key, target_kind, expires_at, allowed_cidrs, max_uses,
	used_count, approval, allow_relaxed_tls, default_group, default_tags, created_by, created_at, revoked_at`

// mgScanRegisterKey scans mgRegisterKeyColumns followed by extra.
func mgScanRegisterKey(r mgRow, extra ...any) (store.RegisterKey, error) {
	var k store.RegisterKey
	var target, approval string
	dest := []any{&k.ID, &k.Name, &k.PublicKey, &target, &k.ExpiresAt, &k.AllowedCIDRs, &k.MaxUses,
		&k.UsedCount, &approval, &k.AllowRelaxedTLS, &k.DefaultGroup, &k.DefaultTags, &k.CreatedBy,
		&k.CreatedAt, &k.RevokedAt}
	if err := r.Scan(append(dest, extra...)...); err != nil {
		return store.RegisterKey{}, err
	}
	k.Target = store.AgentKind(target)
	k.Approval = store.ApprovalMode(approval)
	k.ExpiresAt = mgUTCPtr(k.ExpiresAt)
	k.RevokedAt = mgUTCPtr(k.RevokedAt)
	k.CreatedAt = k.CreatedAt.UTC()
	if k.AllowedCIDRs == nil {
		k.AllowedCIDRs = []netip.Prefix{}
	}
	if k.DefaultTags == nil {
		k.DefaultTags = []string{}
	}
	return k, nil
}

// CreateRegisterKey implements store.RegisterKeys.
func (d *DB) CreateRegisterKey(ctx context.Context, k store.RegisterKey) (store.RegisterKey, error) {
	if len(k.ID) != store.RegisterKeyIDLen {
		return store.RegisterKey{}, fmt.Errorf("postgres: create register key: id length %d: %w", len(k.ID), store.ErrInvalid)
	}
	cidrs := make([]netip.Prefix, 0, len(k.AllowedCIDRs))
	for _, p := range k.AllowedCIDRs {
		if !p.IsValid() {
			return store.RegisterKey{}, fmt.Errorf("postgres: create register key: invalid prefix: %w", store.ErrInvalid)
		}
		cidrs = append(cidrs, p.Masked())
	}
	tags := k.DefaultTags
	if tags == nil {
		tags = []string{}
	}
	row := d.q.QueryRow(ctx, `
		INSERT INTO register_keys (id, name, public_key, target_kind, expires_at, allowed_cidrs, max_uses,
			used_count, approval, allow_relaxed_tls, default_group, default_tags, created_by, created_at, revoked_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 0, $8, $9, $10, $11, $12, $13, NULL)
		RETURNING `+mgRegisterKeyColumns,
		k.ID, k.Name, k.PublicKey, string(k.Target), mgTimePtr(k.ExpiresAt), cidrs, k.MaxUses,
		string(k.Approval), k.AllowRelaxedTLS, k.DefaultGroup, tags, k.CreatedBy, mgOrNow(k.CreatedAt))
	out, err := mgScanRegisterKey(row)
	if err != nil {
		return store.RegisterKey{}, mgErr("create register key", err)
	}
	return out, nil
}

// GetRegisterKey implements store.RegisterKeys.
func (d *DB) GetRegisterKey(ctx context.Context, id string) (store.RegisterKey, error) {
	k, err := mgScanRegisterKey(d.q.QueryRow(ctx,
		`SELECT `+mgRegisterKeyColumns+` FROM register_keys WHERE id = $1`, id))
	if err != nil {
		return store.RegisterKey{}, mgErr("get register key", err)
	}
	return k, nil
}

const mgRegisterKeyWhere = `
	WHERE ($1 = '' OR strpos(lower(name), lower($1)) > 0 OR strpos(lower(id), lower($1)) > 0)
	  AND ($2 = '' OR target_kind = $2)`

// ListRegisterKeys implements store.RegisterKeys.
func (d *DB) ListRegisterKeys(ctx context.Context, f store.RegisterKeyFilter, p store.Page) ([]store.RegisterKey, int, error) {
	p = p.Normalize()
	args := []any{f.Q, string(f.Target)}
	rows, err := d.q.Query(ctx, `SELECT `+mgRegisterKeyColumns+`, count(*) OVER () FROM register_keys`+
		mgRegisterKeyWhere+` ORDER BY created_at DESC, id LIMIT $3 OFFSET $4`,
		append(args, p.Limit, p.Offset)...)
	if err != nil {
		return nil, 0, mgErr("list register keys", err)
	}
	defer rows.Close()
	out := []store.RegisterKey{}
	total := 0
	for rows.Next() {
		k, err := mgScanRegisterKey(rows, &total)
		if err != nil {
			return nil, 0, mgErr("list register keys", err)
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, mgErr("list register keys", err)
	}
	if len(out) == 0 && p.Offset > 0 {
		if err := d.q.QueryRow(ctx, `SELECT count(*) FROM register_keys`+mgRegisterKeyWhere, args...).Scan(&total); err != nil {
			return nil, 0, mgErr("list register keys", err)
		}
	}
	return out, total, nil
}

// RevokeRegisterKey implements store.RegisterKeys.
func (d *DB) RevokeRegisterKey(ctx context.Context, id string, at time.Time) error {
	tag, err := d.q.Exec(ctx,
		`UPDATE register_keys SET revoked_at = coalesce(revoked_at, $2) WHERE id = $1`, id, at.UTC())
	return mgExactlyOne("revoke register key", tag, err)
}

// ConsumeRegisterKey implements store.RegisterKeys.
func (d *DB) ConsumeRegisterKey(ctx context.Context, id string, now time.Time) (store.RegisterKey, error) {
	// A single conditional UPDATE: concurrent callers serialize on the row
	// lock and the WHERE clause is re-checked against the committed row, so
	// at most max_uses calls succeed.
	k, err := mgScanRegisterKey(d.q.QueryRow(ctx, `
		UPDATE register_keys SET used_count = used_count + 1
		WHERE id = $1
		  AND revoked_at IS NULL
		  AND (expires_at IS NULL OR expires_at > $2)
		  AND (max_uses = 0 OR used_count < max_uses)
		RETURNING `+mgRegisterKeyColumns, id, now.UTC()))
	if err == nil {
		return k, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return store.RegisterKey{}, mgErr("consume register key", err)
	}
	cur, err := d.GetRegisterKey(ctx, id)
	if err != nil {
		return store.RegisterKey{}, err
	}
	if reason := cur.Usable(now); reason != nil {
		return store.RegisterKey{}, fmt.Errorf("postgres: consume register key: %w", reason)
	}
	// The row changed between the two statements; report it as used up
	// rather than retrying.
	return store.RegisterKey{}, fmt.Errorf("postgres: consume register key: %w", store.ErrRegisterKeyExhausted)
}

// CreateEnrollSession implements store.EnrollSessions.
func (d *DB) CreateEnrollSession(ctx context.Context, s store.EnrollSession) (store.EnrollSession, error) {
	if s.ID == "" {
		id, err := uuid.NewRandom()
		if err != nil {
			return store.EnrollSession{}, fmt.Errorf("postgres: create enroll session: %w", err)
		}
		s.ID = id.String()
	}
	s.CreatedAt = mgOrNow(s.CreatedAt)
	s.ExpiresAt = s.ExpiresAt.UTC()
	if s.State == nil {
		s.State = []byte{}
	}
	_, err := d.q.Exec(ctx,
		`INSERT INTO enroll_sessions (id, state, created_at, expires_at) VALUES ($1, $2, $3, $4)`,
		s.ID, s.State, s.CreatedAt, s.ExpiresAt)
	if err != nil {
		return store.EnrollSession{}, mgErr("create enroll session", err)
	}
	return s, nil
}

// TakeEnrollSession implements store.EnrollSessions.
func (d *DB) TakeEnrollSession(ctx context.Context, id string, now time.Time) (store.EnrollSession, error) {
	s := store.EnrollSession{}
	err := d.q.QueryRow(ctx,
		`DELETE FROM enroll_sessions WHERE id = $1 RETURNING id::text, state, created_at, expires_at`, id).
		Scan(&s.ID, &s.State, &s.CreatedAt, &s.ExpiresAt)
	if err != nil {
		return store.EnrollSession{}, mgErr("take enroll session", err)
	}
	s.CreatedAt, s.ExpiresAt = s.CreatedAt.UTC(), s.ExpiresAt.UTC()
	if !now.Before(s.ExpiresAt) {
		return store.EnrollSession{}, mgNotFound("take enroll session")
	}
	return s, nil
}

// DeleteExpiredEnrollSessions implements store.EnrollSessions.
func (d *DB) DeleteExpiredEnrollSessions(ctx context.Context, now time.Time) (int64, error) {
	tag, err := d.q.Exec(ctx, `DELETE FROM enroll_sessions WHERE expires_at <= $1`, now.UTC())
	if err != nil {
		return 0, mgErr("delete expired enroll sessions", err)
	}
	return tag.RowsAffected(), nil
}
