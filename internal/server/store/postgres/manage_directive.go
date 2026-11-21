// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

const mgDirectiveColumns = `id::text, agent_id::text, type, payload, coalesce(dedupe_key, ''),
	created_at, delivered_at, acked_at, expires_at`

func mgScanDirective(r mgRow) (store.Directive, error) {
	var d store.Directive
	var payload []byte
	if err := r.Scan(&d.ID, &d.AgentID, &d.Type, &payload, &d.DedupeKey, &d.CreatedAt,
		&d.DeliveredAt, &d.AckedAt, &d.ExpiresAt); err != nil {
		return store.Directive{}, err
	}
	d.Payload = json.RawMessage(payload)
	d.CreatedAt = d.CreatedAt.UTC()
	d.DeliveredAt = mgUTCPtr(d.DeliveredAt)
	d.AckedAt = mgUTCPtr(d.AckedAt)
	d.ExpiresAt = mgUTCPtr(d.ExpiresAt)
	return d, nil
}

// mgDirectiveIDs keeps the ids that are UUIDs; anything else cannot name a
// directive.
func mgDirectiveIDs(ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, err := uuid.Parse(id); err == nil {
			out = append(out, id)
		}
	}
	return out
}

// EnqueueDirective implements store.DirectiveQueue.
func (d *DB) EnqueueDirective(ctx context.Context, in store.Directive) (store.Directive, bool, error) {
	if in.AgentID == "" || in.Type == "" {
		return store.Directive{}, false, fmt.Errorf("postgres: enqueue directive: agent and type are required: %w", store.ErrInvalid)
	}
	if len(in.Payload) == 0 || !json.Valid(in.Payload) {
		return store.Directive{}, false, fmt.Errorf("postgres: enqueue directive: payload is not JSON: %w", store.ErrInvalid)
	}
	if in.ID == "" {
		id, err := mgNewID()
		if err != nil {
			return store.Directive{}, false, err
		}
		in.ID = id
	}
	created := mgOrNow(in.CreatedAt)
	var out store.Directive
	var inserted bool
	err := d.mgInTx(ctx, func(tx *DB) error {
		if in.DedupeKey != "" {
			// An expired directive is no longer pending and must not block
			// a new one with the same key.
			if _, err := tx.q.Exec(ctx, `
				DELETE FROM directives
				WHERE agent_id = $1 AND dedupe_key = $2 AND acked_at IS NULL AND expires_at <= $3`,
				in.AgentID, in.DedupeKey, created); err != nil {
				return mgErr("enqueue directive", err)
			}
		}
		rows, err := tx.q.Query(ctx, `
			INSERT INTO directives (id, agent_id, type, payload, dedupe_key, created_at, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (agent_id, dedupe_key) WHERE acked_at IS NULL AND dedupe_key IS NOT NULL DO NOTHING
			RETURNING `+mgDirectiveColumns,
			in.ID, in.AgentID, in.Type, []byte(in.Payload), mgText(in.DedupeKey), created, mgTimePtr(in.ExpiresAt))
		if err != nil {
			return mgErr("enqueue directive", err)
		}
		for rows.Next() {
			if out, err = mgScanDirective(rows); err != nil {
				rows.Close()
				return mgErr("enqueue directive", err)
			}
			inserted = true
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return mgErr("enqueue directive", err)
		}
		if inserted {
			return nil
		}
		out, err = mgScanDirective(tx.q.QueryRow(ctx, `
			SELECT `+mgDirectiveColumns+` FROM directives
			WHERE agent_id = $1 AND dedupe_key = $2 AND acked_at IS NULL`, in.AgentID, in.DedupeKey))
		return mgErr("enqueue directive", err)
	})
	if err != nil {
		return store.Directive{}, false, err
	}
	return out, inserted, nil
}

// ListPendingDirectives implements store.DirectiveQueue.
func (d *DB) ListPendingDirectives(ctx context.Context, agentID string, now time.Time, limit int) ([]store.Directive, error) {
	var lim any
	if limit > 0 {
		lim = limit
	}
	rows, err := d.q.Query(ctx, `
		SELECT `+mgDirectiveColumns+` FROM directives
		WHERE agent_id = $1 AND acked_at IS NULL AND (expires_at IS NULL OR expires_at > $2)
		ORDER BY created_at, id
		LIMIT $3`, agentID, now.UTC(), lim)
	if err != nil {
		return nil, mgErr("list pending directives", err)
	}
	defer rows.Close()
	out := []store.Directive{}
	for rows.Next() {
		dir, err := mgScanDirective(rows)
		if err != nil {
			return nil, mgErr("list pending directives", err)
		}
		out = append(out, dir)
	}
	if err := rows.Err(); err != nil {
		return nil, mgErr("list pending directives", err)
	}
	return out, nil
}

// MarkDirectivesDelivered implements store.DirectiveQueue.
func (d *DB) MarkDirectivesDelivered(ctx context.Context, agentID string, ids []string, at time.Time) error {
	ids = mgDirectiveIDs(ids)
	if len(ids) == 0 {
		return nil
	}
	_, err := d.q.Exec(ctx, `
		UPDATE directives SET delivered_at = $3
		WHERE agent_id = $1 AND id = ANY($2::uuid[]) AND acked_at IS NULL`,
		agentID, ids, mgOrNow(at))
	return mgErr("mark directives delivered", err)
}

// AckDirectives implements store.DirectiveQueue.
func (d *DB) AckDirectives(ctx context.Context, agentID string, ids []string, at time.Time) (int64, error) {
	ids = mgDirectiveIDs(ids)
	if len(ids) == 0 {
		return 0, nil
	}
	tag, err := d.q.Exec(ctx, `
		UPDATE directives SET acked_at = $3
		WHERE agent_id = $1 AND id = ANY($2::uuid[]) AND acked_at IS NULL`,
		agentID, ids, mgOrNow(at))
	if err != nil {
		return 0, mgErr("ack directives", err)
	}
	return tag.RowsAffected(), nil
}

// DeleteExpiredDirectives implements store.DirectiveQueue.
func (d *DB) DeleteExpiredDirectives(ctx context.Context, now, ackedBefore time.Time) (int64, error) {
	tag, err := d.q.Exec(ctx, `
		DELETE FROM directives WHERE expires_at <= $1 OR acked_at <= $2`, now.UTC(), ackedBefore.UTC())
	if err != nil {
		return 0, mgErr("delete expired directives", err)
	}
	return tag.RowsAffected(), nil
}

// PutAgentEnrollment implements store.AgentEnrollments.
func (d *DB) PutAgentEnrollment(ctx context.Context, e store.AgentEnrollment) error {
	if len(e.CSR) == 0 {
		return fmt.Errorf("postgres: put agent enrollment: no CSR: %w", store.ErrInvalid)
	}
	tags := e.DefaultTags
	if tags == nil {
		tags = []string{}
	}
	_, err := d.q.Exec(ctx, `
		INSERT INTO agent_enrollments (agent_id, csr, allow_relaxed_tls, default_group, default_tags, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (agent_id) DO UPDATE SET csr = excluded.csr, allow_relaxed_tls = excluded.allow_relaxed_tls,
			default_group = excluded.default_group, default_tags = excluded.default_tags,
			created_at = excluded.created_at`,
		e.AgentID, e.CSR, e.AllowRelaxedTLS, e.DefaultGroup, tags, mgOrNow(e.CreatedAt))
	return mgErr("put agent enrollment", err)
}

// GetAgentEnrollment implements store.AgentEnrollments.
func (d *DB) GetAgentEnrollment(ctx context.Context, agentID string) (store.AgentEnrollment, error) {
	var e store.AgentEnrollment
	err := d.q.QueryRow(ctx, `
		SELECT agent_id::text, csr, allow_relaxed_tls, default_group, default_tags, created_at
		FROM agent_enrollments WHERE agent_id = $1`, agentID).
		Scan(&e.AgentID, &e.CSR, &e.AllowRelaxedTLS, &e.DefaultGroup, &e.DefaultTags, &e.CreatedAt)
	if err != nil {
		return store.AgentEnrollment{}, mgErr("get agent enrollment", err)
	}
	if e.DefaultTags == nil {
		e.DefaultTags = []string{}
	}
	e.CreatedAt = e.CreatedAt.UTC()
	return e, nil
}
