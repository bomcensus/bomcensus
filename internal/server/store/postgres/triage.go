// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

var _ store.Triage = (*DB)(nil)

const trCols = `r.id::text, r.vuln_id, r.scope_kind, r.scope_value, r.purl_like, r.status, r.justification, r.note,
	r.expires_at, r.expired_at, r.created_by, r.created_at, r.revoked_at, r.revoked_by`

func trScan(row mgRow, r *store.TriageRule, extra ...any) error {
	dest := append([]any{&r.ID, &r.VulnID, &r.ScopeKind, &r.ScopeValue, &r.PURLLike, &r.Status, &r.Justification, &r.Note,
		&r.ExpiresAt, &r.ExpiredAt, &r.CreatedBy, &r.CreatedAt, &r.RevokedAt, &r.RevokedBy}, extra...)
	if err := row.Scan(dest...); err != nil {
		return err
	}
	r.ExpiresAt, r.ExpiredAt, r.RevokedAt = mgUTCPtr(r.ExpiresAt), mgUTCPtr(r.ExpiredAt), mgUTCPtr(r.RevokedAt)
	r.CreatedAt = r.CreatedAt.UTC()
	return nil
}

// trScope matches the open findings f (with asset a and component c) in
// the scope of rule r.
const trScope = `f.resolved_at IS NULL AND f.vuln_id = r.vuln_id
	AND ((r.scope_kind = 'asset' AND r.scope_value = f.asset_id::text)
		OR (r.scope_kind = 'group' AND a.group_name <> '' AND r.scope_value = a.group_name)
		OR (r.scope_kind = 'purl' AND split_part(c.purl, '?', 1) LIKE r.purl_like))`

const trFindingsJoin = `findings f JOIN assets a ON a.id = f.asset_id JOIN components c ON c.id = f.component_id`

func (d *DB) trEvent(ctx context.Context, ruleID, kind, actor string, at time.Time) error {
	_, err := d.q.Exec(ctx, `
		INSERT INTO triage_events (rule_id, kind, at, actor, findings)
		SELECT r.id, $2, $3, $4, (SELECT count(*) FROM `+trFindingsJoin+` WHERE `+trScope+`)
		FROM triage_rules r WHERE r.id = $1`,
		ruleID, kind, at.UTC(), actor)
	return mgErr("record triage event", err)
}

// CreateTriageRule implements store.Triage.
func (d *DB) CreateTriageRule(ctx context.Context, r store.TriageRule) (store.TriageRule, error) {
	id, err := mgNewID()
	if err != nil {
		return store.TriageRule{}, err
	}
	if r.Status == "" {
		r.Status = store.TriageStatusNotAffected
	}
	var out store.TriageRule
	err = d.mgInTx(ctx, func(tx *DB) error {
		if err := trScan(tx.q.QueryRow(ctx, `
			INSERT INTO triage_rules AS r (id, vuln_id, scope_kind, scope_value, purl_like, status, justification, note,
				expires_at, created_by, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			RETURNING `+trCols,
			id, r.VulnID, r.ScopeKind, r.ScopeValue, r.PURLLike, r.Status, r.Justification, r.Note,
			mgTimePtr(r.ExpiresAt), r.CreatedBy, mgOrNow(r.CreatedAt)), &out); err != nil {
			return mgErr("create triage rule", err)
		}
		return tx.trEvent(ctx, out.ID, store.TriageEventCreated, out.CreatedBy, out.CreatedAt)
	})
	return out, err
}

// RevokeTriageRule implements store.Triage.
func (d *DB) RevokeTriageRule(ctx context.Context, id, by string, at time.Time) (store.TriageRule, error) {
	var out store.TriageRule
	err := d.mgInTx(ctx, func(tx *DB) error {
		cur, err := tx.GetTriageRule(ctx, id)
		if err != nil {
			return err
		}
		if cur.RevokedAt != nil {
			return fmt.Errorf("postgres: revoke triage rule: already revoked: %w", store.ErrInvalidState)
		}
		// The event counts the findings the rule decided before it ends.
		if err := tx.trEvent(ctx, id, store.TriageEventRevoked, by, at); err != nil {
			return err
		}
		err = trScan(tx.q.QueryRow(ctx, `
			UPDATE triage_rules r SET revoked_at = $2, revoked_by = $3 WHERE r.id = $1 RETURNING `+trCols,
			id, at.UTC(), by), &out)
		return mgErr("revoke triage rule", err)
	})
	return out, err
}

// GetTriageRule implements store.Triage.
func (d *DB) GetTriageRule(ctx context.Context, id string) (store.TriageRule, error) {
	var r store.TriageRule
	err := trScan(d.q.QueryRow(ctx, `SELECT `+trCols+` FROM triage_rules r WHERE r.id = $1`, id), &r)
	return r, mgErr("get triage rule", err)
}

// ListTriageRules implements store.Triage.
func (d *DB) ListTriageRules(ctx context.Context, at time.Time, includeRevoked bool) ([]store.TriageRuleRow, error) {
	rows, err := d.q.Query(ctx, `
		SELECT `+trCols+`, coalesce(n.findings, 0), coalesce(n.assets, 0)
		FROM triage_rules r
		LEFT JOIN LATERAL (
			SELECT count(*) AS findings, count(DISTINCT f.asset_id) AS assets FROM `+trFindingsJoin+`
			WHERE `+trScope+` AND (SELECT t.rule_id FROM triage_rule_for(f.vuln_id, f.asset_id, a.group_name, c.purl, $1) t) = r.id
		) n ON r.revoked_at IS NULL
		WHERE $2 OR r.revoked_at IS NULL
		ORDER BY r.created_at DESC, r.id DESC`, mgOrNow(at), includeRevoked)
	if err != nil {
		return nil, mgErr("list triage rules", err)
	}
	defer rows.Close()
	out := []store.TriageRuleRow{}
	for rows.Next() {
		var r store.TriageRuleRow
		if err := trScan(rows, &r.TriageRule, &r.Findings, &r.Assets); err != nil {
			return nil, mgErr("list triage rules", err)
		}
		out = append(out, r)
	}
	return out, mgErr("list triage rules", rows.Err())
}

// ExpireTriageRules implements store.Triage.
func (d *DB) ExpireTriageRules(ctx context.Context, at time.Time) ([]store.TriageEvent, error) {
	var out []store.TriageEvent
	err := d.mgInTx(ctx, func(tx *DB) error {
		rows, err := tx.q.Query(ctx, `
			SELECT r.id::text FROM triage_rules r
			WHERE r.revoked_at IS NULL AND r.expired_at IS NULL AND r.expires_at <= $1
			ORDER BY r.expires_at, r.id
			FOR UPDATE SKIP LOCKED`, at.UTC())
		if err != nil {
			return mgErr("expire triage rules", err)
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return mgErr("expire triage rules", err)
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return mgErr("expire triage rules", err)
		}
		for _, id := range ids {
			var e store.TriageEvent
			if err := trScan(tx.q.QueryRow(ctx, `
				UPDATE triage_rules r SET expired_at = $2 WHERE r.id = $1 RETURNING `+trCols, id, at.UTC()), &e.Rule); err != nil {
				return mgErr("expire triage rules", err)
			}
			// The findings that come back: in the scope and not decided by
			// another active rule.
			if err := tx.q.QueryRow(ctx, `
				WITH ins AS (
					INSERT INTO triage_events (rule_id, kind, at, findings)
					SELECT r.id, 'expired', $2, (
						SELECT count(*) FROM `+trFindingsJoin+`
						WHERE `+trScope+` AND NOT EXISTS (
							SELECT 1 FROM triage_rule_for(f.vuln_id, f.asset_id, a.group_name, c.purl, $2) t
							WHERE t.expires_at IS NULL OR t.expires_at > $2)
					)
					FROM triage_rules r WHERE r.id = $1
					RETURNING id, findings
				)
				SELECT id, findings FROM ins`, id, at.UTC()).Scan(&e.ID, &e.Findings); err != nil {
				return mgErr("expire triage rules", err)
			}
			e.Kind, e.At = store.TriageEventExpired, at.UTC()
			out = append(out, e)
		}
		return nil
	})
	return out, err
}

// ListTriageEvents implements store.Triage.
func (d *DB) ListTriageEvents(ctx context.Context, afterID int64, limit int) ([]store.TriageEvent, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := d.q.Query(ctx, `
		SELECT `+trCols+`, e.id, e.kind, e.at, e.actor, e.findings
		FROM triage_events e JOIN triage_rules r ON r.id = e.rule_id
		WHERE e.id > $1 ORDER BY e.id LIMIT $2`, afterID, limit)
	if err != nil {
		return nil, mgErr("list triage events", err)
	}
	defer rows.Close()
	var out []store.TriageEvent
	for rows.Next() {
		var e store.TriageEvent
		if err := trScan(rows, &e.Rule, &e.ID, &e.Kind, &e.At, &e.Actor, &e.Findings); err != nil {
			return nil, mgErr("list triage events", err)
		}
		e.At = e.At.UTC()
		out = append(out, e)
	}
	return out, mgErr("list triage events", rows.Err())
}
