// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/server/scope"
)

const mgListenColumns = `id::text, address, coalesce(register_key_id, ''), coalesce(agent_id::text, ''), state,
	last_error, last_connected_at, coalesce(lease_owner, ''), lease_expires_at, created_at, scope_id`

// mgListenColumnsT is mgListenColumns through the alias t.
const mgListenColumnsT = `t.id::text, t.address, coalesce(t.register_key_id, ''), coalesce(t.agent_id::text, ''), t.state,
	t.last_error, t.last_connected_at, coalesce(t.lease_owner, ''), t.lease_expires_at, t.created_at, t.scope_id`

// mgScanListen scans mgListenColumns followed by extra.
func mgScanListen(r mgRow, extra ...any) (store.ListenTarget, error) {
	var t store.ListenTarget
	dest := []any{&t.ID, &t.Address, &t.RegisterKeyID, &t.AgentID, &t.State, &t.LastError,
		&t.LastConnectedAt, &t.LeaseOwner, &t.LeaseExpiresAt, &t.CreatedAt, &t.ScopeID}
	if err := r.Scan(append(dest, extra...)...); err != nil {
		return store.ListenTarget{}, err
	}
	t.LastConnectedAt = mgUTCPtr(t.LastConnectedAt)
	t.LeaseExpiresAt = mgUTCPtr(t.LeaseExpiresAt)
	t.CreatedAt = t.CreatedAt.UTC()
	return t, nil
}

func (d *DB) mgQueryListen(ctx context.Context, op, sql string, args ...any) ([]store.ListenTarget, error) {
	rows, err := d.q.Query(ctx, sql, args...)
	if err != nil {
		return nil, mgErr(op, err)
	}
	defer rows.Close()
	out := []store.ListenTarget{}
	for rows.Next() {
		t, err := mgScanListen(rows)
		if err != nil {
			return nil, mgErr(op, err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, mgErr(op, err)
	}
	return out, nil
}

// CreateListenTarget implements store.ListenTargets.
func (d *DB) CreateListenTarget(ctx context.Context, t store.ListenTarget) (store.ListenTarget, error) {
	if t.ID == "" {
		id, err := mgNewID()
		if err != nil {
			return store.ListenTarget{}, err
		}
		t.ID = id
	}
	if t.State == "" {
		t.State = store.ListenNew
	}
	const op = "create listen target"
	s, err := requireScope(ctx, op)
	if err != nil {
		return store.ListenTarget{}, err
	}
	if t.RegisterKeyID != "" {
		k, err := d.GetRegisterKey(ctx, t.RegisterKeyID)
		if err != nil {
			return store.ListenTarget{}, err
		}
		if k.ScopeID != "" {
			t.ScopeID = k.ScopeID
		}
	}
	if t.ScopeID, err = resolveScope(op, s, t.ScopeID); err != nil {
		return store.ListenTarget{}, err
	}
	out, err := mgScanListen(d.q.QueryRow(ctx, `
		INSERT INTO listen_targets (id, address, register_key_id, agent_id, state, created_at, scope_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING `+mgListenColumns,
		t.ID, t.Address, mgText(t.RegisterKeyID), mgText(t.AgentID), t.State, mgOrNow(t.CreatedAt), t.ScopeID))
	if err != nil {
		return store.ListenTarget{}, mgErr(op, err)
	}
	return out, nil
}

// GetListenTarget implements store.ListenTargets.
func (d *DB) GetListenTarget(ctx context.Context, id string) (store.ListenTarget, error) {
	const op = "get listen target"
	q, sc, err := scoped(ctx, op, id)
	if err != nil {
		return store.ListenTarget{}, err
	}
	t, err := mgScanListen(d.q.QueryRow(ctx, `SELECT `+mgListenColumns+` FROM listen_targets WHERE id = $1 AND `+
		sc.col("scope_id"), q.args...))
	if err != nil {
		return store.ListenTarget{}, mgErr(op, err)
	}
	return t, nil
}

// mgListenState is the state as the console shows it: new is connecting.
const mgListenState = `(CASE WHEN t.state = 'new' THEN 'connecting' ELSE t.state END)`

var mgListenSort = map[string]string{
	"address":         "t.address",
	"agent":           "coalesce(a.hostname, '')",
	"state":           mgListenState,
	"createdAt":       "t.created_at",
	"lastConnectedAt": "t.last_connected_at",
}

// mgListenFrom joins the bound agent and filters with $1 q, $2 state, $3
// agent ids (NULL for any) and the scope of the call.
func mgListenFrom(sc sqlScope) string {
	return ` FROM listen_targets t LEFT JOIN agents a ON a.id = t.agent_id AND ` + sc.shared("a.kind", "a.scope_id") + `
	WHERE ($1 = '' OR strpos(lower(t.address), lower($1)) > 0 OR strpos(lower(coalesce(a.hostname, '')), lower($1)) > 0)
	  AND ($2 = '' OR t.state = $2)
	  AND ($3::text[] IS NULL OR t.agent_id::text = ANY ($3::text[]))
	  AND ` + sc.col("t.scope_id")
}

// ListListenTargets implements store.ListenTargets.
func (d *DB) ListListenTargets(ctx context.Context, f store.ListenTargetFilter, p store.Page) ([]store.ListenTarget, int, error) {
	const op = "list listen targets"
	p = p.Normalize()
	order, err := mgOrder(op, f.Sort, "address", mgListenSort, true, "t.address, t.id")
	if err != nil {
		return nil, 0, err
	}
	var ids any
	if f.AgentIDs != nil {
		ids = f.AgentIDs
	}
	q, sc, err := scoped(ctx, op, f.Q, string(f.State), ids)
	if err != nil {
		return nil, 0, err
	}
	args := q.args
	n := len(args)
	rows, err := d.q.Query(ctx, `SELECT `+mgListenColumnsT+`, coalesce(a.hostname, ''), count(*) OVER ()`+mgListenFrom(sc)+
		order+fmt.Sprintf(` LIMIT $%d OFFSET $%d`, n+1, n+2), append(args, p.Limit, p.Offset)...)
	if err != nil {
		return nil, 0, mgErr(op, err)
	}
	defer rows.Close()
	out := []store.ListenTarget{}
	total := 0
	for rows.Next() {
		var host string
		t, err := mgScanListen(rows, &host, &total)
		if err != nil {
			return nil, 0, mgErr(op, err)
		}
		t.AgentHostname = host
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, mgErr(op, err)
	}
	if len(out) == 0 && p.Offset > 0 {
		if err := d.q.QueryRow(ctx, `SELECT count(*)`+mgListenFrom(sc), args[:n]...).Scan(&total); err != nil {
			return nil, 0, mgErr(op, err)
		}
	}
	return out, total, nil
}

// UpdateListenTarget implements store.ListenTargets. A new register key
// must be in the scope of the target.
func (d *DB) UpdateListenTarget(ctx context.Context, t store.ListenTarget) (store.ListenTarget, error) {
	const op = "update listen target"
	cur, err := d.GetListenTarget(ctx, t.ID)
	if err != nil {
		return store.ListenTarget{}, err
	}
	if t.RegisterKeyID != "" {
		k, err := d.GetRegisterKey(ctx, t.RegisterKeyID)
		if err != nil {
			return store.ListenTarget{}, err
		}
		if k.ScopeID != "" && k.ScopeID != cur.ScopeID {
			return store.ListenTarget{}, fmt.Errorf("postgres: %s: register key of another scope: %w", op, scope.ErrOutside)
		}
	}
	q, sc, err := scoped(ctx, op, t.ID, t.Address, mgText(t.RegisterKeyID))
	if err != nil {
		return store.ListenTarget{}, err
	}
	out, err := mgScanListen(d.q.QueryRow(ctx, `
		UPDATE listen_targets SET address = $2, register_key_id = $3,
			state = CASE WHEN address <> $2 THEN 'new' ELSE state END,
			last_error = CASE WHEN address <> $2 THEN '' ELSE last_error END
		WHERE id = $1 AND `+sc.col("scope_id")+`
		RETURNING `+mgListenColumns, q.args...))
	if err != nil {
		return store.ListenTarget{}, mgErr(op, err)
	}
	return out, nil
}

// DeleteListenTarget implements store.ListenTargets.
func (d *DB) DeleteListenTarget(ctx context.Context, id string) error {
	q, sc, err := scoped(ctx, "delete listen target", id)
	if err != nil {
		return err
	}
	tag, err := d.q.Exec(ctx, `DELETE FROM listen_targets WHERE id = $1 AND `+sc.col("scope_id"), q.args...)
	if err != nil {
		return mgDeleteErr("delete listen target", err)
	}
	if tag.RowsAffected() == 0 {
		return mgNotFound("delete listen target")
	}
	return nil
}

// BindListenTargetAgent implements store.ListenTargets.
func (d *DB) BindListenTargetAgent(ctx context.Context, id, agentID string) error {
	q, sc, err := scoped(ctx, "bind listen target agent", id, agentID)
	if err != nil {
		return err
	}
	var bound string
	err = d.q.QueryRow(ctx, `
		UPDATE listen_targets SET agent_id = coalesce(agent_id, $2) WHERE id = $1 AND `+sc.col("scope_id")+`
		RETURNING agent_id::text`, q.args...).Scan(&bound)
	if err != nil {
		return mgErr("bind listen target agent", err)
	}
	if bound != agentID {
		return fmt.Errorf("postgres: bind listen target agent: bound to another agent: %w", store.ErrConflict)
	}
	return nil
}

// AcquireListenLeases implements store.ListenTargets.
func (d *DB) AcquireListenLeases(ctx context.Context, owner string, ttl time.Duration, now time.Time, limit int) ([]store.ListenTarget, error) {
	if owner == "" || ttl <= 0 {
		return nil, fmt.Errorf("postgres: acquire listen leases: %w", store.ErrInvalid)
	}
	if err := requireAll(ctx, "acquire listen leases"); err != nil {
		return nil, err
	}
	var lim any
	if limit > 0 {
		lim = limit
	}
	now = now.UTC()
	var out []store.ListenTarget
	err := d.mgInTx(ctx, func(tx *DB) error {
		// Renew first, then take free leases with SKIP LOCKED. The taking
		// step never waits, so a renewal that waits on a row another
		// replica is taking over always sees that replica finish; there is
		// no lock cycle. The renewal re-checks the owner after waiting, so
		// a lease taken over in the meantime is not renewed.
		if _, err := tx.q.Exec(ctx,
			`UPDATE listen_targets SET lease_expires_at = $2 WHERE lease_owner = $1`,
			owner, now.Add(ttl)); err != nil {
			return mgErr("acquire listen leases", err)
		}
		if _, err := tx.q.Exec(ctx, `
			UPDATE listen_targets SET lease_owner = $1, lease_expires_at = $3
			WHERE id IN (
				SELECT id FROM listen_targets
				WHERE lease_owner IS NULL OR lease_expires_at <= $2
				ORDER BY created_at, id
				LIMIT $4
				FOR UPDATE SKIP LOCKED)`,
			owner, now, now.Add(ttl), lim); err != nil {
			return mgErr("acquire listen leases", err)
		}
		var err error
		out, err = tx.mgQueryListen(ctx, "acquire listen leases",
			`SELECT `+mgListenColumns+` FROM listen_targets WHERE lease_owner = $1 ORDER BY address, id`, owner)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RenewListenLease implements store.ListenTargets.
func (d *DB) RenewListenLease(ctx context.Context, id, owner string, ttl time.Duration, now time.Time) (bool, error) {
	if owner == "" || ttl <= 0 {
		return false, fmt.Errorf("postgres: renew listen lease: %w", store.ErrInvalid)
	}
	if err := requireAll(ctx, "renew listen lease"); err != nil {
		return false, err
	}
	tag, err := d.q.Exec(ctx,
		`UPDATE listen_targets SET lease_expires_at = $3 WHERE id = $1 AND lease_owner = $2`,
		id, owner, now.UTC().Add(ttl))
	if err != nil {
		return false, mgErr("renew listen lease", err)
	}
	if tag.RowsAffected() == 1 {
		return true, nil
	}
	if _, err := d.GetListenTarget(ctx, id); err != nil {
		return false, err
	}
	return false, nil
}

// ReleaseListenLease implements store.ListenTargets.
func (d *DB) ReleaseListenLease(ctx context.Context, id, owner string) error {
	if err := requireAll(ctx, "release listen lease"); err != nil {
		return err
	}
	_, err := d.q.Exec(ctx, `
		UPDATE listen_targets SET lease_owner = NULL, lease_expires_at = NULL
		WHERE id = $1 AND lease_owner = $2`, id, owner)
	return mgErr("release listen lease", err)
}

// RecordListenState implements store.ListenTargets.
func (d *DB) RecordListenState(ctx context.Context, id, owner string, state store.ListenTargetState, lastError string, at time.Time) error {
	if err := requireAll(ctx, "record listen state"); err != nil {
		return err
	}
	tag, err := d.q.Exec(ctx, `
		UPDATE listen_targets SET state = $3, last_error = $4,
			last_connected_at = CASE WHEN $3 = 'connected' THEN $5 ELSE last_connected_at END
		WHERE id = $1 AND lease_owner = $2`,
		id, owner, state, lastError, mgOrNow(at))
	if err != nil {
		return mgErr("record listen state", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	if _, err := d.GetListenTarget(ctx, id); err != nil {
		return err
	}
	return fmt.Errorf("postgres: record listen state: lease not held by %s: %w", owner, store.ErrConflict)
}
