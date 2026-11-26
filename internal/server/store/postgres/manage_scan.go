// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/server/scope"
)

const mgCredentialColumns = `c.id::text, c.name, c.kind, c.username, c.public_key_fingerprint, c.created_by,
	c.created_at, (SELECT count(*) FROM scan_targets t WHERE t.credential_id = c.id), c.scope_id`

func mgScanCredential(r mgRow, extra ...any) (store.Credential, error) {
	var c store.Credential
	dest := []any{&c.ID, &c.Name, &c.Kind, &c.Username, &c.PublicKeyFingerprint, &c.CreatedBy, &c.CreatedAt, &c.UsedBy, &c.ScopeID}
	if err := r.Scan(append(dest, extra...)...); err != nil {
		return store.Credential{}, err
	}
	c.CreatedAt = c.CreatedAt.UTC()
	return c, nil
}

// CreateCredential implements store.Credentials.
func (d *DB) CreateCredential(ctx context.Context, c store.Credential) (store.Credential, error) {
	if len(c.Secret) == 0 {
		return store.Credential{}, fmt.Errorf("postgres: create credential: no secret: %w", store.ErrInvalid)
	}
	if c.ID == "" {
		id, err := mgNewID()
		if err != nil {
			return store.Credential{}, err
		}
		c.ID = id
	}
	s, err := requireScope(ctx, "create credential")
	if err != nil {
		return store.Credential{}, err
	}
	if c.ScopeID, err = resolveScope("create credential", s, c.ScopeID); err != nil {
		return store.Credential{}, err
	}
	out, err := mgScanCredential(d.q.QueryRow(ctx, `
		INSERT INTO credentials AS c (id, name, kind, username, secret, public_key_fingerprint, created_by,
			created_at, scope_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING `+mgCredentialColumns,
		c.ID, c.Name, c.Kind, c.Username, c.Secret, c.PublicKeyFingerprint, c.CreatedBy, mgOrNow(c.CreatedAt),
		c.ScopeID))
	if err != nil {
		return store.Credential{}, mgErr("create credential", err)
	}
	return out, nil
}

// ListCredentials implements store.Credentials.
func (d *DB) ListCredentials(ctx context.Context) ([]store.Credential, error) {
	q, sc, err := scoped(ctx, "list credentials")
	if err != nil {
		return nil, err
	}
	rows, err := d.q.Query(ctx, `SELECT `+mgCredentialColumns+` FROM credentials c WHERE `+sc.col("c.scope_id")+
		` ORDER BY c.name, c.id`, q.args...)
	if err != nil {
		return nil, mgErr("list credentials", err)
	}
	defer rows.Close()
	out := []store.Credential{}
	for rows.Next() {
		c, err := mgScanCredential(rows)
		if err != nil {
			return nil, mgErr("list credentials", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, mgErr("list credentials", err)
	}
	return out, nil
}

// GetCredential implements store.Credentials.
func (d *DB) GetCredential(ctx context.Context, id string) (store.Credential, error) {
	q, sc, err := scoped(ctx, "get credential", id)
	if err != nil {
		return store.Credential{}, err
	}
	c, err := mgScanCredential(d.q.QueryRow(ctx, `SELECT `+mgCredentialColumns+` FROM credentials c WHERE c.id = $1 AND `+
		sc.col("c.scope_id"), q.args...))
	if err != nil {
		return store.Credential{}, mgErr("get credential", err)
	}
	return c, nil
}

// GetCredentialWithSecret implements store.Credentials.
func (d *DB) GetCredentialWithSecret(ctx context.Context, id string) (store.Credential, error) {
	q, sc, err := scoped(ctx, "get credential", id)
	if err != nil {
		return store.Credential{}, err
	}
	var secret []byte
	c, err := mgScanCredential(d.q.QueryRow(ctx,
		`SELECT `+mgCredentialColumns+`, c.secret FROM credentials c WHERE c.id = $1 AND `+sc.col("c.scope_id"),
		q.args...), &secret)
	if err != nil {
		return store.Credential{}, mgErr("get credential", err)
	}
	c.Secret = secret
	return c, nil
}

// UpdateCredentialSecret implements store.Credentials.
func (d *DB) UpdateCredentialSecret(ctx context.Context, c store.Credential) (store.Credential, error) {
	if len(c.Secret) == 0 {
		return store.Credential{}, fmt.Errorf("postgres: update credential secret: no secret: %w", store.ErrInvalid)
	}
	q, sc, err := scoped(ctx, "update credential secret", c.ID, c.Username, c.Secret, c.PublicKeyFingerprint)
	if err != nil {
		return store.Credential{}, err
	}
	out, err := mgScanCredential(d.q.QueryRow(ctx, `
		UPDATE credentials AS c SET username = $2, secret = $3, public_key_fingerprint = $4
		WHERE c.id = $1 AND `+sc.col("c.scope_id")+`
		RETURNING `+mgCredentialColumns, q.args...))
	if err != nil {
		return store.Credential{}, mgErr("update credential secret", err)
	}
	return out, nil
}

// DeleteCredential implements store.Credentials.
func (d *DB) DeleteCredential(ctx context.Context, id string) error {
	// The foreign key from scan_targets refuses the delete while referenced.
	q, sc, err := scoped(ctx, "delete credential", id)
	if err != nil {
		return err
	}
	tag, err := d.q.Exec(ctx, `DELETE FROM credentials WHERE id = $1 AND `+sc.col("scope_id"), q.args...)
	if err != nil {
		return mgDeleteErr("delete credential", err)
	}
	if tag.RowsAffected() == 0 {
		return mgNotFound("delete credential")
	}
	return nil
}

const mgScanTargetColumns = `id::text, name, address, port, credential_id::text, coalesce(scanner_id::text, ''),
	sudo, host_key, interval_minutes, coalesce(asset_id::text, ''), last_run_at, last_run_result,
	last_run_message, last_run_duration_ms, created_at,
	array(SELECT x.dir_id::text FROM scan_target_detect_dirs x JOIN detect_dirs dd ON dd.id = x.dir_id
		WHERE x.target_id = scan_targets.id ORDER BY dd.path),
	array(SELECT dd.path FROM scan_target_detect_dirs x JOIN detect_dirs dd ON dd.id = x.dir_id
		WHERE x.target_id = scan_targets.id ORDER BY dd.path), integrity, scope_id`

func mgScanScanTarget(r mgRow, extra ...any) (store.ScanTarget, error) {
	var t store.ScanTarget
	var runAt *time.Time
	var result *string
	var message string
	var durMS int64
	dest := []any{&t.ID, &t.Name, &t.Address, &t.Port, &t.CredentialID, &t.ScannerID, &t.Sudo, &t.HostKey,
		&t.IntervalMinutes, &t.AssetID, &runAt, &result, &message, &durMS, &t.CreatedAt,
		&t.DetectDirIDs, &t.DetectPaths, &t.Integrity, &t.ScopeID}
	if err := r.Scan(append(dest, extra...)...); err != nil {
		return store.ScanTarget{}, err
	}
	t.CreatedAt = t.CreatedAt.UTC()
	if runAt != nil {
		t.LastRun = &store.ScanRun{
			At:       runAt.UTC(),
			Result:   store.ScanResult(mgDeref(result)),
			Message:  message,
			Duration: time.Duration(durMS) * time.Millisecond,
		}
	}
	return t, nil
}

// CreateScanTarget implements store.ScanTargets.
func (d *DB) CreateScanTarget(ctx context.Context, t store.ScanTarget) (store.ScanTarget, error) {
	if t.ID == "" {
		id, err := mgNewID()
		if err != nil {
			return store.ScanTarget{}, err
		}
		t.ID = id
	}
	const op = "create scan target"
	s, err := requireScope(ctx, op)
	if err != nil {
		return store.ScanTarget{}, err
	}
	if t.ScopeID, err = resolveScope(op, s, t.ScopeID); err != nil {
		return store.ScanTarget{}, err
	}
	if err := d.mgCredentialIn(ctx, op, t.CredentialID, t.ScopeID); err != nil {
		return store.ScanTarget{}, err
	}
	out, err := mgScanScanTarget(d.q.QueryRow(ctx, `
		INSERT INTO scan_targets (id, name, address, port, credential_id, scanner_id, sudo, host_key,
			interval_minutes, asset_id, created_at, integrity, scope_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		RETURNING `+mgScanTargetColumns,
		t.ID, t.Name, t.Address, t.Port, t.CredentialID, mgText(t.ScannerID), t.Sudo, mgBytes(t.HostKey),
		t.IntervalMinutes, mgText(t.AssetID), mgOrNow(t.CreatedAt), mgIntegrityMode(t.Integrity), t.ScopeID))
	if err != nil {
		return store.ScanTarget{}, mgErr(op, err)
	}
	return out, nil
}

// mgCredentialIn checks that a record of the scope scopeID may use the
// credential: scope.ErrOutside when the credential belongs to another scope.
// An unknown credential is left to the foreign key (scan targets) or kept
// as a dangling reference (clusters), as without scopes.
func (d *DB) mgCredentialIn(ctx context.Context, op, id, scopeID string) error {
	if id == "" {
		return nil
	}
	var owner string
	err := d.q.QueryRow(ctx, `SELECT scope_id FROM credentials WHERE id = $1`, id).Scan(&owner)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil
	case err != nil:
		return mgErr(op, err)
	case owner != scopeID:
		return fmt.Errorf("postgres: %s: credential of another scope: %w", op, scope.ErrOutside)
	}
	return nil
}

// GetScanTarget implements store.ScanTargets.
func (d *DB) GetScanTarget(ctx context.Context, id string) (store.ScanTarget, error) {
	q, sc, err := scoped(ctx, "get scan target", id)
	if err != nil {
		return store.ScanTarget{}, err
	}
	t, err := mgScanScanTarget(d.q.QueryRow(ctx, `SELECT `+mgScanTargetColumns+` FROM scan_targets WHERE id = $1 AND `+
		sc.col("scope_id"), q.args...))
	if err != nil {
		return store.ScanTarget{}, mgErr("get scan target", err)
	}
	return t, nil
}

// mgScanTargetWhere filters with $1 q, $2 scope id, $3 scanner id, $4
// credential id, $5 last result and the scope of the call.
func mgScanTargetWhere(sc sqlScope) string {
	return `
	WHERE ($1 = '' OR strpos(lower(name), lower($1)) > 0 OR strpos(lower(address), lower($1)) > 0)
	  AND ($2 = '' OR scope_id = $2)
	  AND ($3 = '' OR scanner_id::text = $3)
	  AND ($4 = '' OR credential_id::text = $4)
	  AND ($5 = '' OR (last_run_at IS NOT NULL AND last_run_result = $5))
	  AND ` + sc.col("scope_id")
}

var mgScanTargetSort = map[string]string{
	"name":    "lower(name)",
	"address": "address",
	"lastRun": "last_run_at",
}

// ListScanTargets implements store.ScanTargets.
func (d *DB) ListScanTargets(ctx context.Context, f store.ScanTargetFilter, p store.Page) ([]store.ScanTarget, int, error) {
	const op = "list scan targets"
	p = p.Normalize()
	order, err := mgOrder(op, f.Sort, "name", mgScanTargetSort, true, "lower(name), id")
	if err != nil {
		return nil, 0, err
	}
	q, sc, err := scoped(ctx, op, f.Q, f.ScopeID, f.ScannerID, f.CredentialID, string(f.LastResult))
	if err != nil {
		return nil, 0, err
	}
	args := q.args
	n := len(args)
	rows, err := d.q.Query(ctx, `SELECT `+mgScanTargetColumns+`, count(*) OVER () FROM scan_targets`+
		mgScanTargetWhere(sc)+order+fmt.Sprintf(` LIMIT $%d OFFSET $%d`, n+1, n+2),
		append(args, p.Limit, p.Offset)...)
	if err != nil {
		return nil, 0, mgErr(op, err)
	}
	defer rows.Close()
	out := []store.ScanTarget{}
	total := 0
	for rows.Next() {
		t, err := mgScanScanTarget(rows, &total)
		if err != nil {
			return nil, 0, mgErr(op, err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, mgErr(op, err)
	}
	if len(out) == 0 && p.Offset > 0 {
		if err := d.q.QueryRow(ctx, `SELECT count(*) FROM scan_targets`+mgScanTargetWhere(sc), args[:n]...).Scan(&total); err != nil {
			return nil, 0, mgErr(op, err)
		}
	}
	return out, total, nil
}

// UpdateScanTarget implements store.ScanTargets.
// The credential must be of the target's scope.
func (d *DB) UpdateScanTarget(ctx context.Context, t store.ScanTarget) error {
	const op = "update scan target"
	cur, err := d.GetScanTarget(ctx, t.ID)
	if err != nil {
		return err
	}
	if err := d.mgCredentialIn(ctx, op, t.CredentialID, cur.ScopeID); err != nil {
		return err
	}
	return d.mgUpdateScanTarget(ctx, op, `name = $2, address = $3, port = $4, credential_id = $5, scanner_id = $6,
			sudo = $7, interval_minutes = $8, integrity = $9`,
		t.ID, t.Name, t.Address, t.Port, t.CredentialID, mgText(t.ScannerID), t.Sudo, t.IntervalMinutes,
		mgIntegrityMode(t.Integrity))
}

// mgUpdateScanTarget runs UPDATE scan_targets SET set WHERE id = $1 for
// exactly one target in the scope of ctx; args are the id followed by the
// values of set.
func (d *DB) mgUpdateScanTarget(ctx context.Context, op, set string, args ...any) error {
	q, sc, err := scoped(ctx, op, args...)
	if err != nil {
		return err
	}
	tag, err := d.q.Exec(ctx, `UPDATE scan_targets SET `+set+` WHERE id = $1 AND `+sc.col("scope_id"), q.args...)
	return mgExactlyOne(op, tag, err)
}

// DeleteScanTarget implements store.ScanTargets.
func (d *DB) DeleteScanTarget(ctx context.Context, id string) error {
	q, sc, err := scoped(ctx, "delete scan target", id)
	if err != nil {
		return err
	}
	tag, err := d.q.Exec(ctx, `DELETE FROM scan_targets WHERE id = $1 AND `+sc.col("scope_id"), q.args...)
	if err != nil {
		return mgDeleteErr("delete scan target", err)
	}
	if tag.RowsAffected() == 0 {
		return mgNotFound("delete scan target")
	}
	return nil
}

// SetScanTargetHostKey implements store.ScanTargets.
func (d *DB) SetScanTargetHostKey(ctx context.Context, id string, key []byte) error {
	if len(key) == 0 {
		return fmt.Errorf("postgres: set scan target host key: empty key: %w", store.ErrInvalid)
	}
	q, sc, err := scoped(ctx, "set scan target host key", id, key)
	if err != nil {
		return err
	}
	var stored []byte
	err = d.q.QueryRow(ctx, `
		UPDATE scan_targets SET host_key = coalesce(host_key, $2) WHERE id = $1 AND `+sc.col("scope_id")+`
		RETURNING host_key`, q.args...).Scan(&stored)
	if err != nil {
		return mgErr("set scan target host key", err)
	}
	if !bytes.Equal(stored, key) {
		return fmt.Errorf("postgres: set scan target host key: a different key is pinned: %w", store.ErrConflict)
	}
	return nil
}

// ClearScanTargetHostKey implements store.ScanTargets.
func (d *DB) ClearScanTargetHostKey(ctx context.Context, id string) error {
	return d.mgUpdateScanTarget(ctx, "clear scan target host key", `host_key = NULL`, id)
}

// SetScanTargetAsset implements store.ScanTargets.
func (d *DB) SetScanTargetAsset(ctx context.Context, id, assetID string) error {
	return d.mgUpdateScanTarget(ctx, "set scan target asset", `asset_id = $2`, id, mgText(assetID))
}

// RecordScanRun implements store.ScanTargets.
func (d *DB) RecordScanRun(ctx context.Context, id string, run store.ScanRun) error {
	if run.Duration < 0 {
		run.Duration = 0
	}
	return d.mgUpdateScanTarget(ctx, "record scan run", `last_run_at = $2, last_run_result = $3,
			last_run_message = $4, last_run_duration_ms = $5`,
		id, mgOrNow(run.At), run.Result, run.Message, run.Duration.Milliseconds())
}

// ListDueScanTargets implements store.ScanTargets.
func (d *DB) ListDueScanTargets(ctx context.Context, scannerID string, now time.Time, limit int) ([]store.ScanTarget, error) {
	if limit <= 0 {
		limit = 1000
	}
	if err := requireAll(ctx, "list due scan targets"); err != nil {
		return nil, err
	}
	rows, err := d.q.Query(ctx, `
		SELECT `+mgScanTargetColumns+` FROM scan_targets
		WHERE scanner_id IS NOT DISTINCT FROM $1::uuid
		  AND interval_minutes > 0
		  AND (last_run_at IS NULL OR last_run_at + make_interval(mins => interval_minutes) <= $2)
		ORDER BY last_run_at NULLS FIRST, id
		LIMIT $3`, mgText(scannerID), now.UTC(), limit)
	if err != nil {
		return nil, mgErr("list due scan targets", err)
	}
	defer rows.Close()
	out := []store.ScanTarget{}
	for rows.Next() {
		t, err := mgScanScanTarget(rows)
		if err != nil {
			return nil, mgErr("list due scan targets", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, mgErr("list due scan targets", err)
	}
	return out, nil
}
