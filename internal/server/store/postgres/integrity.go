// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

var _ store.Integrity = (*DB)(nil)

// mgIntegrityMode maps an empty mode to inherit.
func mgIntegrityMode(m string) string {
	if m == "" {
		return store.IntegrityInherit
	}
	return m
}

func validIntegrityMode(m string) bool {
	switch m {
	case store.IntegrityInherit, store.IntegrityOn, store.IntegrityOff:
		return true
	}
	return false
}

var integrityCoverageRank = map[string]int{"full": 0, "partial": 1, "none": 2}

type integrityRec struct {
	ID           string     `json:"id"`
	Path         string     `json:"path"`
	Status       string     `json:"status"`
	PkgType      string     `json:"pkg_type"`
	Package      string     `json:"package"`
	Version      string     `json:"version"`
	Arch         string     `json:"arch"`
	Algo         string     `json:"algo"`
	Expected     string     `json:"expected"`
	Actual       string     `json:"actual"`
	ActualSHA256 string     `json:"actual_sha256"`
	Size         *int64     `json:"size"`
	Mtime        *time.Time `json:"mtime"`
	Ctime        *time.Time `json:"ctime"`
}

const integrityRecs = `jsonb_to_recordset($1::text::jsonb) AS x(id uuid, path text, status text, pkg_type text,
	package text, version text, arch text, algo text, expected text, actual text, actual_sha256 text,
	size bigint, mtime timestamptz, ctime timestamptz)`

// RecordIntegrityChunk implements store.Integrity.
func (d *DB) RecordIntegrityChunk(ctx context.Context, c store.IntegrityChunk) error {
	if c.AssetID == "" || c.PassKey == "" {
		return fmt.Errorf("postgres: record integrity chunk: %w", store.ErrInvalid)
	}
	if _, ok := integrityCoverageRank[c.Coverage]; !ok {
		c.Coverage = "partial"
	}
	at := mgOrNow(c.At)
	// One observation per path: the first wins, as in the probe.
	seen := map[string]bool{}
	recs := make([]integrityRec, 0, len(c.Findings))
	for _, f := range c.Findings {
		if seen[f.Path] || !strings.HasPrefix(f.Path, "/") {
			continue
		}
		seen[f.Path] = true
		id, err := mgNewID()
		if err != nil {
			return err
		}
		r := integrityRec{ID: id, Path: f.Path, Status: f.Status, PkgType: f.PkgType, Package: f.Package,
			Version: f.Version, Arch: f.Arch, Algo: f.Algo, Expected: f.Expected, Actual: f.Actual,
			ActualSHA256: f.ActualSHA256, Mtime: mgUTCPtr(f.Mtime), Ctime: mgUTCPtr(f.Ctime)}
		if f.Status == store.IntegrityMissing {
			r.Actual, r.ActualSHA256 = "", ""
		} else if f.Size > 0 {
			size := f.Size
			r.Size = &size
		}
		recs = append(recs, r)
	}
	js, err := json.Marshal(recs)
	if err != nil {
		return fmt.Errorf("postgres: record integrity chunk: %w", err)
	}
	return d.mgInTx(ctx, func(tx *DB) error {
		var passID, coverage, reason string
		err := tx.q.QueryRow(ctx, `
			SELECT id::text, coverage, coverage_reason FROM integrity_passes
			WHERE asset_id = $1 AND pass_key = $2 FOR UPDATE`, c.AssetID, c.PassKey).Scan(&passID, &coverage, &reason)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			if passID, err = mgNewID(); err != nil {
				return err
			}
			if _, err := tx.q.Exec(ctx, `
				INSERT INTO integrity_passes (id, asset_id, pass_key, started_at, last_chunk_at)
				VALUES ($1, $2, $3, $4, $4)`, passID, c.AssetID, c.PassKey, at); err != nil {
				return mgErr("record integrity chunk", err)
			}
			coverage = "full"
		case err != nil:
			return mgErr("record integrity chunk", err)
		}
		if integrityCoverageRank[c.Coverage] > integrityCoverageRank[coverage] {
			coverage = c.Coverage
		}
		if c.Reason != "" {
			reason = c.Reason
		}
		if len(reason) > 2048 {
			reason = strings.ToValidUTF8(reason[:2048], "")
		}
		if _, err := tx.q.Exec(ctx, `
			UPDATE integrity_passes SET last_chunk_at = greatest(last_chunk_at, $2),
				files_checked = files_checked + $3, files_excluded = files_excluded + $4,
				files_unreadable = files_unreadable + $5, coverage = $6, coverage_reason = $7,
				cursor = $8, utc_offset_s = $9,
				completed_at = CASE WHEN $10 THEN $2 ELSE completed_at END
			WHERE id = $1`,
			passID, at, c.Checked, c.Excluded, c.Unreadable, coverage, reason, c.Cursor, c.UTCOffset, c.Done); err != nil {
			return mgErr("record integrity chunk", err)
		}
		if len(recs) > 0 {
			// Another content now at a reported path ends the old finding.
			if _, err := tx.q.Exec(ctx, `
				UPDATE integrity_findings f SET resolved_at = $3
				FROM `+integrityRecs+`
				WHERE f.asset_id = $2 AND f.resolved_at IS NULL AND f.path = x.path
				  AND (f.status <> x.status OR f.actual_sha256 <> x.actual_sha256)`,
				string(js), c.AssetID, at); err != nil {
				return mgErr("record integrity chunk", err)
			}
			if _, err := tx.q.Exec(ctx, `
				INSERT INTO integrity_findings (id, asset_id, path, status, pkg_type, package, version, arch, algo,
					expected, actual, actual_sha256, size, mtime, ctime, last_pass, first_seen, last_seen)
				SELECT x.id, $2, x.path, x.status, x.pkg_type, x.package, x.version, x.arch, x.algo, x.expected,
					x.actual, x.actual_sha256, x.size, x.mtime, x.ctime, $3, $4, $4
				FROM `+integrityRecs+`
				ON CONFLICT (asset_id, path, status, actual_sha256) WHERE resolved_at IS NULL DO UPDATE SET
					pkg_type = excluded.pkg_type, package = excluded.package, version = excluded.version,
					arch = excluded.arch, algo = excluded.algo, expected = excluded.expected,
					actual = excluded.actual, size = excluded.size, mtime = excluded.mtime,
					ctime = excluded.ctime, last_pass = excluded.last_pass,
					last_seen = greatest(integrity_findings.last_seen, excluded.last_seen)`,
				string(js), c.AssetID, passID, at); err != nil {
				return mgErr("record integrity chunk", err)
			}
		}
		if c.Done {
			if _, err := tx.q.Exec(ctx, `
				UPDATE integrity_findings SET resolved_at = $3
				WHERE asset_id = $1 AND resolved_at IS NULL AND last_pass <> $2`,
				c.AssetID, passID, at); err != nil {
				return mgErr("record integrity chunk", err)
			}
		}
		return nil
	})
}

const mgIntegrityPassColumns = `id::text, asset_id::text, pass_key, started_at, last_chunk_at, completed_at,
	files_checked, files_excluded, files_unreadable, coverage, coverage_reason, cursor, utc_offset_s`

func mgScanIntegrityPass(r mgRow) (store.IntegrityPass, error) {
	var p store.IntegrityPass
	err := r.Scan(&p.ID, &p.AssetID, &p.PassKey, &p.StartedAt, &p.LastChunkAt, &p.CompletedAt,
		&p.Checked, &p.Excluded, &p.Unreadable, &p.Coverage, &p.Reason, &p.Cursor, &p.UTCOffset)
	p.StartedAt, p.LastChunkAt, p.CompletedAt = p.StartedAt.UTC(), p.LastChunkAt.UTC(), mgUTCPtr(p.CompletedAt)
	return p, err
}

// LastIntegrityPass implements store.Integrity.
func (d *DB) LastIntegrityPass(ctx context.Context, assetID string) (store.IntegrityPass, error) {
	p, err := mgScanIntegrityPass(d.q.QueryRow(ctx, `SELECT `+mgIntegrityPassColumns+` FROM integrity_passes
		WHERE asset_id = $1 ORDER BY last_chunk_at DESC, id DESC LIMIT 1`, assetID))
	if err != nil {
		return store.IntegrityPass{}, mgErr("last integrity pass", err)
	}
	return p, nil
}

// LastCompletedIntegrityPass implements store.Integrity.
func (d *DB) LastCompletedIntegrityPass(ctx context.Context, assetID string) (store.IntegrityPass, error) {
	p, err := mgScanIntegrityPass(d.q.QueryRow(ctx, `SELECT `+mgIntegrityPassColumns+` FROM integrity_passes
		WHERE asset_id = $1 AND completed_at IS NOT NULL ORDER BY completed_at DESC, id DESC LIMIT 1`, assetID))
	if err != nil {
		return store.IntegrityPass{}, mgErr("last completed integrity pass", err)
	}
	return p, nil
}

// mgIntegrityAllowedBy is the first active rule hiding finding f.
const mgIntegrityAllowedBy = `(SELECT r.id::text FROM integrity_allow_rules r
	WHERE r.revoked_at IS NULL AND r.path = f.path AND r.status = f.status AND r.actual_sha256 = f.actual_sha256
	  AND (r.scope = 'fleet' OR r.asset_id = f.asset_id)
	ORDER BY r.created_at, r.id LIMIT 1)`

// mgIntegrityVisible selects the open findings of current assets with the
// filter $1 status, $2 asset id, $3 q, $4 path, $5 sha256 (NULL: any),
// with their asset's name and method and the rule hiding them.
const mgIntegrityVisible = `
	SELECT f.*, a.name AS asset_name, a.method AS asset_method, ` + mgIntegrityAllowedBy + ` AS allowed_by
	FROM integrity_findings f JOIN assets a ON a.id = f.asset_id AND a.gone_at IS NULL
	WHERE f.resolved_at IS NULL
	  AND ($1 = '' OR f.status = $1)
	  AND ($2 = '' OR f.asset_id::text = $2)
	  AND ($3 = '' OR strpos(lower(f.path), lower($3)) > 0 OR strpos(lower(f.package), lower($3)) > 0
	       OR strpos(lower(a.name), lower($3)) > 0)
	  AND ($4 = '' OR f.path = $4)
	  AND ($5::text IS NULL OR f.actual_sha256 = $5)`

func integrityFilterArgs(f store.IntegrityFilter) []any {
	var sha any
	if f.SHA256 != nil {
		sha = *f.SHA256
	}
	return []any{f.Status, f.AssetID, f.Q, f.Path, sha, f.IncludeAllowed}
}

// ListIntegrityGroups implements store.Integrity.
func (d *DB) ListIntegrityGroups(ctx context.Context, f store.IntegrityFilter, p store.Page) ([]store.IntegrityGroup, int, error) {
	p = p.Normalize()
	args := append(integrityFilterArgs(f), p.Limit, p.Offset)
	rows, err := d.q.Query(ctx, `
		WITH v AS (`+mgIntegrityVisible+`)
		SELECT path, status, actual_sha256,
			(array_agg(pkg_type ORDER BY last_seen DESC, id))[1], (array_agg(package ORDER BY last_seen DESC, id))[1],
			(array_agg(version ORDER BY last_seen DESC, id))[1], (array_agg(algo ORDER BY last_seen DESC, id))[1],
			(array_agg(expected ORDER BY last_seen DESC, id))[1], (array_agg(actual ORDER BY last_seen DESC, id))[1],
			count(DISTINCT asset_id) FILTER (WHERE allowed_by IS NULL OR $6),
			count(DISTINCT asset_id) FILTER (WHERE allowed_by IS NOT NULL),
			min(first_seen), max(last_seen), count(*) OVER ()
		FROM v WHERE $6 OR allowed_by IS NULL
		GROUP BY path, status, actual_sha256
		ORDER BY 10 DESC, path, status, actual_sha256
		LIMIT $7 OFFSET $8`, args...)
	if err != nil {
		return nil, 0, mgErr("list integrity groups", err)
	}
	defer rows.Close()
	out := []store.IntegrityGroup{}
	total := 0
	for rows.Next() {
		var g store.IntegrityGroup
		if err := rows.Scan(&g.Path, &g.Status, &g.ActualSHA256, &g.PkgType, &g.Package, &g.Version, &g.Algo,
			&g.Expected, &g.Actual, &g.Assets, &g.AllowedAssets, &g.FirstSeen, &g.LastSeen, &total); err != nil {
			return nil, 0, mgErr("list integrity groups", err)
		}
		g.FirstSeen, g.LastSeen = g.FirstSeen.UTC(), g.LastSeen.UTC()
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, mgErr("list integrity groups", err)
	}
	if len(out) == 0 && p.Offset > 0 {
		if err := d.q.QueryRow(ctx, `WITH v AS (`+mgIntegrityVisible+`)
			SELECT count(*) FROM (SELECT 1 FROM v WHERE $6 OR allowed_by IS NULL GROUP BY path, status, actual_sha256) g`,
			integrityFilterArgs(f)...).Scan(&total); err != nil {
			return nil, 0, mgErr("list integrity groups", err)
		}
	}
	return out, total, nil
}

// ListIntegrityFindings implements store.Integrity.
func (d *DB) ListIntegrityFindings(ctx context.Context, f store.IntegrityFilter, p store.Page) ([]store.IntegrityFinding, int, error) {
	p = p.Normalize()
	args := append(integrityFilterArgs(f), p.Limit, p.Offset)
	rows, err := d.q.Query(ctx, `
		WITH v AS (`+mgIntegrityVisible+`)
		SELECT id::text, asset_id::text, asset_name, asset_method, path, status, pkg_type, package, version, arch,
			algo, expected, actual, actual_sha256, coalesce(size, 0), mtime, ctime, first_seen, last_seen,
			coalesce(allowed_by, ''), count(*) OVER ()
		FROM v WHERE $6 OR allowed_by IS NULL
		ORDER BY asset_name, asset_id, path, status
		LIMIT $7 OFFSET $8`, args...)
	if err != nil {
		return nil, 0, mgErr("list integrity findings", err)
	}
	defer rows.Close()
	out := []store.IntegrityFinding{}
	total := 0
	for rows.Next() {
		var x store.IntegrityFinding
		if err := rows.Scan(&x.ID, &x.AssetID, &x.AssetName, &x.Collector, &x.Path, &x.Status, &x.PkgType,
			&x.Package, &x.Version, &x.Arch, &x.Algo, &x.Expected, &x.Actual, &x.ActualSHA256, &x.Size,
			&x.Mtime, &x.Ctime, &x.FirstSeen, &x.LastSeen, &x.AllowedBy, &total); err != nil {
			return nil, 0, mgErr("list integrity findings", err)
		}
		x.Mtime, x.Ctime = mgUTCPtr(x.Mtime), mgUTCPtr(x.Ctime)
		x.FirstSeen, x.LastSeen = x.FirstSeen.UTC(), x.LastSeen.UTC()
		out = append(out, x)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, mgErr("list integrity findings", err)
	}
	if len(out) == 0 && p.Offset > 0 {
		if err := d.q.QueryRow(ctx, `WITH v AS (`+mgIntegrityVisible+`)
			SELECT count(*) FROM v WHERE $6 OR allowed_by IS NULL`, integrityFilterArgs(f)...).Scan(&total); err != nil {
			return nil, 0, mgErr("list integrity findings", err)
		}
	}
	return out, total, nil
}

// IntegritySummary implements store.Integrity.
func (d *DB) IntegritySummary(ctx context.Context, completedAfter time.Time) (store.IntegritySummary, error) {
	var s store.IntegritySummary
	args := append(integrityFilterArgs(store.IntegrityFilter{}), completedAfter.UTC())
	err := d.q.QueryRow(ctx, `
		WITH v AS (`+mgIntegrityVisible+`), shown AS (SELECT * FROM v WHERE $6 OR allowed_by IS NULL)
		SELECT
			(SELECT count(*) FROM (SELECT 1 FROM shown GROUP BY path, status, actual_sha256) g),
			(SELECT count(DISTINCT asset_id) FROM shown),
			(SELECT count(*) FROM integrity_allow_rules WHERE revoked_at IS NULL),
			(SELECT count(DISTINCT p.asset_id) FROM integrity_passes p
				JOIN assets a ON a.id = p.asset_id AND a.gone_at IS NULL),
			(SELECT count(DISTINCT p.asset_id) FROM integrity_passes p
				JOIN assets a ON a.id = p.asset_id AND a.gone_at IS NULL WHERE p.completed_at >= $7)`,
		args...).Scan(&s.Groups, &s.Assets, &s.Rules, &s.Tracked, &s.Completed)
	if err != nil {
		return s, mgErr("integrity summary", err)
	}
	return s, nil
}

func validSHA256Hex(s string) bool {
	if len(s) != 64 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// CreateIntegrityAllowRule implements store.Integrity.
func (d *DB) CreateIntegrityAllowRule(ctx context.Context, r store.IntegrityAllowRule) (store.IntegrityAllowRule, error) {
	invalid := func(why string) (store.IntegrityAllowRule, error) {
		return store.IntegrityAllowRule{}, fmt.Errorf("postgres: create integrity allow rule: %s: %w", why, store.ErrInvalid)
	}
	switch r.Scope {
	case store.IntegrityScopeAsset:
		if r.AssetID == "" {
			return invalid("asset scope without an asset")
		}
	case store.IntegrityScopeFleet:
		r.AssetID = ""
	default:
		return invalid("unknown scope")
	}
	switch r.Status {
	case store.IntegrityModified:
		if !validSHA256Hex(r.ActualSHA256) {
			return invalid("actual sha256 must be 64 lower-case hex digits")
		}
	case store.IntegrityMissing:
		if r.ActualSHA256 != "" {
			return invalid("a missing file has no sha256")
		}
	default:
		return invalid("unknown status")
	}
	if !strings.HasPrefix(r.Path, "/") || len(r.Path) > 4096 {
		return invalid("path")
	}
	if r.Note == "" || len(r.Note) > 1000 {
		return invalid("note must be 1 to 1000 bytes")
	}
	id, err := mgNewID()
	if err != nil {
		return store.IntegrityAllowRule{}, err
	}
	r.ID = id
	r.CreatedAt = mgOrNow(r.CreatedAt)
	if _, err := d.q.Exec(ctx, `
		INSERT INTO integrity_allow_rules (id, scope, asset_id, path, status, actual_sha256, note, created_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		r.ID, r.Scope, mgText(r.AssetID), r.Path, r.Status, r.ActualSHA256, r.Note, r.CreatedBy, r.CreatedAt); err != nil {
		return store.IntegrityAllowRule{}, mgErr("create integrity allow rule", err)
	}
	return r, nil
}

// ListIntegrityAllowRules implements store.Integrity.
func (d *DB) ListIntegrityAllowRules(ctx context.Context, includeRevoked bool, p store.Page) ([]store.IntegrityAllowRule, int, error) {
	p = p.Normalize()
	rows, err := d.q.Query(ctx, `
		SELECT r.id::text, r.scope, coalesce(r.asset_id::text, ''), coalesce(a.name, ''), r.path, r.status,
			r.actual_sha256, r.note, r.created_by, r.created_at, r.revoked_by, r.revoked_at,
			CASE WHEN r.revoked_at IS NOT NULL THEN 0 ELSE (SELECT count(*) FROM integrity_findings f
				JOIN assets fa ON fa.id = f.asset_id AND fa.gone_at IS NULL
				WHERE f.resolved_at IS NULL AND f.path = r.path AND f.status = r.status
				  AND f.actual_sha256 = r.actual_sha256 AND (r.scope = 'fleet' OR f.asset_id = r.asset_id)) END,
			count(*) OVER ()
		FROM integrity_allow_rules r LEFT JOIN assets a ON a.id = r.asset_id
		WHERE $1 OR r.revoked_at IS NULL
		ORDER BY r.created_at DESC, r.id DESC
		LIMIT $2 OFFSET $3`, includeRevoked, p.Limit, p.Offset)
	if err != nil {
		return nil, 0, mgErr("list integrity allow rules", err)
	}
	defer rows.Close()
	out := []store.IntegrityAllowRule{}
	total := 0
	for rows.Next() {
		var r store.IntegrityAllowRule
		if err := rows.Scan(&r.ID, &r.Scope, &r.AssetID, &r.AssetName, &r.Path, &r.Status, &r.ActualSHA256,
			&r.Note, &r.CreatedBy, &r.CreatedAt, &r.RevokedBy, &r.RevokedAt, &r.Hidden, &total); err != nil {
			return nil, 0, mgErr("list integrity allow rules", err)
		}
		r.CreatedAt, r.RevokedAt = r.CreatedAt.UTC(), mgUTCPtr(r.RevokedAt)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, mgErr("list integrity allow rules", err)
	}
	if len(out) == 0 && p.Offset > 0 {
		if err := d.q.QueryRow(ctx, `SELECT count(*) FROM integrity_allow_rules WHERE $1 OR revoked_at IS NULL`,
			includeRevoked).Scan(&total); err != nil {
			return nil, 0, mgErr("list integrity allow rules", err)
		}
	}
	return out, total, nil
}

// RevokeIntegrityAllowRule implements store.Integrity.
func (d *DB) RevokeIntegrityAllowRule(ctx context.Context, id, by string, at time.Time) error {
	tag, err := d.q.Exec(ctx, `UPDATE integrity_allow_rules SET revoked_at = $3, revoked_by = $2
		WHERE id = $1 AND revoked_at IS NULL`, id, by, mgOrNow(at))
	return mgExactlyOne("revoke integrity allow rule", tag, err)
}

// SetAgentIntegrity implements store.Integrity.
func (d *DB) SetAgentIntegrity(ctx context.Context, id, mode string) error {
	if !validIntegrityMode(mode) {
		return fmt.Errorf("postgres: set agent integrity: %w", store.ErrInvalid)
	}
	tag, err := d.q.Exec(ctx, `UPDATE agents SET integrity = $2 WHERE id = $1`, id, mode)
	return mgExactlyOne("set agent integrity", tag, err)
}

// SetScanTargetIntegrity implements store.Integrity.
func (d *DB) SetScanTargetIntegrity(ctx context.Context, id, mode string) error {
	if !validIntegrityMode(mode) {
		return fmt.Errorf("postgres: set scan target integrity: %w", store.ErrInvalid)
	}
	tag, err := d.q.Exec(ctx, `UPDATE scan_targets SET integrity = $2 WHERE id = $1`, id, mode)
	return mgExactlyOne("set scan target integrity", tag, err)
}
