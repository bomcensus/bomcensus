// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"fmt"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

const mgDetectorTableCols = `id, yaml, digest, reset, created_at, created_by`

func mgScanDetectorTable(r mgRow) (store.DetectorTableRevision, error) {
	var t store.DetectorTableRevision
	if err := r.Scan(&t.ID, &t.YAML, &t.Digest, &t.Reset, &t.CreatedAt, &t.CreatedBy); err != nil {
		return store.DetectorTableRevision{}, err
	}
	t.CreatedAt = t.CreatedAt.UTC()
	return t, nil
}

// LatestDetectorTable implements store.DetectorTables.
func (d *DB) LatestDetectorTable(ctx context.Context) (store.DetectorTableRevision, error) {
	t, err := mgScanDetectorTable(d.q.QueryRow(ctx, `SELECT `+mgDetectorTableCols+` FROM detector_tables ORDER BY id DESC LIMIT 1`))
	return t, mgErr("latest detector table", err)
}

// GetDetectorTable implements store.DetectorTables.
func (d *DB) GetDetectorTable(ctx context.Context, id int64) (store.DetectorTableRevision, error) {
	t, err := mgScanDetectorTable(d.q.QueryRow(ctx, `SELECT `+mgDetectorTableCols+` FROM detector_tables WHERE id = $1`, id))
	return t, mgErr("get detector table", err)
}

// AddDetectorTable implements store.DetectorTables.
func (d *DB) AddDetectorTable(ctx context.Context, r store.DetectorTableRevision) (store.DetectorTableRevision, error) {
	if r.Reset != (r.YAML == "") || r.Reset != (r.Digest == "") {
		return store.DetectorTableRevision{}, fmt.Errorf("postgres: add detector table: yaml and digest go with reset: %w", store.ErrInvalid)
	}
	t, err := mgScanDetectorTable(d.q.QueryRow(ctx, `
		INSERT INTO detector_tables (yaml, digest, reset, created_at, created_by)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING `+mgDetectorTableCols, r.YAML, r.Digest, r.Reset, mgOrNow(r.CreatedAt), r.CreatedBy))
	return t, mgErr("add detector table", err)
}

// ListDetectorTables implements store.DetectorTables.
func (d *DB) ListDetectorTables(ctx context.Context, limit int) ([]store.DetectorTableRevision, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	rows, err := d.q.Query(ctx, `SELECT id, '', digest, reset, created_at, created_by FROM detector_tables
		ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, mgErr("list detector tables", err)
	}
	defer rows.Close()
	out := []store.DetectorTableRevision{}
	for rows.Next() {
		t, err := mgScanDetectorTable(rows)
		if err != nil {
			return nil, mgErr("list detector tables", err)
		}
		out = append(out, t)
	}
	return out, mgErr("list detector tables", rows.Err())
}

// DetectorTableUsage implements store.DetectorTables.
func (d *DB) DetectorTableUsage(ctx context.Context) ([]store.DetectorTableUsage, error) {
	q, sc, err := scoped(ctx, "detector table usage")
	if err != nil {
		return nil, err
	}
	rows, err := d.q.Query(ctx, `
		SELECT a.kind, a.detectors_digest IS NOT NULL, coalesce(a.detectors_digest, ''), count(*)
		FROM agents a
		WHERE a.state = 'approved' AND `+sc.shared("a.kind", "a.scope_id")+`
		GROUP BY 1, 2, 3
		ORDER BY 4 DESC, 1, 3`, q.args...)
	if err != nil {
		return nil, mgErr("detector table usage", err)
	}
	defer rows.Close()
	out := []store.DetectorTableUsage{}
	for rows.Next() {
		var u store.DetectorTableUsage
		if err := rows.Scan(&u.Kind, &u.Reported, &u.Digest, &u.Count); err != nil {
			return nil, mgErr("detector table usage", err)
		}
		out = append(out, u)
	}
	return out, mgErr("detector table usage", rows.Err())
}
