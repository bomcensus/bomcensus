// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"slices"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

const mgDetectDirColumns = `d.id::text, d.path, d.description, d.created_at,
	(SELECT count(*) FROM agent_detect_dirs x WHERE x.dir_id = d.id),
	(SELECT count(*) FROM scan_target_detect_dirs x WHERE x.dir_id = d.id)`

func mgScanDetectDir(r mgRow) (store.DetectDir, error) {
	var d store.DetectDir
	if err := r.Scan(&d.ID, &d.Path, &d.Description, &d.CreatedAt, &d.Agents, &d.ScanTargets); err != nil {
		return store.DetectDir{}, err
	}
	d.CreatedAt = d.CreatedAt.UTC()
	return d, nil
}

// CreateDetectDir implements store.DetectDirs.
func (d *DB) CreateDetectDir(ctx context.Context, dir store.DetectDir) (store.DetectDir, error) {
	if dir.ID == "" {
		id, err := mgNewID()
		if err != nil {
			return store.DetectDir{}, err
		}
		dir.ID = id
	}
	out, err := mgScanDetectDir(d.q.QueryRow(ctx, `
		INSERT INTO detect_dirs AS d (id, path, description, created_at)
		VALUES ($1, $2, $3, $4)
		RETURNING `+mgDetectDirColumns,
		dir.ID, dir.Path, dir.Description, mgOrNow(dir.CreatedAt)))
	if err != nil {
		return store.DetectDir{}, mgErr("create detect dir", err)
	}
	return out, nil
}

// ListDetectDirs implements store.DetectDirs.
func (d *DB) ListDetectDirs(ctx context.Context) ([]store.DetectDir, error) {
	rows, err := d.q.Query(ctx, `SELECT `+mgDetectDirColumns+` FROM detect_dirs d ORDER BY d.path`)
	if err != nil {
		return nil, mgErr("list detect dirs", err)
	}
	defer rows.Close()
	out := []store.DetectDir{}
	for rows.Next() {
		dir, err := mgScanDetectDir(rows)
		if err != nil {
			return nil, mgErr("list detect dirs", err)
		}
		out = append(out, dir)
	}
	if err := rows.Err(); err != nil {
		return nil, mgErr("list detect dirs", err)
	}
	return out, nil
}

// GetDetectDir implements store.DetectDirs.
func (d *DB) GetDetectDir(ctx context.Context, id string) (store.DetectDir, error) {
	dir, err := mgScanDetectDir(d.q.QueryRow(ctx, `SELECT `+mgDetectDirColumns+` FROM detect_dirs d WHERE d.id = $1`, id))
	if err != nil {
		return store.DetectDir{}, mgErr("get detect dir", err)
	}
	return dir, nil
}

// UpdateDetectDir implements store.DetectDirs.
func (d *DB) UpdateDetectDir(ctx context.Context, dir store.DetectDir) (store.DetectDir, error) {
	out, err := mgScanDetectDir(d.q.QueryRow(ctx, `
		UPDATE detect_dirs AS d SET path = $2, description = $3
		WHERE d.id = $1
		RETURNING `+mgDetectDirColumns,
		dir.ID, dir.Path, dir.Description))
	if err != nil {
		return store.DetectDir{}, mgErr("update detect dir", err)
	}
	return out, nil
}

// DeleteDetectDir implements store.DetectDirs.
func (d *DB) DeleteDetectDir(ctx context.Context, id string) error {
	tag, err := d.q.Exec(ctx, `DELETE FROM detect_dirs WHERE id = $1`, id)
	return mgExactlyOne("delete detect dir", tag, err)
}

// SetAgentDetectDirs implements store.DetectDirs.
func (d *DB) SetAgentDetectDirs(ctx context.Context, agentID string, dirIDs []string) error {
	return d.setDetectDirs(ctx, "set agent detect dirs", "agents", "agent_detect_dirs", "agent_id", agentID, dirIDs)
}

// SetScanTargetDetectDirs implements store.DetectDirs.
func (d *DB) SetScanTargetDetectDirs(ctx context.Context, targetID string, dirIDs []string) error {
	return d.setDetectDirs(ctx, "set scan target detect dirs", "scan_targets", "scan_target_detect_dirs", "target_id", targetID, dirIDs)
}

// setDetectDirs replaces the assignments of one owner row. The table and
// column names are constants of the callers.
func (d *DB) setDetectDirs(ctx context.Context, op, owners, table, column, ownerID string, dirIDs []string) error {
	ids := slices.Clone(dirIDs)
	slices.Sort(ids)
	ids = slices.Compact(ids)
	return d.WithTx(ctx, func(s store.Store) error {
		tx := s.(*DB)
		var exists bool
		if err := tx.q.QueryRow(ctx, `SELECT true FROM `+owners+` WHERE id = $1 FOR UPDATE`, ownerID).Scan(&exists); err != nil {
			return mgErr(op, err)
		}
		if _, err := tx.q.Exec(ctx, `DELETE FROM `+table+` WHERE `+column+` = $1`, ownerID); err != nil {
			return mgErr(op, err)
		}
		if len(ids) == 0 {
			return nil
		}
		// An unknown directory fails the foreign key, which is ErrNotFound.
		_, err := tx.q.Exec(ctx, `INSERT INTO `+table+` (`+column+`, dir_id) SELECT $1, unnest($2::uuid[])`, ownerID, ids)
		return mgErr(op, err)
	})
}
