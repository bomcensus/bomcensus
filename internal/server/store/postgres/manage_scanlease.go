// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

func mgLeaseArgs(key, owner string, ttl time.Duration) error {
	if key == "" || owner == "" || ttl <= 0 {
		return fmt.Errorf("postgres: scan lease: key, owner and a positive ttl are required: %w", store.ErrInvalid)
	}
	return nil
}

// AcquireScanLease implements store.ScanLeases.
func (d *DB) AcquireScanLease(ctx context.Context, key, owner string, ttl time.Duration, now time.Time) (bool, error) {
	if err := mgLeaseArgs(key, owner, ttl); err != nil {
		return false, err
	}
	now = mgOrNow(now)
	var got string
	err := d.q.QueryRow(ctx, `
		INSERT INTO scan_leases (key, owner, acquired_at, expires_at) VALUES ($1, $2, $3, $4)
		ON CONFLICT (key) DO UPDATE SET
			acquired_at = CASE WHEN scan_leases.owner = excluded.owner AND scan_leases.expires_at > excluded.acquired_at
				THEN scan_leases.acquired_at ELSE excluded.acquired_at END,
			owner = excluded.owner,
			expires_at = excluded.expires_at
		WHERE scan_leases.expires_at <= excluded.acquired_at OR scan_leases.owner = excluded.owner
		RETURNING owner`, key, owner, now, now.Add(ttl)).Scan(&got)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, mgErr("acquire scan lease", err)
	}
	return got == owner, nil
}

// RenewScanLease implements store.ScanLeases.
func (d *DB) RenewScanLease(ctx context.Context, key, owner string, ttl time.Duration, now time.Time) (bool, error) {
	if err := mgLeaseArgs(key, owner, ttl); err != nil {
		return false, err
	}
	now = mgOrNow(now)
	tag, err := d.q.Exec(ctx, `
		UPDATE scan_leases SET expires_at = $4
		WHERE key = $1 AND owner = $2 AND expires_at > $3`, key, owner, now, now.Add(ttl))
	if err != nil {
		return false, mgErr("renew scan lease", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ReleaseScanLease implements store.ScanLeases.
func (d *DB) ReleaseScanLease(ctx context.Context, key, owner string, now time.Time) error {
	now = mgOrNow(now)
	_, err := d.q.Exec(ctx, `
		UPDATE scan_leases SET expires_at = $3
		WHERE key = $1 AND owner = $2 AND expires_at > $3`, key, owner, now)
	return mgErr("release scan lease", err)
}

// GetScanLease implements store.ScanLeases.
func (d *DB) GetScanLease(ctx context.Context, key string) (store.ScanLease, error) {
	var l store.ScanLease
	err := d.q.QueryRow(ctx, `SELECT key, owner, acquired_at, expires_at FROM scan_leases WHERE key = $1`, key).
		Scan(&l.Key, &l.Owner, &l.AcquiredAt, &l.ExpiresAt)
	if err != nil {
		return store.ScanLease{}, mgErr("get scan lease", err)
	}
	l.AcquiredAt, l.ExpiresAt = l.AcquiredAt.UTC(), l.ExpiresAt.UTC()
	return l, nil
}

// DeleteExpiredScanLeases implements store.ScanLeases.
func (d *DB) DeleteExpiredScanLeases(ctx context.Context, t time.Time) (int64, error) {
	tag, err := d.q.Exec(ctx, `DELETE FROM scan_leases WHERE expires_at <= $1`, t.UTC())
	if err != nil {
		return 0, mgErr("delete expired scan leases", err)
	}
	return tag.RowsAffected(), nil
}
