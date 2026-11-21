// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

const mgPKIColumns = `name, cert_chain_pem, encrypted_key, state, version, created_at, updated_at`

func mgScanPKI(r mgRow) (store.PKIObject, error) {
	var o store.PKIObject
	if err := r.Scan(&o.Name, &o.CertChainPEM, &o.EncryptedKey, &o.State, &o.Version, &o.CreatedAt, &o.UpdatedAt); err != nil {
		return store.PKIObject{}, err
	}
	o.CreatedAt, o.UpdatedAt = o.CreatedAt.UTC(), o.UpdatedAt.UTC()
	return o, nil
}

// GetPKIObject implements store.PKI.
func (d *DB) GetPKIObject(ctx context.Context, name string) (store.PKIObject, error) {
	o, err := mgScanPKI(d.q.QueryRow(ctx, `SELECT `+mgPKIColumns+` FROM pki_objects WHERE name = $1`, name))
	if err != nil {
		return store.PKIObject{}, mgErr("get pki object", err)
	}
	return o, nil
}

// ListPKIObjects implements store.PKI.
func (d *DB) ListPKIObjects(ctx context.Context) ([]store.PKIObject, error) {
	rows, err := d.q.Query(ctx, `SELECT `+mgPKIColumns+` FROM pki_objects ORDER BY name`)
	if err != nil {
		return nil, mgErr("list pki objects", err)
	}
	defer rows.Close()
	out := []store.PKIObject{}
	for rows.Next() {
		o, err := mgScanPKI(rows)
		if err != nil {
			return nil, mgErr("list pki objects", err)
		}
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, mgErr("list pki objects", err)
	}
	return out, nil
}

// PutPKIObject implements store.PKI.
func (d *DB) PutPKIObject(ctx context.Context, o store.PKIObject, expectVersion int64) (store.PKIObject, error) {
	if o.Name == "" || len(o.CertChainPEM) == 0 || expectVersion < 0 {
		return store.PKIObject{}, fmt.Errorf("postgres: put pki object: %w", store.ErrInvalid)
	}
	now := mgNow()
	var row pgx.Row
	if expectVersion == 0 {
		// Concurrent inserts of the same name: the loser waits for the
		// winner's commit and then inserts nothing.
		row = d.q.QueryRow(ctx, `
			INSERT INTO pki_objects (name, cert_chain_pem, encrypted_key, state, version, created_at, updated_at)
			VALUES ($1, $2, $3, $4, 1, $5, $5)
			ON CONFLICT (name) DO NOTHING
			RETURNING `+mgPKIColumns,
			o.Name, o.CertChainPEM, mgBytes(o.EncryptedKey), o.State, now)
	} else {
		row = d.q.QueryRow(ctx, `
			UPDATE pki_objects SET cert_chain_pem = $2, encrypted_key = $3, state = $4,
				version = version + 1, updated_at = $5
			WHERE name = $1 AND version = $6
			RETURNING `+mgPKIColumns,
			o.Name, o.CertChainPEM, mgBytes(o.EncryptedKey), o.State, now, expectVersion)
	}
	out, err := mgScanPKI(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.PKIObject{}, fmt.Errorf("postgres: put pki object %s: version is not %d: %w",
			o.Name, expectVersion, store.ErrConflict)
	}
	if err != nil {
		return store.PKIObject{}, mgErr("put pki object", err)
	}
	return out, nil
}

// DeletePKIObject implements store.PKI.
func (d *DB) DeletePKIObject(ctx context.Context, name string, expectVersion int64) error {
	tag, err := d.q.Exec(ctx, `DELETE FROM pki_objects WHERE name = $1 AND version = $2`, name, expectVersion)
	if err != nil {
		return mgErr("delete pki object", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var version int64
	if err := d.q.QueryRow(ctx, `SELECT version FROM pki_objects WHERE name = $1`, name).Scan(&version); err != nil {
		return mgErr("delete pki object", err)
	}
	return fmt.Errorf("postgres: delete pki object %s: version is %d: %w", name, version, store.ErrConflict)
}

// GetTLSSetting implements store.PKI.
func (d *DB) GetTLSSetting(ctx context.Context, endpoint store.TLSEndpoint) (store.TLSSetting, error) {
	s := store.TLSSetting{Endpoint: endpoint}
	err := d.q.QueryRow(ctx, `SELECT mode, updated_at FROM tls_settings WHERE endpoint = $1`, endpoint).
		Scan(&s.Mode, &s.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		s.Mode = store.TLSModeAuto
		return s, nil
	}
	if err != nil {
		return store.TLSSetting{}, mgErr("get tls setting", err)
	}
	s.UpdatedAt = s.UpdatedAt.UTC()
	return s, nil
}

// PutTLSSetting implements store.PKI.
func (d *DB) PutTLSSetting(ctx context.Context, s store.TLSSetting) error {
	_, err := d.q.Exec(ctx, `
		INSERT INTO tls_settings (endpoint, mode, updated_at) VALUES ($1, $2, $3)
		ON CONFLICT (endpoint) DO UPDATE SET mode = excluded.mode, updated_at = excluded.updated_at`,
		s.Endpoint, s.Mode, mgOrNow(s.UpdatedAt))
	return mgErr("put tls setting", err)
}

// TrustBundleVersion implements store.PKI.
func (d *DB) TrustBundleVersion(ctx context.Context) (int64, error) {
	var v int64
	err := d.q.QueryRow(ctx, `SELECT coalesce(max(version), 0) FROM trust_bundle`).Scan(&v)
	if err != nil {
		return 0, mgErr("trust bundle version", err)
	}
	return v, nil
}

// BumpTrustBundleVersion implements store.PKI.
func (d *DB) BumpTrustBundleVersion(ctx context.Context) (int64, error) {
	var v int64
	err := d.q.QueryRow(ctx, `
		INSERT INTO trust_bundle (id, version) VALUES (true, 1)
		ON CONFLICT (id) DO UPDATE SET version = trust_bundle.version + 1
		RETURNING version`).Scan(&v)
	if err != nil {
		return 0, mgErr("bump trust bundle version", err)
	}
	return v, nil
}
