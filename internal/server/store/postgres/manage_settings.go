// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

// GetSetting implements store.Settings.
func (d *DB) GetSetting(ctx context.Context, key string) (json.RawMessage, error) {
	var v []byte
	if err := d.q.QueryRow(ctx, `SELECT value::text FROM settings WHERE key = $1`, key).Scan(&v); err != nil {
		return nil, mgErr("get setting", err)
	}
	return json.RawMessage(v), nil
}

// PutSetting implements store.Settings.
func (d *DB) PutSetting(ctx context.Context, key string, value json.RawMessage) error {
	if !json.Valid(value) {
		return fmt.Errorf("postgres: put setting %s: %w", key, store.ErrInvalid)
	}
	_, err := d.q.Exec(ctx, `
		INSERT INTO settings (key, value, updated_at) VALUES ($1, $2::text::jsonb, $3)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, string(value), mgNow())
	return mgErr("put setting", err)
}
