// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package app

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/bomcensus/bomcensus/internal/server/job"
	"github.com/bomcensus/bomcensus/internal/server/store/postgres"
	"github.com/bomcensus/bomcensus/server/config"
)

// migrateLock is the advisory lock key that serializes store migrations of
// several servers starting at once. postgres.DB.Migrate (goose) takes no
// lock of its own. River's migrations use another key ("bomcrivr").
const migrateLock = int64(0x626f6d63_6d696772) // "bomcmigr"

// Migrate applies the store and job queue migrations and returns. It needs
// only the database URL of cfg.
func Migrate(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	db, err := postgres.Open(ctx, cfg.DatabaseURL.Reveal())
	if err != nil {
		return err
	}
	defer db.Close()
	if err := migrateStore(ctx, db); err != nil {
		return err
	}
	if err := job.NewRiver(db.Pool(), log.With("component", "queue"), job.RiverConfig{}).Migrate(ctx); err != nil {
		return err
	}
	log.Info("migrations applied")
	return nil
}

// migrateStore runs the store migrations while holding a session-level
// advisory lock on a dedicated connection; goose works on other connections
// of the pool. A server that waits for the lock finds nothing left to do.
func migrateStore(ctx context.Context, db *postgres.DB) (err error) {
	conn, err := db.Pool().Acquire(ctx)
	if err != nil {
		return fmt.Errorf("migrate: acquire connection: %w", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrateLock); err != nil {
		return fmt.Errorf("migrate: lock: %w", err)
	}
	defer func() {
		if _, uerr := conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, migrateLock); uerr != nil {
			// Closing the session releases the lock; the pool then drops
			// the connection.
			_ = conn.Conn().Close(context.WithoutCancel(ctx))
		}
	}()
	return db.Migrate(ctx)
}
