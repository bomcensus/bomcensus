// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

// Helpers in this file carry an mg prefix so they cannot collide with helpers
// of the inventory half of the package.

var _ store.Manage = (*DB)(nil)

// mgRow is what both pgx.Row and pgx.Rows offer for scanning.
type mgRow interface {
	Scan(dest ...any) error
}

// mgErr maps database errors to store errors and adds context.
func mgErr(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("postgres: %s: %w", op, store.ErrNotFound)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			return fmt.Errorf("postgres: %s: %w", op, store.ErrConflict)
		case "23503": // foreign_key_violation on insert or update
			return fmt.Errorf("postgres: %s: referenced record: %w", op, store.ErrNotFound)
		case "22P02": // invalid_text_representation, e.g. a malformed UUID
			return fmt.Errorf("postgres: %s: %w", op, store.ErrNotFound)
		case "23514", "23502", "22003": // check, not null, numeric range
			return fmt.Errorf("postgres: %s: %s: %w", op, pgErr.ConstraintName, store.ErrInvalid)
		}
	}
	return fmt.Errorf("postgres: %s: %w", op, err)
}

// mgDeleteErr is mgErr for deletes, where a foreign key violation means the
// row is still referenced. PostgreSQL 18 reports ON DELETE RESTRICT as
// restrict_violation (23001), earlier versions as foreign_key_violation.
func mgDeleteErr(op string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && (pgErr.Code == "23503" || pgErr.Code == "23001") {
		return fmt.Errorf("postgres: %s: %w", op, store.ErrInUse)
	}
	return mgErr(op, err)
}

func mgNotFound(op string) error {
	return fmt.Errorf("postgres: %s: %w", op, store.ErrNotFound)
}

// mgNewID returns a time-ordered UUID (v7).
func mgNewID() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("postgres: new id: %w", err)
	}
	return id.String(), nil
}

// mgNow is the current time at the precision PostgreSQL stores.
func mgNow() time.Time {
	return time.Now().UTC().Truncate(time.Microsecond)
}

func mgOrNow(t time.Time) time.Time {
	if t.IsZero() {
		return mgNow()
	}
	return t.UTC()
}

// mgText maps an empty string to NULL.
func mgText(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// mgBytes maps an empty slice to NULL.
func mgBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func mgTimePtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC()
}

func mgDeref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func mgUTCPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

// mgInTx runs fn in a transaction, joining the current one when d is already
// bound to a transaction. Unlike WithTx it does not need the full store.Store.
func (d *DB) mgInTx(ctx context.Context, fn func(tx *DB) error) error {
	if d.inTx {
		return fn(d)
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	if err := fn(&DB{pool: d.pool, q: tx, inTx: true}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit: %w", err)
	}
	return nil
}

// mgExactlyOne turns a zero-row command into ErrNotFound.
func mgExactlyOne(op string, tag pgconn.CommandTag, err error) error {
	if err != nil {
		return mgErr(op, err)
	}
	if tag.RowsAffected() == 0 {
		return mgNotFound(op)
	}
	return nil
}
