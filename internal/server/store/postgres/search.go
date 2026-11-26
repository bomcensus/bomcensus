// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// features caches optional parts of the schema. It is shared by a DB and the
// transactions it starts.
type features struct {
	mu        sync.Mutex
	trgm      bool
	checkedAt time.Time
}

// trgmRecheck is how long a missing search index is remembered; migrations
// may run from another process while the server runs.
const trgmRecheck = time.Minute

// trgmIndexes are the trigram indexes for the substring (ILIKE '%q%')
// searches of the larger lists. They are not in a migration: pg_trgm may be
// missing or not creatable by this role (managed PostgreSQL), and once an
// administrator creates it the next start adds them.
var trgmIndexes = []struct{ name, table, expr string }{
	{"processes_exe_trgm_idx", "processes", "exe"},
	{"processes_cmdline_trgm_idx", "processes", "cmdline"},
	{"processes_user_trgm_idx", "processes", "user_name"},
	{"processes_pid_trgm_idx", "processes", "(pid::text)"},
	{"assets_name_trgm_idx", "assets", "name"},
	{"components_name_trgm_idx", "components", "name"},
	{"components_purl_trgm_idx", "components", "purl"},
}

// ensureSearchIndexes creates pg_trgm and the trigram indexes when it can. A
// missing extension is not an error: searches then scan.
func (d *DB) ensureSearchIndexes(ctx context.Context) error {
	var have bool
	if err := d.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm')`).Scan(&have); err != nil {
		return fmt.Errorf("postgres: search indexes: %w", err)
	}
	if !have {
		if _, err := d.pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pg_trgm`); err != nil {
			return nil //nolint:nilerr // reported by TrigramSearch
		}
	}
	for _, ix := range trgmIndexes {
		if _, err := d.pool.Exec(ctx, fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s ON %s USING gin (%s gin_trgm_ops)`,
			ix.name, ix.table, ix.expr)); err != nil {
			return fmt.Errorf("postgres: search index %s: %w", ix.name, err)
		}
	}
	return nil
}

// TrigramSearch reports whether the trigram search indexes exist.
func (d *DB) TrigramSearch(ctx context.Context) (bool, error) {
	var n int
	names := make([]string, len(trgmIndexes))
	for i, ix := range trgmIndexes {
		names[i] = ix.name
	}
	err := d.q.QueryRow(ctx, `SELECT count(*) FROM unnest($1::text[]) n WHERE to_regclass(n) IS NOT NULL`, names).Scan(&n)
	return n == len(trgmIndexes), err
}

// trigramSearch is TrigramSearch, cached. Errors count as no index.
func (d *DB) trigramSearch(ctx context.Context) bool {
	if d.feat == nil {
		return false
	}
	d.feat.mu.Lock()
	defer d.feat.mu.Unlock()
	if d.feat.trgm || time.Since(d.feat.checkedAt) < trgmRecheck {
		return d.feat.trgm
	}
	d.feat.trgm, _ = d.TrigramSearch(ctx)
	d.feat.checkedAt = time.Now()
	return d.feat.trgm
}

// trgmMinLen is the shortest search a trigram index helps with; shorter
// patterns match most of the index and are faster as a plain scan.
const trgmMinLen = 3

// useTrigram reports whether a search for q should take the indexed form.
func (d *DB) useTrigram(ctx context.Context, q string) bool {
	return utf8.RuneCountInString(strings.TrimSpace(q)) >= trgmMinLen && d.trigramSearch(ctx)
}
