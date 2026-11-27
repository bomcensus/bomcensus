// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

// Helpers in this file carry an iv prefix so they cannot collide with helpers
// of the management half of the package.

var _ store.Inventory = (*DB)(nil)

// ivAtomic runs fn in a transaction, or in the current one.
func (d *DB) ivAtomic(ctx context.Context, fn func(*DB) error) error {
	if d.inTx {
		return fn(d)
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	if err := fn(&DB{pool: d.pool, q: tx, inTx: true, feat: d.feat}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit: %w", err)
	}
	return nil
}

// ivLock takes a transaction-scoped advisory lock on key.
func (d *DB) ivLock(ctx context.Context, key string) error {
	if _, err := d.q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, key); err != nil {
		return fmt.Errorf("postgres: lock: %w", err)
	}
	return nil
}

// ivLockAsset locks the asset row against concurrent replace operations and
// fails with ErrNotFound when it does not exist in the scope of ctx.
func (d *DB) ivLockAsset(ctx context.Context, op, assetID string) error {
	q, sc, err := scoped(ctx, op, assetID)
	if err != nil {
		return err
	}
	if !ivValidID(assetID) {
		return ivNotFound(op)
	}
	var one int
	err = d.q.QueryRow(ctx, `SELECT 1 FROM assets WHERE id = $1 AND `+sc.col("scope_id")+` FOR NO KEY UPDATE`,
		q.args...).Scan(&one)
	return ivErr(op, err)
}

// ivLockCluster is ivLockAsset for a cluster row.
func (d *DB) ivLockCluster(ctx context.Context, op, clusterID string) error {
	q, sc, err := scoped(ctx, op, clusterID)
	if err != nil {
		return err
	}
	if !ivValidID(clusterID) {
		return ivNotFound(op)
	}
	var one int
	err = d.q.QueryRow(ctx, `SELECT 1 FROM k8s_clusters WHERE id = $1 AND `+sc.col("scope_id")+` FOR NO KEY UPDATE`,
		q.args...).Scan(&one)
	return ivErr(op, err)
}

func ivErr(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("postgres: %s: %w", op, store.ErrNotFound)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return fmt.Errorf("postgres: %s: %w", op, store.ErrConflict)
		case "23503":
			return fmt.Errorf("postgres: %s: referenced record: %w", op, store.ErrNotFound)
		case "22P02":
			return fmt.Errorf("postgres: %s: %w", op, store.ErrInvalid)
		case "23514", "23502", "22003", "22001", "22021":
			return fmt.Errorf("postgres: %s: %s: %w", op, pgErr.Message, store.ErrInvalid)
		}
	}
	return fmt.Errorf("postgres: %s: %w", op, err)
}

func ivNotFound(op string) error {
	return fmt.Errorf("postgres: %s: %w", op, store.ErrNotFound)
}

func ivInvalid(op, msg string) error {
	return fmt.Errorf("postgres: %s: %s: %w", op, msg, store.ErrInvalid)
}

func ivValidID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

func ivNewID() string {
	return uuid.Must(uuid.NewV7()).String()
}

func ivNow() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }

func ivAt(t time.Time) time.Time {
	if t.IsZero() {
		return ivNow()
	}
	return t.UTC().Truncate(time.Microsecond)
}

func ivUTC(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

// ivNull maps an empty string to NULL.
func ivNull(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func ivTimeOrNil(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// ivJSON encodes rows for jsonb_to_recordset.
func ivJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("postgres: encode rows: %w", err)
	}
	return string(b), nil
}

func ivStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ivSortedUnique returns the distinct values of s in order, never nil.
func ivSortedUnique(s []string) []string {
	out := make([]string, 0, len(s))
	out = append(out, s...)
	sort.Strings(out)
	n := 0
	for i, v := range out {
		if i > 0 && v == out[n-1] {
			continue
		}
		out[n] = v
		n++
	}
	return out[:n]
}

// ivIdent is the identity key of a component: the SHA-256 of the
// length-prefixed fields type, name, version, arch, distro and purl, and of
// the build when there is one. Components without a build keep the identity
// they had before builds were reported.
func ivIdent(c store.Component) []byte {
	h := sha256.New()
	var n [8]byte
	fields := []string{c.Type, c.Name, c.Version, c.Arch, c.Distro, c.PURL}
	if c.Build != "" {
		fields = append(fields, "build", c.Build)
	}
	for _, f := range fields {
		binary.BigEndian.PutUint64(n[:], uint64(len(f)))
		h.Write(n[:])
		h.Write([]byte(f))
	}
	return h.Sum(nil)
}

func ivIdentHex(c store.Component) string { return hex.EncodeToString(ivIdent(c)) }

// ivQuery builds a parameterized statement.
type ivQuery struct {
	args  []any
	conds []string
}

// arg adds a parameter and returns its placeholder.
func (q *ivQuery) arg(v any) string {
	q.args = append(q.args, v)
	return "$" + strconv.Itoa(len(q.args))
}

// where adds a condition. Each %s in cond is replaced by a placeholder for
// the next value of args.
func (q *ivQuery) where(cond string, args ...any) {
	ph := make([]any, len(args))
	for i, a := range args {
		ph[i] = q.arg(a)
	}
	q.conds = append(q.conds, fmt.Sprintf(cond, ph...))
}

// and adds a condition that has no parameters of its own.
func (q *ivQuery) and(cond string) {
	q.conds = append(q.conds, cond)
}

func (q *ivQuery) whereSQL() string {
	if len(q.conds) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(q.conds, " AND ")
}

// ivLike turns a search string into an ILIKE substring pattern.
func ivLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(strings.TrimSpace(s)) + "%"
}

// ivOrder maps a sort key ("name" or "-name") to an ORDER BY clause. tie
// makes the order total so pages do not overlap.
func ivOrder(op, sortKey, def string, keys map[string]string, tie string) (string, error) {
	s := sortKey
	if s == "" {
		s = def
	}
	dir := " ASC"
	if strings.HasPrefix(s, "-") {
		dir = " DESC"
		s = s[1:]
	}
	expr, ok := keys[s]
	if !ok {
		return "", ivInvalid(op, fmt.Sprintf("unknown sort key %q", sortKey))
	}
	return " ORDER BY " + expr + dir + ", " + tie, nil
}

// ivPage runs a count and a page query that share from (FROM ... WHERE ...)
// and args. sel is the select list, order the ORDER BY clause.
func ivPage(ctx context.Context, d *DB, op string, q *ivQuery, sel, from, order string, p store.Page, scan func(pgx.Rows) error) (int, error) {
	p = p.Normalize()
	var total int
	if err := d.q.QueryRow(ctx, "SELECT count(*) "+from, q.args...).Scan(&total); err != nil {
		return 0, ivErr(op, err)
	}
	if total == 0 || p.Offset >= total {
		return total, nil
	}
	args := append(append([]any{}, q.args...), p.Limit, p.Offset)
	n := len(q.args)
	sql := "SELECT " + sel + " " + from + order + " LIMIT $" + strconv.Itoa(n+1) + " OFFSET $" + strconv.Itoa(n+2)
	rows, err := d.q.Query(ctx, sql, args...)
	if err != nil {
		return 0, ivErr(op, err)
	}
	defer rows.Close()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return 0, ivErr(op, err)
		}
	}
	if err := rows.Err(); err != nil {
		return 0, ivErr(op, err)
	}
	return total, nil
}

// Component columns of alias c, NULL-safe for outer joins. Scanned by
// ivScanComponent.
const ivComponentCols = `COALESCE(c.id::text, ''), COALESCE(c.type, ''), COALESCE(c.name, ''),
	COALESCE(c.version, ''), COALESCE(c.arch, ''), COALESCE(c.distro, ''), COALESCE(c.purl, ''),
	COALESCE(c.cpe, ''), COALESCE(c.source_name, ''), COALESCE(c.source_version, ''),
	COALESCE(c.vendor, ''), COALESCE(c.origin, ''), COALESCE(c.build, '')`

func ivComponentDest(c *store.Component) []any {
	return []any{&c.ID, &c.Type, &c.Name, &c.Version, &c.Arch, &c.Distro, &c.PURL,
		&c.CPE, &c.SourceName, &c.SourceVersion, &c.Vendor, &c.Origin, &c.Build}
}

// Asset brief columns of asset alias a and cluster alias k.
const ivBriefCols = `a.id::text, a.name, a.kind, a.address, COALESCE(a.cluster_id::text, ''),
	COALESCE(k.name, ''), COALESCE(a.namespace, '')`

func ivBriefDest(b *store.AssetBrief) []any {
	return []any{&b.ID, &b.Name, &b.Kind, &b.Address, &b.ClusterID, &b.ClusterName, &b.Namespace}
}
