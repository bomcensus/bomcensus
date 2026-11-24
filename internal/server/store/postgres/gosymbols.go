// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

var _ store.GoSymbols = (*DB)(nil)

type gsBinaryRow struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	GOOS   string `json:"goos"`
	GOARCH string `json:"goarch"`
}

// ReplaceGoBinaries implements store.GoSymbols.
func (d *DB) ReplaceGoBinaries(ctx context.Context, scope store.GoBinaryScope, bins []store.GoBinary, opts store.ReplaceOptions) error {
	rows := make([]gsBinaryRow, 0, len(bins))
	seen := map[string]bool{}
	for _, b := range bins {
		if b.Path == "" || b.SHA256 == "" || seen[b.Path] {
			continue
		}
		seen[b.Path] = true
		rows = append(rows, gsBinaryRow{Path: b.Path, SHA256: b.SHA256, GOOS: b.GOOS, GOARCH: b.GOARCH})
	}
	js, err := json.Marshal(rows)
	if err != nil {
		return fmt.Errorf("postgres: replace go binaries: %w", err)
	}
	const recs = `jsonb_to_recordset($1::text::jsonb) AS x(path text, sha256 text, goos text, goarch text)`
	at := mgOrNow(opts.At)
	return d.mgInTx(ctx, func(tx *DB) error {
		if scope.Digest != "" {
			if !opts.KeepMissing {
				if _, err := tx.q.Exec(ctx, `
					DELETE FROM image_go_binaries g WHERE g.digest = $2
						AND NOT EXISTS (SELECT 1 FROM `+recs+` WHERE x.path = g.path)`, string(js), scope.Digest); err != nil {
					return mgErr("replace go binaries", err)
				}
			}
			_, err := tx.q.Exec(ctx, `
				INSERT INTO image_go_binaries (digest, path, sha256, goos, goarch)
				SELECT $2, x.path, x.sha256, x.goos, x.goarch FROM `+recs+`
				ON CONFLICT (digest, path) DO UPDATE SET sha256 = excluded.sha256, goos = excluded.goos,
					goarch = excluded.goarch`, string(js), scope.Digest)
			return mgErr("replace go binaries", err)
		}
		if !opts.KeepMissing {
			if _, err := tx.q.Exec(ctx, `
				DELETE FROM go_binaries g WHERE g.asset_id = $2 AND g.container = $3 AND g.layer = $4
					AND NOT EXISTS (SELECT 1 FROM `+recs+` WHERE x.path = g.path)`,
				string(js), scope.AssetID, scope.Container, scope.Layer); err != nil {
				return mgErr("replace go binaries", err)
			}
		}
		_, err := tx.q.Exec(ctx, `
			INSERT INTO go_binaries (asset_id, container, layer, path, sha256, goos, goarch, seen_at)
			SELECT $2, $3, $4, x.path, x.sha256, x.goos, x.goarch, $5 FROM `+recs+`
			ON CONFLICT (asset_id, container, layer, path) DO UPDATE SET sha256 = excluded.sha256,
				goos = excluded.goos, goarch = excluded.goarch, seen_at = excluded.seen_at`,
			string(js), scope.AssetID, scope.Container, scope.Layer, at)
		return mgErr("replace go binaries", err)
	})
}

// SaveGoSymbolResults implements store.GoSymbols.
func (d *DB) SaveGoSymbolResults(ctx context.Context, assetID string, results []store.GoSymbolResult) error {
	if len(results) == 0 {
		return nil
	}
	type row struct {
		SHA256    string    `json:"sha256"`
		Name      string    `json:"name"`
		Result    string    `json:"result"`
		Reason    string    `json:"reason"`
		CheckedAt time.Time `json:"checked_at"`
	}
	rows := make([]row, 0, len(results))
	for _, r := range results {
		rows = append(rows, row{SHA256: r.SHA256, Name: r.Name, Result: r.Result, Reason: r.Reason, CheckedAt: mgOrNow(r.CheckedAt)})
	}
	js, err := json.Marshal(rows)
	if err != nil {
		return fmt.Errorf("postgres: save go symbol results: %w", err)
	}
	return d.mgInTx(ctx, func(tx *DB) error {
		if _, err := tx.q.Exec(ctx, `
			INSERT INTO go_symbol_results (asset_id, sha256, name, result, reason, checked_at)
			SELECT DISTINCT ON (x.sha256, x.name) $2, x.sha256, x.name, x.result, x.reason, x.checked_at
			FROM jsonb_to_recordset($1::text::jsonb) AS x(sha256 text, name text, result text, reason text, checked_at timestamptz)
			ORDER BY x.sha256, x.name, x.checked_at DESC
			ON CONFLICT (asset_id, sha256, name) DO UPDATE SET result = excluded.result, reason = excluded.reason,
				checked_at = excluded.checked_at`, string(js), assetID); err != nil {
			return mgErr("save go symbol results", err)
		}
		_, err := tx.q.Exec(ctx, `
			INSERT INTO asset_findings_state (asset_id, vulns_version) VALUES ($1, 1)
			ON CONFLICT (asset_id) DO UPDATE SET vulns_version = asset_findings_state.vulns_version + 1`, assetID)
		return mgErr("save go symbol results", err)
	})
}

// GoSymbolAssets implements store.GoSymbols.
func (d *DB) GoSymbolAssets(ctx context.Context, since time.Time, limit int) ([]string, error) {
	rows, err := d.q.Query(ctx, `
		SELECT f.asset_id::text FROM findings f
		JOIN assets a ON a.id = f.asset_id AND a.gone_at IS NULL
		WHERE f.resolved_at IS NULL AND f.reachability IS NULL
			AND EXISTS (SELECT 1 FROM component_vulns v
				WHERE v.component_id = f.component_id AND v.vuln_id = f.vuln_id AND v.symbols <> '[]')
			AND NOT EXISTS (SELECT 1 FROM go_symbol_queries q WHERE q.asset_id = f.asset_id AND q.created_at > $1)
		GROUP BY f.asset_id
		ORDER BY f.asset_id
		LIMIT $2`, since, limit)
	if err != nil {
		return nil, mgErr("go symbol assets", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, mgErr("go symbol assets", err)
		}
		out = append(out, id)
	}
	return out, mgErr("go symbol assets", rows.Err())
}

// PutGoSymbolQuery implements store.GoSymbols.
func (d *DB) PutGoSymbolQuery(ctx context.Context, q store.GoSymbolQuery) error {
	_, err := d.q.Exec(ctx, `
		INSERT INTO go_symbol_queries (asset_id, container, query, created_at) VALUES ($1, $2, $3::text::jsonb, $4)
		ON CONFLICT (asset_id, container) DO UPDATE SET query = excluded.query, created_at = excluded.created_at`,
		q.AssetID, q.Container, string(q.Query), mgOrNow(q.CreatedAt))
	return mgErr("put go symbol query", err)
}

// GoSymbolQueryFor implements store.GoSymbols.
func (d *DB) GoSymbolQueryFor(ctx context.Context, assetID, container string) (store.GoSymbolQuery, error) {
	q := store.GoSymbolQuery{AssetID: assetID, Container: container}
	var raw string
	err := d.q.QueryRow(ctx, `SELECT query::text, created_at FROM go_symbol_queries WHERE asset_id = $1 AND container = $2`,
		assetID, container).Scan(&raw, &q.CreatedAt)
	if err != nil {
		return q, mgErr("get go symbol query", err)
	}
	q.Query = json.RawMessage(raw)
	return q, nil
}

// DeleteGoSymbolQuery implements store.GoSymbols.
func (d *DB) DeleteGoSymbolQuery(ctx context.Context, assetID, container string) error {
	_, err := d.q.Exec(ctx, `DELETE FROM go_symbol_queries WHERE asset_id = $1 AND container = $2`, assetID, container)
	return mgErr("delete go symbol query", err)
}

// ClusterGoSymbolQueries implements store.GoSymbols.
func (d *DB) ClusterGoSymbolQueries(ctx context.Context, clusterID string) ([]store.WorkloadGoSymbolQuery, error) {
	rows, err := d.q.Query(ctx, `
		SELECT w.namespace, w.kind, w.name, q.asset_id::text, q.container, q.query::text, q.created_at
		FROM go_symbol_queries q JOIN k8s_workloads w ON w.asset_id = q.asset_id
		WHERE w.cluster_id = $1 AND w.gone_at IS NULL AND NOT w.excluded
		ORDER BY w.namespace, w.kind, w.name, q.container`, clusterID)
	if err != nil {
		return nil, mgErr("cluster go symbol queries", err)
	}
	defer rows.Close()
	var out []store.WorkloadGoSymbolQuery
	for rows.Next() {
		var q store.WorkloadGoSymbolQuery
		var raw string
		if err := rows.Scan(&q.Namespace, &q.WorkloadKind, &q.WorkloadName, &q.AssetID, &q.Container, &raw, &q.CreatedAt); err != nil {
			return nil, mgErr("cluster go symbol queries", err)
		}
		q.Query = json.RawMessage(raw)
		out = append(out, q)
	}
	return out, mgErr("cluster go symbol queries", rows.Err())
}

// gsFindingInputs adds what the reachability of the asset's findings is
// computed from.
func (d *DB) gsFindingInputs(ctx context.Context, assetID string, in *store.FindingInputs, compIDs []string) error {
	in.Symbols = map[string][]store.GoImport{}
	in.SymbolResults = map[string]map[string]store.GoSymbolResult{}
	rows, err := d.q.Query(ctx, `
		SELECT component_id::text, vuln_id, symbols::text FROM component_vulns
		WHERE component_id = ANY($1::uuid[]) AND symbols <> '[]'`, compIDs)
	if err != nil {
		return mgErr("finding inputs", err)
	}
	for rows.Next() {
		var comp, vuln, raw string
		if err := rows.Scan(&comp, &vuln, &raw); err != nil {
			rows.Close()
			return mgErr("finding inputs", err)
		}
		var imps []store.GoImport
		if err := json.Unmarshal([]byte(raw), &imps); err != nil {
			rows.Close()
			return fmt.Errorf("postgres: finding inputs: symbols: %w", err)
		}
		in.Symbols[store.SymbolKey(comp, vuln)] = imps
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return mgErr("finding inputs", err)
	}
	if len(in.Symbols) == 0 {
		return nil
	}

	rows, err = d.q.Query(ctx, `
		SELECT container, layer, '', path, sha256, goos, goarch FROM go_binaries WHERE asset_id = $1
		UNION ALL
		SELECT ct.name, 'image', ct.image_digest, g.path, g.sha256, g.goos, g.goarch
		FROM asset_containers ct JOIN image_go_binaries g ON g.digest = ct.image_digest
		WHERE ct.asset_id = $1 AND ct.gone_at IS NULL AND ct.image_digest <> ''`, assetID)
	if err != nil {
		return mgErr("finding inputs", err)
	}
	for rows.Next() {
		var b store.FindingGoBinary
		if err := rows.Scan(&b.Container, &b.Layer, &b.ImageDigest, &b.Path, &b.SHA256, &b.GOOS, &b.GOARCH); err != nil {
			rows.Close()
			return mgErr("finding inputs", err)
		}
		in.GoBinaries = append(in.GoBinaries, b)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return mgErr("finding inputs", err)
	}

	rows, err = d.q.Query(ctx, `
		SELECT sha256, name, result, reason, checked_at FROM go_symbol_results WHERE asset_id = $1`, assetID)
	if err != nil {
		return mgErr("finding inputs", err)
	}
	for rows.Next() {
		var r store.GoSymbolResult
		if err := rows.Scan(&r.SHA256, &r.Name, &r.Result, &r.Reason, &r.CheckedAt); err != nil {
			rows.Close()
			return mgErr("finding inputs", err)
		}
		if in.SymbolResults[r.SHA256] == nil {
			in.SymbolResults[r.SHA256] = map[string]store.GoSymbolResult{}
		}
		in.SymbolResults[r.SHA256][r.Name] = r
	}
	rows.Close()
	return mgErr("finding inputs", rows.Err())
}
