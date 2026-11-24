// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

var _ store.VulnViews = (*DB)(nil)

// vuOpen is the open findings, and vuLocations one exposure per place of a
// component.
const vuOpen = `open AS (
		SELECT asset_id, container, component_id, vuln_id, exposure FROM findings WHERE resolved_at IS NULL
	), locs AS (
		SELECT DISTINCT component_id, asset_id, container, exposure FROM open
	)`

const vuExposureCols = `count(*) FILTER (WHERE exposure = 'listening') AS listening,
	count(*) FILTER (WHERE exposure = 'running') AS running,
	count(*) FILTER (WHERE exposure = 'installed') AS installed,
	count(*) FILTER (WHERE exposure = 'unknown') AS unknown_exposure`

// VulnComponents implements store.VulnViews.
func (d *DB) VulnComponents(ctx context.Context) ([]store.VulnComponentRow, error) {
	rows, err := d.q.Query(ctx, `
		WITH `+vuOpen+`, per AS (
			SELECT o.component_id,
				array_agg(DISTINCT o.vuln_id) AS vulns,
				coalesce(array_agg(DISTINCT o.vuln_id) FILTER (WHERE m.severity IN ('critical', 'high')), '{}') AS hot,
				coalesce(array_agg(DISTINCT o.vuln_id) FILTER (WHERE m.kev_added IS NOT NULL), '{}') AS kev,
				count(DISTINCT o.vuln_id) FILTER (WHERE m.severity = 'critical') AS critical,
				count(DISTINCT o.vuln_id) FILTER (WHERE m.severity = 'high') AS high,
				count(DISTINCT o.vuln_id) FILTER (WHERE m.severity = 'medium') AS medium,
				count(DISTINCT o.vuln_id) FILTER (WHERE m.severity = 'low') AS low,
				count(DISTINCT o.vuln_id) FILTER (WHERE m.severity IN ('', 'none')) AS unknown,
				max(m.max_score) AS score, max(m.epss) AS epss,
				count(DISTINCT o.asset_id) AS assets
			FROM open o JOIN vuln_meta m ON m.vuln_id = o.vuln_id
			GROUP BY o.component_id
		), ex AS (
			SELECT component_id, `+vuExposureCols+` FROM locs GROUP BY component_id
		), fix AS (
			SELECT x.component_id,
				coalesce(array_agg(DISTINCT cv.fixed_version) FILTER (WHERE cv.fixed_version <> ''), '{}') AS fixes,
				count(DISTINCT x.vuln_id) - count(DISTINCT x.vuln_id) FILTER (WHERE cv.fixed_version <> '') AS unfixed
			FROM (SELECT DISTINCT component_id, vuln_id FROM open) x
			JOIN component_vulns cv ON cv.component_id = x.component_id AND cv.vuln_id = x.vuln_id
			GROUP BY x.component_id
		)
		SELECT c.id::text, c.type, c.name, c.version, c.purl, per.vulns, per.hot, per.kev,
			per.critical, per.high, per.medium, per.low, per.unknown, per.score, per.epss, per.assets,
			ex.listening, ex.running, ex.installed, ex.unknown_exposure,
			coalesce(fix.fixes, '{}'), coalesce(fix.unfixed, 0)
		FROM per
		JOIN components c ON c.id = per.component_id
		JOIN ex ON ex.component_id = per.component_id
		LEFT JOIN fix ON fix.component_id = per.component_id`)
	if err != nil {
		return nil, mgErr("vulnerable components", err)
	}
	var out []store.VulnComponentRow
	index := map[string]int{}
	for rows.Next() {
		var r store.VulnComponentRow
		var score, epss *float32
		if err := rows.Scan(&r.Component.ID, &r.Component.Type, &r.Component.Name, &r.Component.Version, &r.Component.PURL,
			&r.VulnIDs, &r.HotVulnIDs, &r.KEVVulnIDs,
			&r.Severity.Critical, &r.Severity.High, &r.Severity.Medium, &r.Severity.Low, &r.Severity.Unknown,
			&score, &epss, &r.Assets,
			&r.Exposure.Listening, &r.Exposure.Running, &r.Exposure.Installed, &r.Exposure.Unknown,
			&r.FixedVersions, &r.Unfixed); err != nil {
			rows.Close()
			return nil, mgErr("vulnerable components", err)
		}
		r.MaxScore, r.MaxEPSS = vuF64(score), vuF64(epss)
		index[r.Component.ID] = len(out)
		out = append(out, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, mgErr("vulnerable components", err)
	}

	// The executables of the loading processes, one per process and place.
	rows, err = d.q.Query(ctx, `
		SELECT component_id::text, exe, count(*) FROM (
			SELECT DISTINCT f.component_id, f.asset_id, f.container, p->>'pod' AS pod, p->>'pid' AS pid, p->>'exe' AS exe
			FROM findings f CROSS JOIN LATERAL jsonb_array_elements(f.processes) p
			WHERE f.resolved_at IS NULL
		) x
		GROUP BY component_id, exe
		ORDER BY component_id, count(*) DESC, exe`)
	if err != nil {
		return nil, mgErr("vulnerable components", err)
	}
	for rows.Next() {
		var id string
		var pc store.ProcessCount
		if err := rows.Scan(&id, &pc.Exe, &pc.Count); err != nil {
			rows.Close()
			return nil, mgErr("vulnerable components", err)
		}
		if i, ok := index[id]; ok && len(out[i].Processes) < 5 {
			out[i].Processes = append(out[i].Processes, pc)
		}
	}
	rows.Close()
	return out, mgErr("vulnerable components", rows.Err())
}

// VulnCves implements store.VulnViews.
func (d *DB) VulnCves(ctx context.Context) ([]store.VulnCveRow, error) {
	rows, err := d.q.Query(ctx, `
		WITH `+vuOpen+`, per AS (
			SELECT o.vuln_id, count(DISTINCT o.component_id) AS components, count(DISTINCT o.asset_id) AS assets,
				array_agg(DISTINCT c.name) AS names
			FROM open o JOIN components c ON c.id = o.component_id
			GROUP BY o.vuln_id
		), ex AS (
			SELECT vuln_id, `+vuExposureCols+`
			FROM (SELECT DISTINCT vuln_id, component_id, asset_id, container, exposure FROM open) x
			GROUP BY vuln_id
		)
		SELECT `+vuMetaCols+`, per.components, per.assets, per.names,
			ex.listening, ex.running, ex.installed, ex.unknown_exposure
		FROM per
		JOIN vuln_meta m ON m.vuln_id = per.vuln_id
		JOIN ex ON ex.vuln_id = per.vuln_id`)
	if err != nil {
		return nil, mgErr("vulnerabilities", err)
	}
	defer rows.Close()
	var out []store.VulnCveRow
	for rows.Next() {
		var r store.VulnCveRow
		if err := vuScanMeta(rows, &r.Meta, &r.Components, &r.Assets, &r.ComponentNames,
			&r.Exposure.Listening, &r.Exposure.Running, &r.Exposure.Installed, &r.Exposure.Unknown); err != nil {
			return nil, mgErr("vulnerabilities", err)
		}
		out = append(out, r)
	}
	return out, mgErr("vulnerabilities", rows.Err())
}

// OpenFindings implements store.VulnViews.
func (d *DB) OpenFindings(ctx context.Context, f store.OpenFindingFilter) ([]store.OpenFinding, error) {
	var conds []string
	var args []any
	add := func(col, v string) {
		if v != "" {
			args = append(args, v)
			conds = append(conds, fmt.Sprintf("%s = $%d", col, len(args)))
		}
	}
	add("f.asset_id", f.AssetID)
	add("f.component_id", f.ComponentID)
	add("f.vuln_id", f.VulnID)
	if len(conds) == 0 {
		return nil, fmt.Errorf("postgres: open findings: no filter: %w", store.ErrInvalid)
	}
	rows, err := d.q.Query(ctx, `
		SELECT `+vuMetaCols+`,
			f.id::text, f.asset_id::text, a.name, a.kind, f.container, f.layer, f.image_digest,
			c.id::text, c.type, c.name, c.version, c.purl,
			f.vuln_id, f.exposure, f.processes::text, f.first_seen,
			coalesce(loc.locs, '{}'), coalesce(loc.method, ''),
			coalesce(cv.method, ''), coalesce(cv.ecosystem, ''), coalesce(cv.fix_state, 'unknown'),
			coalesce(cv.fixed_version, ''), coalesce(cv.cpe_match, ''), coalesce(cv.range_source, ''),
			coalesce(cv.platforms, '{}'), coalesce(cv.advisories::text, '[]')
		FROM findings f
		JOIN assets a ON a.id = f.asset_id
		JOIN components c ON c.id = f.component_id
		JOIN vuln_meta m ON m.vuln_id = f.vuln_id
		LEFT JOIN LATERAL (
			SELECT * FROM component_vulns v WHERE v.component_id = f.component_id AND v.vuln_id = f.vuln_id
			ORDER BY v.method = 'package' DESC LIMIT 1
		) cv ON true
		LEFT JOIN LATERAL (
			SELECT array_agg(DISTINCT z.l) FILTER (WHERE z.l IS NOT NULL) AS locs, min(z.method) AS method FROM (
				SELECT unnest(CASE WHEN ac.locations = '{}' THEN '{NULL}'::text[] ELSE ac.locations END) AS l, ac.method
				FROM asset_components ac
				WHERE (f.layer <> 'image' OR f.image_digest = '')
					AND ac.asset_id = f.asset_id AND ac.container = f.container AND ac.component_id = f.component_id
					AND ac.removed_at IS NULL
				UNION ALL
				SELECT unnest(CASE WHEN ic.locations = '{}' THEN '{NULL}'::text[] ELSE ic.locations END), ic.method
				FROM image_components ic
				WHERE f.layer = 'image' AND f.image_digest <> '' AND ic.digest = f.image_digest AND ic.component_id = f.component_id
			) z
		) loc ON true
		WHERE f.resolved_at IS NULL AND `+strings.Join(conds, " AND ")+`
		ORDER BY a.name, f.asset_id, f.container, c.name, f.vuln_id`, args...)
	if err != nil {
		return nil, mgErr("open findings", err)
	}
	defer rows.Close()
	var out []store.OpenFinding
	for rows.Next() {
		var o store.OpenFinding
		var procs, adv string
		if err := vuScanMeta(rows, &o.Meta, &o.ID, &o.AssetID, &o.AssetName, &o.AssetKind, &o.Container, &o.Layer, &o.ImageDigest,
			&o.Component.ID, &o.Component.Type, &o.Component.Name, &o.Component.Version, &o.Component.PURL,
			&o.VulnID, &o.Exposure, &procs, &o.FirstSeen,
			&o.Locations, &o.Method,
			&o.Match.Method, &o.Match.Ecosystem, &o.Match.FixState, &o.Match.FixedVersion, &o.Match.CPEMatch,
			&o.Match.RangeSource, &o.Match.Platforms, &adv); err != nil {
			return nil, mgErr("open findings", err)
		}
		if err := json.Unmarshal([]byte(procs), &o.Processes); err != nil {
			return nil, fmt.Errorf("postgres: open findings: processes: %w", err)
		}
		if err := json.Unmarshal([]byte(adv), &o.Match.Advisories); err != nil {
			return nil, fmt.Errorf("postgres: open findings: advisories: %w", err)
		}
		o.Match.VulnID = o.VulnID
		o.FirstSeen = o.FirstSeen.UTC()
		out = append(out, o)
	}
	return out, mgErr("open findings", rows.Err())
}

// GetVulnMeta implements store.VulnViews.
func (d *DB) GetVulnMeta(ctx context.Context, vulnID string) (store.VulnMeta, error) {
	var v store.VulnMeta
	err := vuScanMeta(d.q.QueryRow(ctx, `SELECT `+vuMetaCols+` FROM vuln_meta m WHERE m.vuln_id = $1`, vulnID), &v)
	return v, mgErr("get vulnerability", err)
}

// CountFindingAssets implements store.VulnViews.
func (d *DB) CountFindingAssets(ctx context.Context) (int, error) {
	var n int
	err := d.q.QueryRow(ctx, `SELECT count(DISTINCT asset_id) FROM findings WHERE resolved_at IS NULL`).Scan(&n)
	return n, mgErr("count finding assets", err)
}
