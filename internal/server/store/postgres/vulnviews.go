// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

var _ store.VulnViews = (*DB)(nil)

// vuOpen is the open findings of assets in the scope with whether an active
// triage rule defers them at $1 and their severity (store.MatchSeverity of
// the package match first), open those shown ($2 includes deferred ones, $3
// negligible ones), and locs one exposure per place of a component.
func vuOpen(sc sqlScope) string {
	return `allopen AS (
		SELECT f.asset_id, f.container, f.component_id, f.vuln_id, f.exposure, f.processes,
			coalesce(t.rule_id IS NOT NULL AND (t.expires_at IS NULL OR t.expires_at > $1), false) AS deferred,
			coalesce(nullif(cv.severity, ''), m.severity, '') AS severity
		FROM findings f
		JOIN assets a ON a.id = f.asset_id
		JOIN components c ON c.id = f.component_id
		LEFT JOIN vuln_meta m ON m.vuln_id = f.vuln_id
		LEFT JOIN LATERAL (
			SELECT v.severity FROM component_vulns v WHERE v.component_id = f.component_id AND v.vuln_id = f.vuln_id
			ORDER BY v.method = 'package' DESC LIMIT 1
		) cv ON true
		LEFT JOIN LATERAL triage_rule_for(f.vuln_id, f.asset_id, a.group_name, c.purl, $1, ARRAY[a.scope_id]) t ON true
		WHERE f.resolved_at IS NULL AND ` + sc.col("a.scope_id") + `
	), open AS (
		SELECT * FROM allopen WHERE ($2 OR NOT deferred) AND ($3 OR severity <> 'negligible')
	), locs AS (
		SELECT DISTINCT component_id, asset_id, container, exposure FROM open
	)`
}

func vuArgs(o store.VulnViewOptions) []any {
	return []any{mgOrNow(o.At), o.IncludeDeferred, o.IncludeNegligible}
}

// vuScoped binds vuArgs(o) and the scope of ctx.
func vuScoped(ctx context.Context, op string, o store.VulnViewOptions) (*ivQuery, sqlScope, error) {
	return scoped(ctx, op, vuArgs(o)...)
}

// vuSevRank orders the severity in col, highest first. A vulnerability
// without a rating ranks above a negligible one: it may be anything.
func vuSevRank(col string) string {
	return `CASE ` + col + ` WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2
		WHEN 'negligible' THEN 0 ELSE 1 END`
}

// vuSevTop is the highest severity in col of a group.
func vuSevTop(col string) string {
	return `(array_agg(` + col + ` ORDER BY ` + vuSevRank(col) + ` DESC))[1]`
}

// vuSevCounts counts the distinct ids by the severity in col; each id has
// one severity in the group.
func vuSevCounts(id, col string) string {
	f := func(cond string) string { return `count(DISTINCT ` + id + `) FILTER (WHERE ` + col + ` ` + cond + `)` }
	return f(`= 'critical'`) + ` AS critical, ` + f(`= 'high'`) + ` AS high, ` + f(`= 'medium'`) + ` AS medium, ` +
		f(`= 'low'`) + ` AS low, ` + f(`= 'negligible'`) + ` AS negligible, ` + f(`IN ('', 'none')`) + ` AS unknown`
}

const vuExposureCols = `count(*) FILTER (WHERE exposure = 'listening') AS listening,
	count(*) FILTER (WHERE exposure = 'running') AS running,
	count(*) FILTER (WHERE exposure = 'installed') AS installed,
	count(*) FILTER (WHERE exposure = 'unknown') AS unknown_exposure`

// VulnComponents implements store.VulnViews.
func (d *DB) VulnComponents(ctx context.Context, o store.VulnViewOptions) ([]store.VulnComponentRow, error) {
	q, sc, err := vuScoped(ctx, "vulnerable components", o)
	if err != nil {
		return nil, err
	}
	rows, err := d.q.Query(ctx, `
		WITH `+vuOpen(sc)+`, per AS (
			SELECT o.component_id,
				array_agg(DISTINCT o.vuln_id) AS vulns,
				coalesce(array_agg(DISTINCT o.vuln_id) FILTER (WHERE o.severity IN ('critical', 'high')), '{}') AS hot,
				coalesce(array_agg(DISTINCT o.vuln_id) FILTER (WHERE m.kev_added IS NOT NULL), '{}') AS kev,
				`+vuSevCounts("o.vuln_id", "o.severity")+`,
				max(m.max_score) AS score, max(m.epss) AS epss,
				count(DISTINCT o.asset_id) AS assets,
				count(*) FILTER (WHERE o.deferred) AS deferred
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
			per.critical, per.high, per.medium, per.low, per.negligible, per.unknown, per.score, per.epss, per.assets, per.deferred,
			ex.listening, ex.running, ex.installed, ex.unknown_exposure,
			coalesce(fix.fixes, '{}'), coalesce(fix.unfixed, 0)
		FROM per
		JOIN components c ON c.id = per.component_id
		JOIN ex ON ex.component_id = per.component_id
		LEFT JOIN fix ON fix.component_id = per.component_id`, q.args...)
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
			&r.Severity.Critical, &r.Severity.High, &r.Severity.Medium, &r.Severity.Low, &r.Severity.Negligible, &r.Severity.Unknown,
			&score, &epss, &r.Assets, &r.Deferred,
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
		WITH `+vuOpen(sc)+`
		SELECT component_id::text, exe, count(*) FROM (
			SELECT DISTINCT o.component_id, o.asset_id, o.container, p->>'pod' AS pod, p->>'pid' AS pid, p->>'exe' AS exe
			FROM open o CROSS JOIN LATERAL jsonb_array_elements(o.processes) p
		) x
		GROUP BY component_id, exe
		ORDER BY component_id, count(*) DESC, exe`, q.args...)
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
func (d *DB) VulnCves(ctx context.Context, o store.VulnViewOptions) ([]store.VulnCveRow, error) {
	q, sc, err := vuScoped(ctx, "vulnerabilities", o)
	if err != nil {
		return nil, err
	}
	rows, err := d.q.Query(ctx, `
		WITH `+vuOpen(sc)+`, per AS (
			SELECT o.vuln_id, count(DISTINCT o.component_id) AS components, count(DISTINCT o.asset_id) AS assets,
				array_agg(DISTINCT c.name) AS names, count(*) FILTER (WHERE o.deferred) AS deferred,
				`+vuSevTop("o.severity")+` AS severity
			FROM open o JOIN components c ON c.id = o.component_id
			GROUP BY o.vuln_id
		), ex AS (
			SELECT vuln_id, `+vuExposureCols+`
			FROM (SELECT DISTINCT vuln_id, component_id, asset_id, container, exposure FROM open) x
			GROUP BY vuln_id
		)
		SELECT `+vuMetaCols+`, per.components, per.assets, per.names, per.deferred, per.severity,
			ex.listening, ex.running, ex.installed, ex.unknown_exposure
		FROM per
		JOIN vuln_meta m ON m.vuln_id = per.vuln_id
		JOIN ex ON ex.vuln_id = per.vuln_id`, q.args...)
	if err != nil {
		return nil, mgErr("vulnerabilities", err)
	}
	defer rows.Close()
	var out []store.VulnCveRow
	for rows.Next() {
		var r store.VulnCveRow
		if err := vuScanMeta(rows, &r.Meta, &r.Components, &r.Assets, &r.ComponentNames, &r.Deferred, &r.Severity,
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
	if f.Exe != "" {
		b, err := json.Marshal([]map[string]string{{"exe": f.Exe}})
		if err != nil {
			return nil, err
		}
		args = append(args, string(b))
		conds = append(conds, fmt.Sprintf("f.processes @> $%d::jsonb", len(args)))
	}
	if len(conds) == 0 {
		return nil, fmt.Errorf("postgres: open findings: no filter: %w", store.ErrInvalid)
	}
	args = append(args, mgOrNow(f.At))
	atArg := fmt.Sprintf("$%d", len(args))
	q, sc, err := scoped(ctx, "open findings", args...)
	if err != nil {
		return nil, err
	}
	args = q.args
	conds = append(conds, sc.col("a.scope_id"))
	rows, err := d.q.Query(ctx, `
		SELECT `+vuMetaCols+`,
			f.id::text, f.asset_id::text, a.name, a.kind, f.container, f.layer, f.image_digest,
			c.id::text, c.type, c.name, c.version, c.purl,
			f.vuln_id, f.exposure, coalesce(f.reachability, ''), f.processes::text, f.first_seen,
			coalesce(loc.locs, '{}'), coalesce(loc.method, ''),
			coalesce(cv.method, ''), coalesce(cv.ecosystem, ''), coalesce(cv.fix_state, 'unknown'),
			coalesce(cv.fixed_version, ''), coalesce(cv.cpe_match, ''), coalesce(cv.range_source, ''),
			coalesce(cv.platforms, '{}'), coalesce(cv.advisories::text, '[]'), coalesce(cv.symbols::text, '[]'),
			coalesce(cv.severity, ''), t.rule_id IS NOT NULL, coalesce(t.expires_at IS NULL OR t.expires_at > `+atArg+`, false),
			`+trCols+`
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
		LEFT JOIN LATERAL triage_rule_for(f.vuln_id, f.asset_id, a.group_name, c.purl, `+atArg+`, ARRAY[a.scope_id]) t ON true
		LEFT JOIN triage_rules r ON r.id = t.rule_id
		WHERE f.resolved_at IS NULL AND `+strings.Join(conds, " AND ")+`
		ORDER BY a.name, f.asset_id, f.container, c.name, f.vuln_id`, args...)
	if err != nil {
		return nil, mgErr("open findings", err)
	}
	defer rows.Close()
	var out []store.OpenFinding
	for rows.Next() {
		var o store.OpenFinding
		var procs, adv, syms string
		var hasRule, active bool
		var rule trNullRule
		if err := vuScanMeta(rows, &o.Meta, &o.ID, &o.AssetID, &o.AssetName, &o.AssetKind, &o.Container, &o.Layer, &o.ImageDigest,
			&o.Component.ID, &o.Component.Type, &o.Component.Name, &o.Component.Version, &o.Component.PURL,
			&o.VulnID, &o.Exposure, &o.Reachability, &procs, &o.FirstSeen,
			&o.Locations, &o.Method,
			&o.Match.Method, &o.Match.Ecosystem, &o.Match.FixState, &o.Match.FixedVersion, &o.Match.CPEMatch,
			&o.Match.RangeSource, &o.Match.Platforms, &adv, &syms, &o.Match.Severity, &hasRule, &active,
			&rule.ID, &rule.VulnID, &rule.ScopeKind, &rule.ScopeValue, &rule.PURLLike, &rule.Status, &rule.Justification,
			&rule.Note, &rule.ExpiresAt, &rule.ExpiredAt, &rule.CreatedBy, &rule.CreatedAt, &rule.RevokedAt,
			&rule.RevokedBy, &rule.ScopeID); err != nil {
			return nil, mgErr("open findings", err)
		}
		if hasRule {
			o.Triage = &store.FindingTriage{Rule: rule.rule(), Active: active}
		}
		if err := json.Unmarshal([]byte(procs), &o.Processes); err != nil {
			return nil, fmt.Errorf("postgres: open findings: processes: %w", err)
		}
		if err := json.Unmarshal([]byte(adv), &o.Match.Advisories); err != nil {
			return nil, fmt.Errorf("postgres: open findings: advisories: %w", err)
		}
		if err := json.Unmarshal([]byte(syms), &o.Match.Symbols); err != nil {
			return nil, fmt.Errorf("postgres: open findings: symbols: %w", err)
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

// trNullRule scans the rule columns of a LEFT JOIN.
type trNullRule struct {
	ID, VulnID, ScopeKind, ScopeValue, PURLLike, Status, Justification, Note, CreatedBy, RevokedBy, ScopeID *string
	ExpiresAt, ExpiredAt, CreatedAt, RevokedAt                                                              *time.Time
}

func (n trNullRule) rule() store.TriageRule {
	return store.TriageRule{
		ID: mgDeref(n.ID), VulnID: mgDeref(n.VulnID), ScopeKind: mgDeref(n.ScopeKind), ScopeValue: mgDeref(n.ScopeValue),
		PURLLike: mgDeref(n.PURLLike), Status: mgDeref(n.Status), Justification: mgDeref(n.Justification), Note: mgDeref(n.Note),
		ExpiresAt: mgUTCPtr(n.ExpiresAt), ExpiredAt: mgUTCPtr(n.ExpiredAt), CreatedBy: mgDeref(n.CreatedBy),
		CreatedAt: deref0(n.CreatedAt), RevokedAt: mgUTCPtr(n.RevokedAt), RevokedBy: mgDeref(n.RevokedBy),
		ScopeID: mgDeref(n.ScopeID),
	}
}

func deref0(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.UTC()
}

// CountFindingAssets implements store.VulnViews.
func (d *DB) CountFindingAssets(ctx context.Context, at time.Time) (int, error) {
	q, sc, err := vuScoped(ctx, "count finding assets", store.VulnViewOptions{At: at})
	if err != nil {
		return 0, err
	}
	var n int
	err = d.q.QueryRow(ctx, `WITH `+vuOpen(sc)+` SELECT count(DISTINCT asset_id) FROM open`, q.args...).Scan(&n)
	return n, mgErr("count finding assets", err)
}

// CountDeferred implements store.VulnViews.
func (d *DB) CountDeferred(ctx context.Context, at time.Time) (int, error) {
	q, sc, err := vuScoped(ctx, "count deferred", store.VulnViewOptions{At: at})
	if err != nil {
		return 0, err
	}
	var n int
	err = d.q.QueryRow(ctx, `
		WITH `+vuOpen(sc)+`
		SELECT count(*) FROM (
			SELECT vuln_id FROM allopen WHERE severity <> 'negligible' GROUP BY vuln_id HAVING bool_and(deferred)
		) x`, q.args...).Scan(&n)
	return n, mgErr("count deferred", err)
}

// CountNegligible implements store.VulnViews.
func (d *DB) CountNegligible(ctx context.Context, at time.Time) (int, error) {
	q, sc, err := vuScoped(ctx, "count negligible", store.VulnViewOptions{At: at})
	if err != nil {
		return 0, err
	}
	var n int
	err = d.q.QueryRow(ctx, `
		WITH `+vuOpen(sc)+`
		SELECT count(*) FROM (
			SELECT vuln_id FROM allopen WHERE NOT deferred GROUP BY vuln_id HAVING bool_and(severity = 'negligible')
		) x`, q.args...).Scan(&n)
	return n, mgErr("count negligible", err)
}

// VulnProcesses implements store.VulnViews.
func (d *DB) VulnProcesses(ctx context.Context, o store.VulnViewOptions) ([]store.VulnProcessRow, error) {
	q, sc, err := vuScoped(ctx, "vulnerable processes", o)
	if err != nil {
		return nil, err
	}
	rows, err := d.q.Query(ctx, `
		WITH `+vuOpen(sc)+`, p AS (
			SELECT o.asset_id, o.container, o.component_id, o.vuln_id, pr->>'exe' AS exe,
				coalesce(pr->>'pod', '') AS pod, pr->>'pid' AS pid,
				jsonb_array_length(coalesce(pr->'ports', '[]'::jsonb)) > 0 AS listening, o.severity
			FROM open o CROSS JOIN LATERAL jsonb_array_elements(o.processes) pr
		), pv AS (
			SELECT exe, vuln_id, `+vuSevTop("severity")+` AS severity FROM p GROUP BY exe, vuln_id
		), sev AS (
			SELECT exe, `+vuSevCounts("vuln_id", "severity")+` FROM pv GROUP BY exe
		), per AS (
			SELECT p.exe, count(DISTINCT p.asset_id) AS assets,
				count(DISTINCT (p.asset_id, p.container, p.pod, p.pid)) AS processes,
				count(DISTINCT (p.asset_id, p.container, p.pod, p.pid)) FILTER (WHERE p.listening) AS listening,
				count(DISTINCT p.component_id) AS components, array_agg(DISTINCT p.vuln_id) AS vulns,
				count(DISTINCT p.vuln_id) FILTER (WHERE m.kev_added IS NOT NULL) AS kev, max(m.max_score) AS score
			FROM p JOIN vuln_meta m ON m.vuln_id = p.vuln_id
			GROUP BY p.exe
		)
		SELECT per.exe, per.assets, per.processes, per.listening, per.components, per.vulns, per.kev, per.score,
			sev.critical, sev.high, sev.medium, sev.low, sev.negligible, sev.unknown
		FROM per JOIN sev ON sev.exe = per.exe`, q.args...)
	if err != nil {
		return nil, mgErr("vulnerable processes", err)
	}
	defer rows.Close()
	var out []store.VulnProcessRow
	for rows.Next() {
		var r store.VulnProcessRow
		var score *float32
		if err := rows.Scan(&r.Exe, &r.Assets, &r.Processes, &r.Listening, &r.Components, &r.VulnIDs, &r.KEV, &score,
			&r.Severity.Critical, &r.Severity.High, &r.Severity.Medium, &r.Severity.Low, &r.Severity.Negligible,
			&r.Severity.Unknown); err != nil {
			return nil, mgErr("vulnerable processes", err)
		}
		r.MaxScore = vuF64(score)
		out = append(out, r)
	}
	return out, mgErr("vulnerable processes", rows.Err())
}

// vuImageVulns is the vulnerabilities of the contents of images visible in
// the scope, with whether a component rule of the scope defers them at $1
// and their severity as in vuOpen.
func vuImageVulns(sc sqlScope) string {
	return `iv AS (
		SELECT ic.digest, ic.component_id, cv.vuln_id,
			coalesce(t.rule_id IS NOT NULL AND (t.expires_at IS NULL OR t.expires_at > $1), false) AS deferred,
			coalesce(nullif(cv.severity, ''), m.severity) AS severity
		FROM image_components ic
		JOIN components c ON c.id = ic.component_id
		JOIN (
			SELECT DISTINCT ON (component_id, vuln_id) component_id, vuln_id, severity FROM component_vulns
			ORDER BY component_id, vuln_id, method = 'package' DESC
		) cv ON cv.component_id = ic.component_id
		JOIN vuln_meta m ON m.vuln_id = cv.vuln_id
		LEFT JOIN LATERAL triage_rule_for(cv.vuln_id, NULL, '', c.purl, $1, ` + sc.rules() + `) t ON true
		WHERE ` + sc.image("ic.digest") + `
	)`
}

// VulnImages implements store.VulnViews.
func (d *DB) VulnImages(ctx context.Context, o store.VulnViewOptions) ([]store.VulnImageRow, error) {
	q, sc, err := vuScoped(ctx, "vulnerable images", o)
	if err != nil {
		return nil, err
	}
	rows, err := d.q.Query(ctx, `
		WITH `+vuImageVulns(sc)+`, shown AS (
			SELECT * FROM iv WHERE ($2 OR NOT deferred) AND ($3 OR severity <> 'negligible')
		), sev AS (
			SELECT digest, `+vuSevCounts("vuln_id", "severity")+` FROM (
				SELECT digest, vuln_id, `+vuSevTop("severity")+` AS severity FROM shown GROUP BY digest, vuln_id
			) x GROUP BY digest
		), per AS (
			SELECT s.digest, count(DISTINCT s.component_id) AS components, array_agg(DISTINCT s.vuln_id) AS vulns,
				count(DISTINCT s.vuln_id) FILTER (WHERE m.kev_added IS NOT NULL) AS kev,
				max(m.max_score) AS score, max(m.epss) AS epss,
				sev.critical, sev.high, sev.medium, sev.low, sev.negligible, sev.unknown
			FROM shown s JOIN vuln_meta m ON m.vuln_id = s.vuln_id JOIN sev ON sev.digest = s.digest
			GROUP BY s.digest, sev.critical, sev.high, sev.medium, sev.low, sev.negligible, sev.unknown
		)
		SELECT per.digest,
			coalesce((SELECT array_agg(DISTINCT it.tag ORDER BY it.tag) FROM image_tags it
				WHERE it.digest = per.digest AND it.gone_at IS NULL AND `+ivTagIn(sc)+`), '{}'),
			per.components, per.vulns, per.kev, per.score, per.epss,
			per.critical, per.high, per.medium, per.low, per.negligible, per.unknown,
			(SELECT count(*) FROM asset_containers ct JOIN assets ca ON ca.id = ct.asset_id
				WHERE ct.image_digest = per.digest AND ct.gone_at IS NULL AND ca.gone_at IS NULL AND `+sc.col("ca.scope_id")+`),
			(SELECT count(DISTINCT ct.asset_id) FROM asset_containers ct JOIN assets ca ON ca.id = ct.asset_id
				WHERE ct.image_digest = per.digest AND ct.gone_at IS NULL AND ca.gone_at IS NULL AND `+sc.col("ca.scope_id")+`)
		FROM per`, q.args...)
	if err != nil {
		return nil, mgErr("vulnerable images", err)
	}
	defer rows.Close()
	var out []store.VulnImageRow
	for rows.Next() {
		var r store.VulnImageRow
		var score, epss *float32
		if err := rows.Scan(&r.Digest, &r.Tags, &r.Components, &r.VulnIDs, &r.KEV, &score, &epss,
			&r.Severity.Critical, &r.Severity.High, &r.Severity.Medium, &r.Severity.Low, &r.Severity.Negligible,
			&r.Severity.Unknown, &r.Containers, &r.Assets); err != nil {
			return nil, mgErr("vulnerable images", err)
		}
		r.MaxScore, r.MaxEPSS = vuF64(score), vuF64(epss)
		out = append(out, r)
	}
	return out, mgErr("vulnerable images", rows.Err())
}

// ImageVulns implements store.VulnViews.
func (d *DB) ImageVulns(ctx context.Context, digest string, at time.Time) ([]store.ImageVuln, error) {
	q, sc, err := scoped(ctx, "image vulnerabilities", digest, mgOrNow(at))
	if err != nil {
		return nil, err
	}
	rows, err := d.q.Query(ctx, `
		SELECT `+vuMetaCols+`, c.id::text, c.type, c.name, c.version, c.purl, ic.locations,
			cv.method, cv.ecosystem, cv.fix_state, cv.fixed_version, cv.cpe_match, cv.range_source,
			cv.platforms, cv.advisories::text, cv.severity,
			coalesce(t.rule_id IS NOT NULL AND (t.expires_at IS NULL OR t.expires_at > $2), false)
		FROM image_components ic
		JOIN components c ON c.id = ic.component_id
		JOIN LATERAL (
			SELECT DISTINCT ON (v.vuln_id) * FROM component_vulns v WHERE v.component_id = ic.component_id
			ORDER BY v.vuln_id, v.method = 'package' DESC
		) cv ON true
		JOIN vuln_meta m ON m.vuln_id = cv.vuln_id
		LEFT JOIN LATERAL triage_rule_for(cv.vuln_id, NULL, '', c.purl, $2, `+sc.rules()+`) t ON true
		WHERE ic.digest = $1 AND `+sc.image("ic.digest")+`
		ORDER BY c.name, c.version, cv.vuln_id`, q.args...)
	if err != nil {
		return nil, mgErr("image vulnerabilities", err)
	}
	defer rows.Close()
	var out []store.ImageVuln
	for rows.Next() {
		var v store.ImageVuln
		var adv string
		if err := vuScanMeta(rows, &v.Meta, &v.Component.ID, &v.Component.Type, &v.Component.Name, &v.Component.Version,
			&v.Component.PURL, &v.Locations, &v.Match.Method, &v.Match.Ecosystem, &v.Match.FixState, &v.Match.FixedVersion,
			&v.Match.CPEMatch, &v.Match.RangeSource, &v.Match.Platforms, &adv, &v.Match.Severity, &v.Deferred); err != nil {
			return nil, mgErr("image vulnerabilities", err)
		}
		if err := json.Unmarshal([]byte(adv), &v.Match.Advisories); err != nil {
			return nil, fmt.Errorf("postgres: image vulnerabilities: advisories: %w", err)
		}
		v.Match.VulnID = v.Meta.ID
		out = append(out, v)
	}
	return out, mgErr("image vulnerabilities", rows.Err())
}
