// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

var _ store.Vulns = (*DB)(nil)

// vuLive is true for a component c that a current asset has installed or an image
// contains.
const vuLive = `(EXISTS (SELECT 1 FROM asset_components ac JOIN assets la ON la.id = ac.asset_id
		WHERE ac.component_id = c.id AND ac.removed_at IS NULL AND la.gone_at IS NULL)
	OR EXISTS (SELECT 1 FROM image_components ic WHERE ic.component_id = c.id))`

// vuMatchedIn joins m, the match of c against the epoch in $1..$3.
const vuMatchedIn = `m.component_id = c.id AND m.feed_server_id = $1 AND m.revision >= $2 AND m.rules_digest = $3`

// PendingMatches implements store.Vulns.
func (d *DB) PendingMatches(ctx context.Context, e store.MatchEpoch, limit int) ([]store.Component, error) {
	rows, err := d.q.Query(ctx, `
		SELECT c.id, c.type, c.name, c.version, c.arch, c.distro, c.purl, c.cpe,
			c.source_name, c.source_version, c.vendor, c.origin, c.modularity, c.build
		FROM components c
		WHERE `+vuLive+`
			AND NOT EXISTS (SELECT 1 FROM component_matches m WHERE `+vuMatchedIn+`)
		ORDER BY c.distro, c.id
		LIMIT $4`,
		e.ServerID, e.Revision, e.Rules, limit)
	if err != nil {
		return nil, mgErr("pending matches", err)
	}
	defer rows.Close()
	var out []store.Component
	for rows.Next() {
		var c store.Component
		if err := rows.Scan(&c.ID, &c.Type, &c.Name, &c.Version, &c.Arch, &c.Distro, &c.PURL, &c.CPE,
			&c.SourceName, &c.SourceVersion, &c.Vendor, &c.Origin, &c.Modularity, &c.Build); err != nil {
			return nil, mgErr("pending matches", err)
		}
		out = append(out, c)
	}
	return out, mgErr("pending matches", rows.Err())
}

type vuMetaRow struct {
	ID             string            `json:"vuln_id"`
	Aliases        []string          `json:"aliases"`
	Summary        string            `json:"summary"`
	Description    string            `json:"description"`
	CVSS           []store.CVSSScore `json:"cvss"`
	MaxScore       *float64          `json:"max_score"`
	Severity       string            `json:"severity"`
	CWEs           []string          `json:"cwes"`
	Refs           []string          `json:"refs"`
	KEVAdded       *string           `json:"kev_added"`
	KEV            *store.KEVEntry   `json:"kev"`
	EPSS           *float64          `json:"epss"`
	EPSSPercentile *float64          `json:"epss_percentile"`
	Published      *time.Time        `json:"published"`
	Modified       *time.Time        `json:"modified"`
}

type vuVulnRow struct {
	ComponentID  string               `json:"component_id"`
	VulnID       string               `json:"vuln_id"`
	Method       string               `json:"method"`
	Ecosystem    string               `json:"ecosystem"`
	FixState     string               `json:"fix_state"`
	FixedVersion string               `json:"fixed_version"`
	CPEMatch     string               `json:"cpe_match"`
	RangeSource  string               `json:"range_source"`
	Platforms    []string             `json:"platforms"`
	Advisories   []store.VulnAdvisory `json:"advisories"`
	Symbols      []store.GoImport     `json:"symbols"`
	Severity     string               `json:"severity"`
}

type vuMatchRow struct {
	ComponentID string `json:"component_id"`
	OSKey       string `json:"os_key"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
}

func vuStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// SaveMatches implements store.Vulns. Rows travel as one JSON document per
// table, expanded with jsonb_to_recordset.
func (d *DB) SaveMatches(ctx context.Context, b store.MatchBatch) error {
	metas := make([]vuMetaRow, 0, len(b.Vulns))
	for _, v := range b.Vulns {
		r := vuMetaRow{ID: v.ID, Aliases: vuStrings(v.Aliases), Summary: v.Summary, Description: v.Description,
			CVSS: v.CVSS, MaxScore: v.MaxScore, Severity: v.Severity, CWEs: vuStrings(v.CWEs), Refs: vuStrings(v.References),
			KEV: v.KEV, EPSS: v.EPSS, EPSSPercentile: v.EPSSPercentile, Published: v.Published, Modified: v.Modified}
		if r.CVSS == nil {
			r.CVSS = []store.CVSSScore{}
		}
		if v.KEV != nil && v.KEV.DateAdded != "" {
			r.KEVAdded = &v.KEV.DateAdded
		}
		metas = append(metas, r)
	}
	var vulns []vuVulnRow
	matches := make([]vuMatchRow, 0, len(b.Components))
	ids := make([]string, 0, len(b.Components))
	for _, c := range b.Components {
		ids = append(ids, c.ComponentID)
		matches = append(matches, vuMatchRow{ComponentID: c.ComponentID, OSKey: c.OSKey, Status: c.Status, Reason: c.Reason})
		for _, v := range c.Vulns {
			adv := v.Advisories
			if adv == nil {
				adv = []store.VulnAdvisory{}
			}
			vulns = append(vulns, vuVulnRow{ComponentID: c.ComponentID, VulnID: v.VulnID, Method: v.Method, Ecosystem: v.Ecosystem,
				FixState: v.FixState, FixedVersion: v.FixedVersion, CPEMatch: v.CPEMatch, RangeSource: v.RangeSource,
				Platforms: vuStrings(v.Platforms), Advisories: adv, Symbols: vuSymbols(v.Symbols), Severity: v.Severity})
		}
	}
	metaJSON, err := json.Marshal(metas)
	if err != nil {
		return fmt.Errorf("postgres: save matches: %w", err)
	}
	vulnJSON, err := json.Marshal(vulns)
	if err != nil {
		return fmt.Errorf("postgres: save matches: %w", err)
	}
	matchJSON, err := json.Marshal(matches)
	if err != nil {
		return fmt.Errorf("postgres: save matches: %w", err)
	}
	at := mgOrNow(b.At)

	return d.mgInTx(ctx, func(tx *DB) error {
		if len(metas) > 0 {
			if _, err := tx.q.Exec(ctx, `
				INSERT INTO vuln_meta (vuln_id, aliases, summary, description, cvss, max_score, severity, cwes, refs,
					kev_added, kev, epss, epss_percentile, published, modified, updated_at)
				SELECT x.vuln_id, x.aliases, x.summary, x.description, x.cvss, x.max_score, x.severity, x.cwes, x.refs,
					x.kev_added, x.kev, x.epss, x.epss_percentile, x.published, x.modified, $2
				FROM jsonb_to_recordset($1::text::jsonb) AS x(vuln_id text, aliases text[], summary text, description text,
					cvss jsonb, max_score real, severity text, cwes text[], refs text[], kev_added date, kev jsonb,
					epss real, epss_percentile real, published timestamptz, modified timestamptz)
				ON CONFLICT (vuln_id) DO UPDATE SET aliases = excluded.aliases, summary = excluded.summary,
					description = excluded.description, cvss = excluded.cvss, max_score = excluded.max_score,
					severity = excluded.severity, cwes = excluded.cwes, refs = excluded.refs, kev_added = excluded.kev_added,
					kev = excluded.kev, epss = excluded.epss, epss_percentile = excluded.epss_percentile,
					published = excluded.published, modified = excluded.modified, updated_at = excluded.updated_at`,
				string(metaJSON), at); err != nil {
				return mgErr("save vulnerability details", err)
			}
		}
		changed, err := tx.vuChangedComponents(ctx, b.Components)
		if err != nil {
			return err
		}
		if _, err := tx.q.Exec(ctx, `DELETE FROM component_vulns WHERE component_id = ANY($1::uuid[])`, ids); err != nil {
			return mgErr("save component vulnerabilities", err)
		}
		if len(vulns) > 0 {
			if _, err := tx.q.Exec(ctx, `
				INSERT INTO component_vulns (component_id, vuln_id, method, ecosystem, fix_state, fixed_version,
					cpe_match, range_source, platforms, advisories, symbols, severity)
				SELECT x.component_id, x.vuln_id, x.method, x.ecosystem, x.fix_state, x.fixed_version,
					x.cpe_match, x.range_source, x.platforms, x.advisories, x.symbols, x.severity
				FROM jsonb_to_recordset($1::text::jsonb) AS x(component_id uuid, vuln_id text, method text, ecosystem text,
					fix_state text, fixed_version text, cpe_match text, range_source text, platforms text[], advisories jsonb,
					symbols jsonb, severity text)
				ON CONFLICT DO NOTHING`,
				string(vulnJSON)); err != nil {
				return mgErr("save component vulnerabilities", err)
			}
		}
		_, err = tx.q.Exec(ctx, `
			INSERT INTO component_matches (component_id, feed_server_id, revision, rules_digest, os_key, status, reason, matched_at)
			SELECT x.component_id, $2, $3, $4, x.os_key, x.status, x.reason, $5
			FROM jsonb_to_recordset($1::text::jsonb) AS x(component_id uuid, os_key text, status text, reason text)
			ON CONFLICT (component_id) DO UPDATE SET feed_server_id = excluded.feed_server_id, revision = excluded.revision,
				rules_digest = excluded.rules_digest, os_key = excluded.os_key, status = excluded.status,
				reason = excluded.reason, matched_at = excluded.matched_at`,
			string(matchJSON), b.Epoch.ServerID, b.Epoch.Revision, b.Epoch.Rules, at)
		if err != nil {
			return mgErr("save component matches", err)
		}
		if err := tx.ntSave(ctx, b, ids, at); err != nil {
			return err
		}
		return tx.markVulnsChanged(ctx, changed)
	})
}

// vuChangedComponents returns the components of a batch whose
// vulnerabilities, or their vulnerable functions, differ from the stored
// ones.
func (d *DB) vuChangedComponents(ctx context.Context, comps []store.ComponentMatch) ([]string, error) {
	ids := make([]string, 0, len(comps))
	for _, c := range comps {
		ids = append(ids, c.ComponentID)
	}
	// sig is what a component's findings depend on: its vulnerabilities and
	// their functions, in one canonical form.
	sig := func(vulns map[string][]store.GoImport) string {
		keys := make([]string, 0, len(vulns))
		for k := range vulns {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		var sb strings.Builder
		for _, k := range keys {
			js, _ := json.Marshal(vuSymbols(vulns[k]))
			sb.WriteString(k)
			sb.WriteByte(0)
			sb.Write(js)
			sb.WriteByte('\n')
		}
		return sb.String()
	}
	old := map[string]map[string][]store.GoImport{}
	rows, err := d.q.Query(ctx, `
		SELECT component_id::text, vuln_id, symbols::text
		FROM component_vulns WHERE component_id = ANY($1::uuid[])`, ids)
	if err != nil {
		return nil, mgErr("compare component vulnerabilities", err)
	}
	for rows.Next() {
		var id, vuln, syms string
		if err := rows.Scan(&id, &vuln, &syms); err != nil {
			rows.Close()
			return nil, mgErr("compare component vulnerabilities", err)
		}
		var imps []store.GoImport
		if err := json.Unmarshal([]byte(syms), &imps); err != nil {
			rows.Close()
			return nil, fmt.Errorf("postgres: compare component vulnerabilities: symbols: %w", err)
		}
		if old[id] == nil {
			old[id] = map[string][]store.GoImport{}
		}
		// The same vulnerability by two methods: package matches carry
		// the functions.
		if len(imps) > 0 || old[id][vuln] == nil {
			old[id][vuln] = imps
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, mgErr("compare component vulnerabilities", err)
	}
	var changed []string
	for _, c := range comps {
		now := map[string][]store.GoImport{}
		for _, v := range c.Vulns {
			if len(v.Symbols) > 0 || now[v.VulnID] == nil {
				now[v.VulnID] = v.Symbols
			}
		}
		if sig(now) != sig(old[c.ComponentID]) {
			changed = append(changed, c.ComponentID)
		}
	}
	return changed, nil
}

// vuSymbols returns imports in a canonical form: sorted, never nil.
func vuSymbols(in []store.GoImport) []store.GoImport {
	out := make([]store.GoImport, 0, len(in))
	for _, g := range in {
		g.Symbols = slices.Sorted(slices.Values(g.Symbols))
		g.GOOS = slices.Sorted(slices.Values(g.GOOS))
		g.GOARCH = slices.Sorted(slices.Values(g.GOARCH))
		if g.Symbols == nil {
			g.Symbols = []string{}
		}
		out = append(out, g)
	}
	slices.SortFunc(out, func(a, b store.GoImport) int { return strings.Compare(a.Path, b.Path) })
	return out
}

// ResetMatches implements store.Vulns.
func (d *DB) ResetMatches(ctx context.Context, serverID string) error {
	_, err := d.q.Exec(ctx, `DELETE FROM component_matches WHERE feed_server_id = $1`, serverID)
	return mgErr("reset matches", err)
}

// CountMatches implements store.Vulns. It counts the components visible in
// the scope of ctx.
func (d *DB) CountMatches(ctx context.Context, e store.MatchEpoch) (store.MatchCounts, error) {
	var c store.MatchCounts
	q, sc, err := scoped(ctx, "count matches", e.ServerID, e.Revision, e.Rules)
	if err != nil {
		return c, err
	}
	err = d.q.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE m.status = 'checked'),
			count(*) FILTER (WHERE m.status = 'unsupported'),
			count(*) FILTER (WHERE m.status = 'invalid'),
			count(*) FILTER (WHERE m.component_id IS NULL),
			count(*) FILTER (WHERE m.status = 'checked' AND EXISTS (SELECT 1 FROM component_vulns v WHERE v.component_id = c.id))
		FROM components c
		LEFT JOIN component_matches m ON `+vuMatchedIn+`
		WHERE `+vuLive+` AND `+sc.component("c.id"), q.args...).Scan(&c.Checked, &c.Unsupported, &c.Invalid, &c.Pending, &c.Vulnerable)
	return c, mgErr("count matches", err)
}

// GetComponentMatch implements store.Vulns.
func (d *DB) GetComponentMatch(ctx context.Context, componentID string) (store.ComponentMatch, store.MatchEpoch, time.Time, error) {
	m := store.ComponentMatch{ComponentID: componentID}
	var e store.MatchEpoch
	var at time.Time
	err := d.q.QueryRow(ctx, `
		SELECT feed_server_id, revision, rules_digest, os_key, status, reason, matched_at
		FROM component_matches WHERE component_id = $1`, componentID).
		Scan(&e.ServerID, &e.Revision, &e.Rules, &m.OSKey, &m.Status, &m.Reason, &at)
	if err != nil {
		return store.ComponentMatch{}, store.MatchEpoch{}, time.Time{}, mgErr("get component match", err)
	}
	return m, e, at.UTC(), nil
}

const vuMetaCols = `m.vuln_id, m.aliases, m.summary, m.description, m.cvss::text, m.max_score, m.severity, m.cwes, m.refs,
	m.kev::text, m.epss, m.epss_percentile, m.published, m.modified`

// vuScanMeta scans vuMetaCols; the destinations come first in dest.
func vuScanMeta(r mgRow, v *store.VulnMeta, extra ...any) error {
	var cvss []byte
	var kev *string
	var maxScore, epss, pct *float32
	dest := append([]any{&v.ID, &v.Aliases, &v.Summary, &v.Description, &cvss, &maxScore, &v.Severity, &v.CWEs, &v.References,
		&kev, &epss, &pct, &v.Published, &v.Modified}, extra...)
	if err := r.Scan(dest...); err != nil {
		return err
	}
	if err := json.Unmarshal(cvss, &v.CVSS); err != nil {
		return fmt.Errorf("cvss: %w", err)
	}
	if kev != nil {
		v.KEV = &store.KEVEntry{}
		if err := json.Unmarshal([]byte(*kev), v.KEV); err != nil {
			return fmt.Errorf("kev: %w", err)
		}
	}
	v.MaxScore, v.EPSS, v.EPSSPercentile = vuF64(maxScore), vuF64(epss), vuF64(pct)
	v.Published, v.Modified = mgUTCPtr(v.Published), mgUTCPtr(v.Modified)
	return nil
}

// vuF64 widens a real, rounding away float32 noise (7.5 stays 7.5, 0.97354
// does not become 0.9735400080680847).
func vuF64(f *float32) *float64 {
	if f == nil {
		return nil
	}
	v, _ := json.Number(fmt.Sprintf("%g", *f)).Float64()
	return &v
}

// ListComponentVulns implements store.Vulns.
func (d *DB) ListComponentVulns(ctx context.Context, componentID string) ([]store.ComponentVulnRow, error) {
	rows, err := d.q.Query(ctx, `
		SELECT `+vuMetaCols+`, v.method, v.ecosystem, v.fix_state, v.fixed_version, v.cpe_match, v.range_source,
			v.platforms, v.advisories::text, v.severity
		FROM component_vulns v JOIN vuln_meta m ON m.vuln_id = v.vuln_id
		WHERE v.component_id = $1
		ORDER BY m.kev_added IS NULL, m.max_score DESC NULLS LAST, m.epss DESC NULLS LAST, v.vuln_id, v.method`,
		componentID)
	if err != nil {
		return nil, mgErr("list component vulnerabilities", err)
	}
	defer rows.Close()
	out := []store.ComponentVulnRow{}
	for rows.Next() {
		var r store.ComponentVulnRow
		var adv []byte
		if err := vuScanMeta(rows, &r.Meta, &r.Method, &r.Ecosystem, &r.FixState, &r.FixedVersion, &r.CPEMatch,
			&r.RangeSource, &r.Platforms, &adv, &r.Severity); err != nil {
			return nil, mgErr("list component vulnerabilities", err)
		}
		if err := json.Unmarshal(adv, &r.Advisories); err != nil {
			return nil, fmt.Errorf("postgres: list component vulnerabilities: advisories: %w", err)
		}
		r.VulnID = r.Meta.ID
		out = append(out, r)
	}
	return out, mgErr("list component vulnerabilities", rows.Err())
}
