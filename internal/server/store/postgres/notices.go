// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

var _ store.Notices = (*DB)(nil)

type ntNoticeRow struct {
	ID            string                 `json:"notice_id"`
	Source        string                 `json:"source"`
	Title         string                 `json:"title"`
	URL           string                 `json:"url"`
	Published     *time.Time             `json:"published"`
	Summary       string                 `json:"summary"`
	CVEIDs        []string               `json:"cve_ids"`
	RelatedCVEIDs []string               `json:"related_cve_ids"`
	AdvisoryIDs   []string               `json:"advisory_ids"`
	Software      []store.NoticeSoftware `json:"software"`
	Modified      *time.Time             `json:"modified"`
}

type ntLinkRow struct {
	ComponentID string `json:"component_id"`
	NoticeID    string `json:"notice_id"`
}

// ntSave stores the notices of a batch and replaces the notice links of
// its components (ids). A link that stays keeps its linked_at, so that a
// re-match does not make a read notice unread.
func (d *DB) ntSave(ctx context.Context, b store.MatchBatch, ids []string, at time.Time) error {
	if len(b.Notices) > 0 {
		rows := make([]ntNoticeRow, 0, len(b.Notices))
		for _, n := range b.Notices {
			sw := n.Software
			if sw == nil {
				sw = []store.NoticeSoftware{}
			}
			rows = append(rows, ntNoticeRow{ID: n.ID, Source: n.Source, Title: n.Title, URL: n.URL, Published: n.Published,
				Summary: n.Summary, CVEIDs: vuStrings(n.CVEIDs), RelatedCVEIDs: vuStrings(n.RelatedCVEIDs),
				AdvisoryIDs: vuStrings(n.AdvisoryIDs), Software: sw, Modified: n.Modified})
		}
		js, err := json.Marshal(rows)
		if err != nil {
			return fmt.Errorf("postgres: save notices: %w", err)
		}
		if _, err := d.q.Exec(ctx, `
			INSERT INTO notices (notice_id, source, title, url, published, summary, cve_ids, related_cve_ids,
				advisory_ids, software, modified, updated_at)
			SELECT x.notice_id, x.source, x.title, x.url, x.published, x.summary, x.cve_ids, x.related_cve_ids,
				x.advisory_ids, x.software, x.modified, $2
			FROM jsonb_to_recordset($1::text::jsonb) AS x(notice_id text, source text, title text, url text,
				published timestamptz, summary text, cve_ids text[], related_cve_ids text[], advisory_ids text[],
				software jsonb, modified timestamptz)
			ON CONFLICT (notice_id) DO UPDATE SET source = excluded.source, title = excluded.title, url = excluded.url,
				published = excluded.published, summary = excluded.summary, cve_ids = excluded.cve_ids,
				related_cve_ids = excluded.related_cve_ids, advisory_ids = excluded.advisory_ids,
				software = excluded.software, modified = excluded.modified, updated_at = excluded.updated_at`,
			string(js), at); err != nil {
			return mgErr("save notices", err)
		}
	}
	links := []ntLinkRow{}
	for _, c := range b.Components {
		for _, n := range c.Notices {
			links = append(links, ntLinkRow{ComponentID: c.ComponentID, NoticeID: n})
		}
	}
	js, err := json.Marshal(links)
	if err != nil {
		return fmt.Errorf("postgres: save component notices: %w", err)
	}
	if _, err := d.q.Exec(ctx, `
		DELETE FROM component_notices cn
		WHERE cn.component_id = ANY($1::uuid[])
			AND (cn.component_id, cn.notice_id) NOT IN (
				SELECT x.component_id, x.notice_id FROM jsonb_to_recordset($2::text::jsonb) AS x(component_id uuid, notice_id text))`,
		ids, string(js)); err != nil {
		return mgErr("save component notices", err)
	}
	if len(links) == 0 {
		return nil
	}
	_, err = d.q.Exec(ctx, `
		INSERT INTO component_notices (component_id, notice_id, linked_at)
		SELECT DISTINCT x.component_id, x.notice_id, $2::timestamptz
		FROM jsonb_to_recordset($1::text::jsonb) AS x(component_id uuid, notice_id text)
		ON CONFLICT DO NOTHING`, string(js), at)
	return mgErr("save component notices", err)
}

// ntLive joins the current installations ac on current assets a to the
// notice links cn.
const ntLive = `component_notices cn
	JOIN asset_components ac ON ac.component_id = cn.component_id AND ac.removed_at IS NULL
	JOIN assets a ON a.id = ac.asset_id AND a.gone_at IS NULL`

// ntSince is when the installation ac started matching the notice.
const ntSince = `greatest(ac.first_seen, cn.linked_at)`

// ntSummary aggregates, per notice, the current assets in the scope that
// match it: one row per asset with the time it started matching, then the
// read marks of the asset scopes.
func ntSummary(q *ivQuery, sc sqlScope, f store.NoticeFilter) string {
	cond := sc.col("a.scope_id")
	if f.ID != "" {
		cond += " AND cn.notice_id = " + q.arg(f.ID)
	}
	if f.AssetID != "" {
		cond += " AND a.id = " + q.arg(f.AssetID)
	}
	return `SELECT m.notice_id, count(*) AS assets,
			count(*) FILTER (WHERE r.read_at IS NULL OR m.since > r.read_at) AS new_assets,
			min(m.since) AS first_matched, max(m.since) AS last_matched, max(r.read_at) AS read_at,
			(array_agg(r.read_by ORDER BY r.read_at DESC) FILTER (WHERE r.read_at IS NOT NULL))[1] AS read_by
		FROM (SELECT cn.notice_id, a.id AS asset_id, a.scope_id, min(` + ntSince + `) AS since
			FROM ` + ntLive + `
			WHERE ` + cond + `
			GROUP BY cn.notice_id, a.id, a.scope_id) m
		LEFT JOIN notice_reads r ON r.notice_id = m.notice_id AND r.scope_id = m.scope_id
		GROUP BY m.notice_id`
}

const ntCols = `n.notice_id, n.source, n.title, n.url, n.published, n.summary, n.cve_ids, n.related_cve_ids,
	n.advisory_ids, n.software::text, n.modified, s.assets, s.new_assets, s.first_matched, s.last_matched,
	s.read_at, s.read_by`

func ntScan(r mgRow, n *store.NoticeRow) error {
	var sw string
	var by *string
	if err := r.Scan(&n.ID, &n.Source, &n.Title, &n.URL, &n.Published, &n.Summary, &n.CVEIDs, &n.RelatedCVEIDs,
		&n.AdvisoryIDs, &sw, &n.Modified, &n.Assets, &n.NewAssets, &n.FirstMatched, &n.LastMatched,
		&n.ReadAt, &by); err != nil {
		return err
	}
	if err := json.Unmarshal([]byte(sw), &n.Software); err != nil {
		return fmt.Errorf("software: %w", err)
	}
	if by != nil {
		n.ReadBy = *by
	}
	n.Published, n.Modified, n.ReadAt = mgUTCPtr(n.Published), mgUTCPtr(n.Modified), mgUTCPtr(n.ReadAt)
	n.FirstMatched, n.LastMatched = n.FirstMatched.UTC(), n.LastMatched.UTC()
	return nil
}

// ListNotices implements store.Notices.
func (d *DB) ListNotices(ctx context.Context, f store.NoticeFilter, p store.Page) ([]store.NoticeRow, int, error) {
	const op = "list notices"
	q, sc, err := scoped(ctx, op)
	if err != nil {
		return nil, 0, err
	}
	if f.AssetID != "" && !ivValidID(f.AssetID) {
		return nil, 0, nil
	}
	from := `FROM (` + ntSummary(q, sc, f) + `) s JOIN notices n ON n.notice_id = s.notice_id`
	if !f.IncludeRead {
		q.and("s.new_assets > 0")
	}
	if f.Source != "" {
		q.where("n.source = %s", f.Source)
	}
	if f.Q != "" {
		q.where(`(n.notice_id ILIKE %[1]s OR n.title ILIKE %[1]s OR n.summary ILIKE %[1]s
			OR array_to_string(n.cve_ids || n.related_cve_ids || n.advisory_ids, ' ') ILIKE %[1]s
			OR EXISTS (SELECT 1 FROM jsonb_array_elements(n.software) sw
				WHERE sw->>'vendor' ILIKE %[1]s OR sw->>'product' ILIKE %[1]s))`, ivLike(f.Q))
	}
	from += q.whereSQL()
	order := ` ORDER BY (s.new_assets > 0) DESC, n.published DESC NULLS LAST, n.notice_id`
	var out []store.NoticeRow
	total, err := ivPage(ctx, d, op, q, ntCols, from, order, p, func(rows pgx.Rows) error {
		var n store.NoticeRow
		if err := ntScan(rows, &n); err != nil {
			return err
		}
		out = append(out, n)
		return nil
	})
	return out, total, err
}

// GetNotice implements store.Notices.
func (d *DB) GetNotice(ctx context.Context, id string) (store.NoticeRow, error) {
	const op = "get notice"
	q, sc, err := scoped(ctx, op)
	if err != nil {
		return store.NoticeRow{}, err
	}
	var n store.NoticeRow
	err = ntScan(d.q.QueryRow(ctx, `SELECT `+ntCols+`
		FROM (`+ntSummary(q, sc, store.NoticeFilter{ID: id})+`) s JOIN notices n ON n.notice_id = s.notice_id`,
		q.args...), &n)
	return n, ivErr(op, err)
}

// ListNoticeMatches implements store.Notices.
func (d *DB) ListNoticeMatches(ctx context.Context, f store.NoticeMatchFilter) ([]store.NoticeMatch, error) {
	const op = "list notice matches"
	q, sc, err := scoped(ctx, op)
	if err != nil {
		return nil, err
	}
	if f.NoticeID == "" && f.AssetID == "" {
		return nil, ivInvalid(op, "a notice or an asset is required")
	}
	if f.AssetID != "" && !ivValidID(f.AssetID) {
		return []store.NoticeMatch{}, nil
	}
	q.and(sc.col("a.scope_id"))
	if f.NoticeID != "" {
		q.where("cn.notice_id = %s", f.NoticeID)
	}
	if f.AssetID != "" {
		q.where("a.id = %s", f.AssetID)
	}
	rows, err := d.q.Query(ctx, `
		SELECT cn.notice_id, a.id, a.name, a.kind, ac.container, c.id, c.type, c.name, c.version, c.purl, c.cpe,
			ac.locations, `+ntSince+`,
			(r.read_at IS NULL OR min(`+ntSince+`) OVER (PARTITION BY cn.notice_id, a.id) > r.read_at)
		FROM `+ntLive+`
		JOIN components c ON c.id = cn.component_id
		LEFT JOIN notice_reads r ON r.notice_id = cn.notice_id AND r.scope_id = a.scope_id`+q.whereSQL()+`
		ORDER BY a.name, a.id, ac.container, c.name, c.version, cn.notice_id`, q.args...)
	if err != nil {
		return nil, ivErr(op, err)
	}
	defer rows.Close()
	out := []store.NoticeMatch{}
	for rows.Next() {
		var m store.NoticeMatch
		if err := rows.Scan(&m.NoticeID, &m.AssetID, &m.AssetName, &m.AssetKind, &m.Container, &m.Component.ID,
			&m.Component.Type, &m.Component.Name, &m.Component.Version, &m.Component.PURL, &m.Component.CPE,
			&m.Locations, &m.FirstSeen, &m.New); err != nil {
			return nil, ivErr(op, err)
		}
		m.FirstSeen = m.FirstSeen.UTC()
		out = append(out, m)
	}
	return out, ivErr(op, rows.Err())
}

// CountNotices implements store.Notices.
func (d *DB) CountNotices(ctx context.Context) (store.NoticeCounts, error) {
	const op = "count notices"
	q, sc, err := scoped(ctx, op)
	if err != nil {
		return store.NoticeCounts{}, err
	}
	var c store.NoticeCounts
	err = d.q.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE s.new_assets > 0)
		FROM (`+ntSummary(q, sc, store.NoticeFilter{})+`) s`, q.args...).Scan(&c.Total, &c.Unread)
	return c, ivErr(op, err)
}

// MarkNoticesRead implements store.Notices.
func (d *DB) MarkNoticesRead(ctx context.Context, ids []string, by string, at time.Time) (int, error) {
	const op = "mark notices read"
	q, sc, err := scoped(ctx, op, ivStrings(ids), ivAt(at), by)
	if err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	return d.ntCount(ctx, op, `
		INSERT INTO notice_reads (notice_id, scope_id, read_at, read_by)
		SELECT DISTINCT cn.notice_id, a.scope_id, $2::timestamptz, $3::text
		FROM `+ntLive+`
		WHERE cn.notice_id = ANY($1::text[]) AND `+sc.col("a.scope_id")+`
		ON CONFLICT (notice_id, scope_id) DO UPDATE SET read_at = excluded.read_at, read_by = excluded.read_by
		RETURNING notice_id`, q.args)
}

// MarkNoticesUnread implements store.Notices.
func (d *DB) MarkNoticesUnread(ctx context.Context, ids []string) (int, error) {
	const op = "mark notices unread"
	q, sc, err := scoped(ctx, op, ivStrings(ids))
	if err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	return d.ntCount(ctx, op, `
		DELETE FROM notice_reads r WHERE r.notice_id = ANY($1::text[]) AND `+sc.col("r.scope_id")+`
		RETURNING r.notice_id`, q.args)
}

// ntCount runs a statement that returns notice ids and counts the distinct
// ones.
func (d *DB) ntCount(ctx context.Context, op, sql string, args []any) (int, error) {
	rows, err := d.q.Query(ctx, sql, args...)
	if err != nil {
		return 0, ivErr(op, err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return 0, ivErr(op, err)
		}
		seen[id] = true
	}
	return len(seen), ivErr(op, rows.Err())
}
