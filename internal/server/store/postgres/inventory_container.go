// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"sort"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

type ivContainerRow struct {
	AssetID        string     `json:"asset_id"`
	Name           string     `json:"name"`
	RuntimeID      string     `json:"runtime_id"`
	ImageRef       string     `json:"image_ref"`
	ImageDigest    string     `json:"image_digest"`
	Runtime        string     `json:"runtime"`
	Instances      int        `json:"instances"`
	Coverage       string     `json:"coverage"`
	CoverageReason string     `json:"coverage_reason"`
	StartedAt      *time.Time `json:"started_at"`
}

// ReplaceContainers implements store.ContainerIngest.
func (d *DB) ReplaceContainers(ctx context.Context, assetID string, cs []store.ContainerObservation, opts store.ReplaceOptions) error {
	const op = "replace containers"
	byName := map[string]ivContainerRow{}
	for _, c := range cs {
		if c.Name == "" {
			return ivInvalid(op, "container without name")
		}
		byName[c.Name] = ivContainerRow{
			AssetID: assetID, Name: c.Name, RuntimeID: c.RuntimeID, ImageRef: c.ImageRef,
			ImageDigest: c.ImageDigest, Runtime: c.Runtime, Instances: c.Instances,
			Coverage: string(c.Coverage), CoverageReason: c.CoverageReason, StartedAt: ivTimeOrNil(c.StartedAt),
		}
	}
	rows := make([]ivContainerRow, 0, len(byName))
	for _, r := range byName {
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return d.ivAtomic(ctx, func(d *DB) error {
		if err := d.ivLockAsset(ctx, op, assetID); err != nil {
			return err
		}
		return ivErr(op, d.ivReplaceContainers(ctx, []string{assetID}, rows, ivAt(opts.At), opts.KeepMissing))
	})
}

// ivReplaceContainers makes rows the containers of the given assets. The
// caller holds the asset locks.
func (d *DB) ivReplaceContainers(ctx context.Context, assetIDs []string, rows []ivContainerRow, at time.Time, keepMissing bool) error {
	js, err := ivJSON(rows)
	if err != nil {
		return err
	}
	const obs = `jsonb_to_recordset($1::jsonb) AS o(asset_id uuid, name text, runtime_id text, image_ref text,
		image_digest text, runtime text, instances integer, coverage text, coverage_reason text,
		started_at timestamptz)`
	if _, err := d.q.Exec(ctx, `
		UPDATE asset_containers t SET
			runtime_id = o.runtime_id,
			image_ref = o.image_ref,
			previous_digest = CASE WHEN t.image_digest <> o.image_digest THEN t.image_digest ELSE t.previous_digest END,
			digest_since = CASE WHEN t.image_digest <> o.image_digest THEN $2 ELSE t.digest_since END,
			image_digest = o.image_digest,
			runtime = o.runtime,
			instances = o.instances,
			coverage = CASE WHEN o.coverage <> '' THEN o.coverage
				WHEN t.image_digest <> o.image_digest THEN 'inventory_only' ELSE t.coverage END,
			coverage_reason = CASE WHEN o.coverage <> '' THEN o.coverage_reason
				WHEN t.image_digest <> o.image_digest THEN '' ELSE t.coverage_reason END,
			started_at = COALESCE(o.started_at, t.started_at),
			last_seen = GREATEST(t.last_seen, $2),
			gone_at = NULL
		FROM `+obs+`
		WHERE t.asset_id = o.asset_id AND t.name = o.name`, js, at); err != nil {
		return err
	}
	if _, err := d.q.Exec(ctx, `
		INSERT INTO asset_containers (asset_id, name, runtime_id, image_ref, image_digest, digest_since,
			runtime, instances, coverage, coverage_reason, started_at, first_seen, last_seen)
		SELECT o.asset_id, o.name, o.runtime_id, o.image_ref, o.image_digest, $2, o.runtime, o.instances,
			COALESCE(NULLIF(o.coverage, ''), 'inventory_only'),
			CASE WHEN o.coverage <> '' THEN o.coverage_reason ELSE '' END, o.started_at, $2, $2
		FROM `+obs+`
		WHERE NOT EXISTS (SELECT 1 FROM asset_containers t WHERE t.asset_id = o.asset_id AND t.name = o.name)`,
		js, at); err != nil {
		return err
	}
	if !keepMissing {
		if _, err := d.q.Exec(ctx, `
			UPDATE asset_containers t SET gone_at = $3, instances = 0
			WHERE t.asset_id = ANY($2::uuid[]) AND t.gone_at IS NULL
			  AND NOT EXISTS (SELECT 1 FROM `+obs+` WHERE o.asset_id = t.asset_id AND o.name = t.name)`,
			js, assetIDs, at); err != nil {
			return err
		}
	}
	return d.ivEnsureImages(ctx, js, at)
}

// ivEnsureImages creates an images row for every digest in the container
// rows js. Tags are recorded by UpsertImages for the source of the
// observation.
func (d *DB) ivEnsureImages(ctx context.Context, js string, at time.Time) error {
	_, err := d.q.Exec(ctx, `
		INSERT INTO images (digest, first_seen, last_seen)
		SELECT DISTINCT x.image_digest, $2::timestamptz, $2::timestamptz
		FROM jsonb_to_recordset($1::jsonb) AS x(image_digest text)
		WHERE x.image_digest <> ''
		ORDER BY x.image_digest
		ON CONFLICT (digest) DO UPDATE SET
			last_seen = GREATEST(images.last_seen, EXCLUDED.last_seen)`, js, at)
	return err
}

// SetContainerCoverage implements store.ContainerIngest.
func (d *DB) SetContainerCoverage(ctx context.Context, assetID, name string, coverage store.Coverage, reason string) error {
	const op = "set container coverage"
	if !ivValidID(assetID) {
		return ivNotFound(op)
	}
	tag, err := d.q.Exec(ctx, `UPDATE asset_containers SET coverage = $3, coverage_reason = $4
		WHERE asset_id = $1 AND name = $2`, assetID, name, string(coverage), reason)
	if err != nil {
		return ivErr(op, err)
	}
	if tag.RowsAffected() == 0 {
		return ivNotFound(op)
	}
	return nil
}

// UpsertImages implements store.ContainerIngest.
func (d *DB) UpsertImages(ctx context.Context, src store.ImageSource, images []store.ImageObservation, opts store.ReplaceOptions) error {
	const op = "upsert images"
	type row struct {
		Digest   string   `json:"digest"`
		RepoTags []string `json:"repo_tags"`
		OS       string   `json:"os"`
		Arch     string   `json:"arch"`
		Size     int64    `json:"size"`
	}
	// The source row lock orders replaces of the same source.
	var lock func(d *DB) error
	switch src.Kind {
	case store.ImageSourceAsset:
		lock = func(d *DB) error { return d.ivLockAsset(ctx, op, src.ID) }
	case store.ImageSourceCluster:
		lock = func(d *DB) error { return d.ivLockCluster(ctx, op, src.ID) }
	default:
		return ivInvalid(op, "unknown image source kind "+strconv.Quote(string(src.Kind)))
	}
	if !ivValidID(src.ID) {
		return ivNotFound(op)
	}
	byDigest := map[string]*row{}
	for _, im := range images {
		if im.Digest == "" {
			continue
		}
		r, ok := byDigest[im.Digest]
		if !ok {
			r = &row{Digest: im.Digest}
			byDigest[im.Digest] = r
		}
		for _, t := range im.RepoTags {
			if t != "" {
				r.RepoTags = append(r.RepoTags, t)
			}
		}
		if im.OS != "" {
			r.OS = im.OS
		}
		if im.Arch != "" {
			r.Arch = im.Arch
		}
		if im.Size > 0 {
			r.Size = im.Size
		}
	}
	rows := make([]row, 0, len(byDigest))
	for _, r := range byDigest {
		r.RepoTags = ivSortedUnique(r.RepoTags)
		rows = append(rows, *r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Digest < rows[j].Digest })
	js, err := ivJSON(rows)
	if err != nil {
		return err
	}
	at := ivAt(opts.At)
	const obs = `jsonb_to_recordset($1::jsonb) AS x(digest text, repo_tags text[], os text, arch text, size bigint)`
	return d.ivAtomic(ctx, func(d *DB) error {
		if err := lock(d); err != nil {
			return err
		}
		if _, err := d.q.Exec(ctx, `
			INSERT INTO images (digest, os, arch, size, first_seen, last_seen)
			SELECT x.digest, x.os, x.arch, x.size, $2, $2
			FROM `+obs+`
			ORDER BY x.digest
			ON CONFLICT (digest) DO UPDATE SET
				os = COALESCE(NULLIF(EXCLUDED.os, ''), images.os),
				arch = COALESCE(NULLIF(EXCLUDED.arch, ''), images.arch),
				size = CASE WHEN EXCLUDED.size > 0 THEN EXCLUDED.size ELSE images.size END,
				first_seen = LEAST(images.first_seen, EXCLUDED.first_seen),
				last_seen = GREATEST(images.last_seen, EXCLUDED.last_seen)`, js, at); err != nil {
			return ivErr(op, err)
		}
		if _, err := d.q.Exec(ctx, `
			INSERT INTO image_tags (digest, tag, source_kind, source_id, first_seen, last_seen)
			SELECT x.digest, t.tag, $2, $3, $4, $4
			FROM `+obs+` CROSS JOIN LATERAL unnest(x.repo_tags) AS t(tag)
			ORDER BY x.digest, t.tag
			ON CONFLICT (digest, tag, source_kind, source_id) DO UPDATE SET
				last_seen = GREATEST(image_tags.last_seen, EXCLUDED.last_seen),
				gone_at = NULL`, js, string(src.Kind), src.ID, at); err != nil {
			return ivErr(op, err)
		}
		if opts.KeepMissing {
			return nil
		}
		_, err := d.q.Exec(ctx, `
			WITH seen AS MATERIALIZED (
				SELECT x.digest, t.tag FROM `+obs+` CROSS JOIN LATERAL unnest(x.repo_tags) AS t(tag))
			UPDATE image_tags it SET gone_at = $4
			WHERE it.source_kind = $2 AND it.source_id = $3 AND it.gone_at IS NULL
			  AND NOT EXISTS (SELECT 1 FROM seen s WHERE s.digest = it.digest AND s.tag = it.tag)`,
			js, string(src.Kind), src.ID, at)
		return ivErr(op, err)
	})
}

const ivContainerCols = `ct.name, ct.runtime_id, ct.image_ref, ct.image_digest, ct.runtime, ct.instances,
	ct.coverage, ct.coverage_reason, ct.started_at, ct.previous_digest, ct.digest_since,
	ct.first_seen, ct.last_seen, ct.gone_at`

func ivContainerDest(c *store.Container) []any {
	return []any{&c.Name, &c.RuntimeID, &c.ImageRef, &c.ImageDigest, &c.Runtime, &c.Instances,
		&c.Coverage, &c.CoverageReason, &c.StartedAt, &c.PreviousDigest, &c.DigestSince,
		&c.FirstSeen, &c.LastSeen, &c.GoneAt}
}

func ivFixContainer(c *store.Container) {
	c.StartedAt = ivUTC(c.StartedAt)
	c.DigestSince = c.DigestSince.UTC()
	c.FirstSeen = c.FirstSeen.UTC()
	c.LastSeen = c.LastSeen.UTC()
	c.GoneAt = ivUTC(c.GoneAt)
}

// ivContainers returns the containers matching cond (alias ct), current ones
// first.
func (d *DB) ivContainers(ctx context.Context, cond string, args ...any) ([]store.Container, error) {
	rows, err := d.q.Query(ctx, `SELECT `+ivContainerCols+` FROM asset_containers ct WHERE `+cond+`
		ORDER BY ct.gone_at IS NOT NULL, ct.name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Container
	for rows.Next() {
		var c store.Container
		if err := rows.Scan(ivContainerDest(&c)...); err != nil {
			return nil, err
		}
		ivFixContainer(&c)
		out = append(out, c)
	}
	return out, rows.Err()
}

// ivTagLive is true for an image_tags row (alias it) that a live source
// lists in its latest observation.
const ivTagLive = `(it.gone_at IS NULL AND (
		(it.source_kind = 'asset' AND EXISTS (SELECT 1 FROM assets a WHERE a.id = it.source_id AND a.gone_at IS NULL))
		OR (it.source_kind = 'cluster' AND EXISTS (SELECT 1 FROM k8s_clusters k WHERE k.id = it.source_id))))`

// ivImageFrom adds usage by current containers and the current and previous
// tags to the images rows.
const ivImageFrom = `FROM (SELECT i.*, COALESCE(u.assets, 0) AS assets, COALESCE(u.containers, 0) AS containers,
		COALESCE(u.instances, 0) AS instances, COALESCE(tg.tags, '{}') AS tags,
		COALESCE(tg.prev_tags, '{}') AS prev_tags, COALESCE(tg.prev_seen, '{}') AS prev_seen
		FROM images i LEFT JOIN (
			SELECT ct.image_digest, count(DISTINCT ct.asset_id) AS assets, count(*) AS containers,
				sum(ct.instances) AS instances
			FROM asset_containers ct JOIN assets a ON a.id = ct.asset_id AND a.gone_at IS NULL
			WHERE ct.gone_at IS NULL AND ct.image_digest <> ''
			GROUP BY ct.image_digest) u ON u.image_digest = i.digest
		LEFT JOIN LATERAL (
			SELECT array_agg(s.tag ORDER BY s.tag) FILTER (WHERE s.live) AS tags,
				array_agg(s.tag ORDER BY s.last_seen DESC, s.tag) FILTER (WHERE NOT s.live) AS prev_tags,
				array_agg(s.last_seen ORDER BY s.last_seen DESC, s.tag) FILTER (WHERE NOT s.live) AS prev_seen
			FROM (SELECT it.tag, bool_or(` + ivTagLive + `) AS live, max(it.last_seen) AS last_seen
				FROM image_tags it WHERE it.digest = i.digest GROUP BY it.tag) s) tg ON true) i`

const ivImageCols = `i.digest, i.tags, i.prev_tags, i.prev_seen, i.os, i.arch, i.size, i.first_seen, i.last_seen,
	i.content_collected_at, i.content_coverage, i.assets, i.containers, i.instances,
	(SELECT count(*) FROM image_components ic WHERE ic.digest = i.digest)`

type ivImageScan struct {
	row      store.ImageRow
	prevTags []string
	prevSeen []time.Time
}

func ivImageDest(r *ivImageScan) []any {
	return []any{&r.row.Digest, &r.row.Tags, &r.prevTags, &r.prevSeen, &r.row.OS, &r.row.Arch, &r.row.Size,
		&r.row.FirstSeen, &r.row.LastSeen, &r.row.ContentCollectedAt, &r.row.ContentCoverage,
		&r.row.Assets, &r.row.Containers, &r.row.Instances, &r.row.Components}
}

func ivFixImage(s *ivImageScan) store.ImageRow {
	r := s.row
	r.FirstSeen = r.FirstSeen.UTC()
	r.LastSeen = r.LastSeen.UTC()
	r.ContentCollectedAt = ivUTC(r.ContentCollectedAt)
	r.Tags = ivStrings(r.Tags)
	r.PreviousTags = make([]store.PreviousTag, 0, len(s.prevTags))
	for i, t := range s.prevTags {
		p := store.PreviousTag{Tag: t}
		if i < len(s.prevSeen) {
			p.LastSeen = s.prevSeen[i].UTC()
		}
		r.PreviousTags = append(r.PreviousTags, p)
	}
	return r
}

// ListImages implements store.InventoryQuery.
func (d *DB) ListImages(ctx context.Context, f store.ImageFilter, p store.Page) ([]store.ImageRow, int, error) {
	const op = "list images"
	order, err := ivOrder(op, f.Sort, "tag", map[string]string{
		"tag":        "COALESCE(i.tags[1], i.prev_tags[1], '')",
		"digest":     "i.digest",
		"os":         "i.os",
		"arch":       "i.arch",
		"size":       "i.size",
		"assets":     "i.assets",
		"containers": "i.containers",
		"instances":  "i.instances",
		"first_seen": "i.first_seen",
	}, "i.digest")
	if err != nil {
		return nil, 0, err
	}
	q := &ivQuery{}
	if f.InUseOnly {
		q.where("i.containers > 0")
	}
	if f.ContentKnown != nil {
		if *f.ContentKnown {
			q.where("i.content_collected_at IS NOT NULL")
		} else {
			q.where("i.content_collected_at IS NULL")
		}
	}
	if f.Q != "" {
		q.where("(i.digest ILIKE %[1]s OR EXISTS (SELECT 1 FROM image_tags it WHERE it.digest = i.digest AND it.tag ILIKE %[1]s))", ivLike(f.Q))
	}
	var out []store.ImageRow
	total, err := ivPage(ctx, d, op, q, ivImageCols, ivImageFrom+q.whereSQL(), order, p, func(rows pgx.Rows) error {
		var r ivImageScan
		if err := rows.Scan(ivImageDest(&r)...); err != nil {
			return err
		}
		out = append(out, ivFixImage(&r))
		return nil
	})
	return out, total, err
}

// GetImage implements store.InventoryQuery.
func (d *DB) GetImage(ctx context.Context, digest string) (store.ImageDetail, error) {
	const op = "get image"
	var out store.ImageDetail
	var r ivImageScan
	err := d.q.QueryRow(ctx, `SELECT `+ivImageCols+` `+ivImageFrom+` WHERE i.digest = $1`, digest).
		Scan(ivImageDest(&r)...)
	if err != nil {
		return out, ivErr(op, err)
	}
	out.ImageRow = ivFixImage(&r)
	rows, err := d.q.Query(ctx, `
		SELECT `+ivAssetRowCols+`, `+ivContainerCols+`
		FROM asset_containers ct JOIN assets a ON a.id = ct.asset_id
		LEFT JOIN k8s_clusters k ON k.id = a.cluster_id
		WHERE ct.image_digest = $1 AND ct.gone_at IS NULL AND a.gone_at IS NULL
		ORDER BY a.name, a.id, ct.name`, digest)
	if err != nil {
		return out, ivErr(op, err)
	}
	defer rows.Close()
	for rows.Next() {
		var u store.ImageUse
		if err := rows.Scan(append(ivAssetRowDest(&u.Asset), ivContainerDest(&u.Container)...)...); err != nil {
			return out, ivErr(op, err)
		}
		ivFixAssetRow(&u.Asset)
		ivFixContainer(&u.Container)
		out.Uses = append(out.Uses, u)
	}
	return out, ivErr(op, rows.Err())
}
