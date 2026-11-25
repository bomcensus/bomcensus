// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"encoding/hex"
	"errors"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

// ivObs is a merged observation ready to be written.
type ivObs struct {
	ident string
	comp  store.Component
	row   ivObsRow
}

// ivObsRow is the JSON form of an observation for jsonb_to_recordset.
type ivObsRow struct {
	NewID          string   `json:"new_id"`
	Source         string   `json:"source"`
	ComponentID    string   `json:"component_id"`
	Locations      []string `json:"locations"`
	InUse          bool     `json:"in_use"`
	Method         string   `json:"method"`
	VersionCommand string   `json:"version_command"`
	VersionRaw     string   `json:"version_raw"`
}

// ivMergeObs merges observations of the same component (per source) and
// orders them by identity.
func ivMergeObs(source store.ComponentSource, obs []store.ComponentObservation, out map[string]*ivObs) {
	for _, o := range obs {
		ident := ivIdentHex(o.Component)
		key := string(source) + "|" + ident
		m, ok := out[key]
		if !ok {
			m = &ivObs{ident: ident, comp: o.Component, row: ivObsRow{
				NewID:  ivNewID(),
				Source: string(source),
			}}
			out[key] = m
		}
		m.row.Locations = append(m.row.Locations, o.Locations...)
		m.row.InUse = m.row.InUse || o.InUse
		if m.row.Method == "" {
			m.row.Method = o.Method
		}
		if m.row.VersionCommand == "" && m.row.VersionRaw == "" {
			m.row.VersionCommand = o.VersionCommand
			m.row.VersionRaw = o.VersionRaw
		}
	}
}

func ivSortedObs(m map[string]*ivObs) []*ivObs {
	out := make([]*ivObs, 0, len(m))
	for _, o := range m {
		o.row.Locations = ivSortedUnique(o.row.Locations)
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ident != out[j].ident {
			return out[i].ident < out[j].ident
		}
		return out[i].row.Source < out[j].row.Source
	})
	return out
}

// ivUpsertComponents creates the missing global components of obs and fills
// in row.ComponentID. It returns the IDs of the created components.
func (d *DB) ivUpsertComponents(ctx context.Context, obs []*ivObs, at time.Time) ([]string, error) {
	if len(obs) == 0 {
		return nil, nil
	}
	type row struct {
		ID            string `json:"id"`
		Ident         string `json:"ident"`
		Type          string `json:"type"`
		Name          string `json:"name"`
		Version       string `json:"version"`
		Arch          string `json:"arch"`
		Distro        string `json:"distro"`
		PURL          string `json:"purl"`
		CPE           string `json:"cpe"`
		SourceName    string `json:"source_name"`
		SourceVersion string `json:"source_version"`
		Vendor        string `json:"vendor"`
		Origin        string `json:"origin"`
		Modularity    string `json:"modularity"`
	}
	seen := map[string]bool{}
	var rows []row
	var idents [][]byte
	for _, o := range obs {
		if seen[o.ident] {
			continue
		}
		seen[o.ident] = true
		c := o.comp
		rows = append(rows, row{ivNewID(), o.ident, c.Type, c.Name, c.Version, c.Arch, c.Distro, c.PURL,
			c.CPE, c.SourceName, c.SourceVersion, c.Vendor, string(c.Origin), c.Modularity})
		b, _ := hex.DecodeString(o.ident)
		idents = append(idents, b)
	}
	js, err := ivJSON(rows)
	if err != nil {
		return nil, err
	}
	// Rows are sorted by identity so that concurrent writers take the
	// unique index locks in the same order.
	var created []string
	res, err := d.q.Query(ctx, `
		INSERT INTO components (id, ident, type, name, version, arch, distro, purl, cpe,
			source_name, source_version, vendor, origin, modularity, created_at)
		SELECT x.id, decode(x.ident, 'hex'), x.type, x.name, x.version, x.arch, x.distro, x.purl, x.cpe,
			x.source_name, x.source_version, x.vendor, x.origin, x.modularity, $2
		FROM jsonb_to_recordset($1::jsonb) AS x(id uuid, ident text, type text, name text, version text,
			arch text, distro text, purl text, cpe text, source_name text, source_version text,
			vendor text, origin text, modularity text)
		ORDER BY x.ident
		ON CONFLICT (ident) DO NOTHING
		RETURNING id::text`, js, at)
	if err != nil {
		return nil, err
	}
	for res.Next() {
		var id string
		if err := res.Scan(&id); err != nil {
			res.Close()
			return nil, err
		}
		created = append(created, id)
	}
	res.Close()
	if err := res.Err(); err != nil {
		return nil, err
	}

	// Components stored before the modularity label was kept get it from
	// the next observation that has one, and are matched again.
	var labeled []row
	for _, r := range rows {
		if r.Modularity != "" {
			labeled = append(labeled, r)
		}
	}
	if len(labeled) > 0 {
		ljs, err := ivJSON(labeled)
		if err != nil {
			return nil, err
		}
		if _, err := d.q.Exec(ctx, `
			WITH upd AS (
				UPDATE components c SET modularity = x.modularity
				FROM jsonb_to_recordset($1::jsonb) AS x(ident text, modularity text)
				WHERE c.ident = decode(x.ident, 'hex') AND c.modularity = ''
				RETURNING c.id
			)
			DELETE FROM component_matches m USING upd WHERE m.component_id = upd.id`, ljs); err != nil {
			return nil, err
		}
	}

	// A separate statement sees rows committed by concurrent writers.
	ids := make(map[string]string, len(rows))
	res, err = d.q.Query(ctx, `SELECT id::text, encode(ident, 'hex') FROM components WHERE ident = ANY($1::bytea[])`, idents)
	if err != nil {
		return nil, err
	}
	for res.Next() {
		var id, ident string
		if err := res.Scan(&id, &ident); err != nil {
			res.Close()
			return nil, err
		}
		ids[ident] = id
	}
	res.Close()
	if err := res.Err(); err != nil {
		return nil, err
	}
	for _, o := range obs {
		o.row.ComponentID = ids[o.ident]
	}
	sort.Strings(created)
	return created, nil
}

// ReplaceAssetComponents implements store.ComponentIngest.
func (d *DB) ReplaceAssetComponents(ctx context.Context, scope store.ComponentScope, obs []store.ComponentObservation, opts store.ReplaceOptions) (store.ReplaceResult, error) {
	const op = "replace asset components"
	var res store.ReplaceResult
	if scope.Source != store.SourcePackages && scope.Source != store.SourceArtifacts {
		return res, ivInvalid(op, "unknown source")
	}
	switch scope.Layer {
	case "", store.LayerImage, store.LayerRuntime:
	default:
		return res, ivInvalid(op, "unknown layer")
	}
	if scope.Container == "" && scope.Layer != "" {
		return res, ivInvalid(op, "layer without container")
	}
	at := ivAt(opts.At)
	merged := map[string]*ivObs{}
	ivMergeObs(scope.Source, obs, merged)
	list := ivSortedObs(merged)

	err := d.ivAtomic(ctx, func(d *DB) error {
		if err := d.ivLockAsset(ctx, op, scope.AssetID); err != nil {
			return err
		}
		created, err := d.ivUpsertComponents(ctx, list, at)
		if err != nil {
			return ivErr(op, err)
		}
		res.NewComponents = created
		rows := make([]ivObsRow, len(list))
		for i, o := range list {
			rows[i] = o.row
		}
		js, err := ivJSON(rows)
		if err != nil {
			return err
		}
		err = d.q.QueryRow(ctx, `
			WITH obs AS (
				SELECT * FROM jsonb_to_recordset($5::jsonb) AS x(new_id uuid, component_id uuid,
					locations text[], in_use boolean, method text, version_command text, version_raw text)
			), cur AS (
				SELECT id, component_id FROM asset_components
				WHERE asset_id = $1 AND container = $2 AND source = $3 AND layer = $4 AND removed_at IS NULL
			), changed AS (
				UPDATE asset_components ac SET locations = o.locations, in_use = o.in_use, method = o.method,
					version_command = o.version_command, version_raw = o.version_raw
				FROM obs o JOIN cur ON cur.component_id = o.component_id
				WHERE ac.id = cur.id
				  AND (ac.locations, ac.in_use, ac.method, ac.version_command, ac.version_raw)
				      IS DISTINCT FROM (o.locations, o.in_use, o.method, o.version_command, o.version_raw)
				RETURNING 1
			), added AS (
				INSERT INTO asset_components (id, asset_id, container, source, layer, component_id,
					locations, in_use, method, version_command, version_raw, first_seen)
				SELECT o.new_id, $1, $2, $3, $4, o.component_id, o.locations, o.in_use, o.method,
					o.version_command, o.version_raw, $6
				FROM obs o WHERE NOT EXISTS (SELECT 1 FROM cur WHERE cur.component_id = o.component_id)
				RETURNING 1
			), removed AS (
				UPDATE asset_components ac SET removed_at = GREATEST($6, ac.first_seen)
				FROM cur
				WHERE ac.id = cur.id AND NOT $7::boolean
				  AND NOT EXISTS (SELECT 1 FROM obs o WHERE o.component_id = cur.component_id)
				RETURNING 1
			)
			SELECT (SELECT count(*) FROM added), (SELECT count(*) FROM removed), (SELECT count(*) FROM changed)`,
			scope.AssetID, scope.Container, string(scope.Source), scope.Layer, js, at, opts.KeepMissing).
			Scan(&res.Added, &res.Removed, &res.Changed)
		return ivErr(op, err)
	})
	if err != nil {
		return store.ReplaceResult{}, err
	}
	res.ComponentIDs = make([]string, len(obs))
	for i, o := range obs {
		if m := merged[string(scope.Source)+"|"+ivIdentHex(o.Component)]; m != nil {
			res.ComponentIDs[i] = m.row.ComponentID
		}
	}
	return res, nil
}

// ComponentsAtLocations implements store.ComponentIngest.
func (d *DB) ComponentsAtLocations(ctx context.Context, assetID string, locs []store.ComponentLocation) (map[store.ComponentLocation]string, error) {
	const op = "components at locations"
	out := map[store.ComponentLocation]string{}
	if err := d.ivScopeAsset(ctx, op, assetID); err != nil {
		return nil, err
	}
	if len(locs) == 0 || !ivValidID(assetID) {
		return out, nil
	}
	type row struct {
		Container string `json:"container"`
		Path      string `json:"path"`
	}
	seen := map[store.ComponentLocation]bool{}
	var rows []row
	var containers []string
	for _, l := range locs {
		if seen[l] {
			continue
		}
		seen[l] = true
		rows = append(rows, row{l.Container, l.Path})
		containers = append(containers, l.Container)
	}
	js, err := ivJSON(rows)
	if err != nil {
		return nil, err
	}
	res, err := d.q.Query(ctx, `
		WITH l AS (
			SELECT * FROM jsonb_to_recordset($2::jsonb) AS x(container text, path text)
		), r AS (
			SELECT ac.container, ac.layer, ac.source, ac.component_id, ac.locations
			FROM asset_components ac
			WHERE ac.asset_id = $1 AND ac.removed_at IS NULL AND ac.container = ANY($3)
			UNION ALL
			SELECT ct.name, 'image', ic.source, ic.component_id, ic.locations
			FROM asset_containers ct JOIN image_components ic ON ic.digest = ct.image_digest
			WHERE ct.asset_id = $1 AND ct.gone_at IS NULL AND ct.image_digest <> '' AND ct.name = ANY($3)
		)
		SELECT DISTINCT ON (l.container, l.path) l.container, l.path, c.id::text
		FROM l JOIN r ON r.container = l.container AND l.path = ANY(r.locations)
		JOIN components c ON c.id = r.component_id
		ORDER BY l.container, l.path, c.name, c.version, r.layer, r.source, c.id`,
		assetID, js, ivSortedUnique(containers))
	if err != nil {
		return nil, ivErr(op, err)
	}
	defer res.Close()
	for res.Next() {
		var l store.ComponentLocation
		var id string
		if err := res.Scan(&l.Container, &l.Path, &id); err != nil {
			return nil, ivErr(op, err)
		}
		out[l] = id
	}
	return out, ivErr(op, res.Err())
}

// LookupComponentIDs implements store.ComponentIngest.
func (d *DB) LookupComponentIDs(ctx context.Context, comps []store.Component) ([]string, error) {
	const op = "lookup component ids"
	out := make([]string, len(comps))
	if len(comps) == 0 {
		return out, nil
	}
	idents := make([][]byte, len(comps))
	for i, c := range comps {
		idents[i] = ivIdent(c)
	}
	rows, err := d.q.Query(ctx, `SELECT encode(ident, 'hex'), id::text FROM components WHERE ident = ANY($1::bytea[])`, idents)
	if err != nil {
		return nil, ivErr(op, err)
	}
	defer rows.Close()
	ids := map[string]string{}
	for rows.Next() {
		var ident, id string
		if err := rows.Scan(&ident, &id); err != nil {
			return nil, ivErr(op, err)
		}
		ids[ident] = id
	}
	if err := rows.Err(); err != nil {
		return nil, ivErr(op, err)
	}
	for i, c := range comps {
		out[i] = ids[ivIdentHex(c)]
	}
	return out, nil
}

// PutImageContent implements store.ComponentIngest.
func (d *DB) PutImageContent(ctx context.Context, c store.ImageContent) (bool, error) {
	const op = "put image content"
	if c.Digest == "" {
		return false, ivInvalid(op, "empty digest")
	}
	at := ivAt(c.CollectedAt)
	coverage := c.Coverage
	if coverage == "" {
		coverage = store.CoverageFull
	}
	merged := map[string]*ivObs{}
	ivMergeObs(store.SourcePackages, c.Packages, merged)
	ivMergeObs(store.SourceArtifacts, c.Artifacts, merged)
	list := ivSortedObs(merged)

	written := false
	err := d.ivAtomic(ctx, func(d *DB) error {
		if _, err := d.q.Exec(ctx, `
			INSERT INTO images (digest, first_seen, last_seen) VALUES ($1, $2, $2)
			ON CONFLICT (digest) DO UPDATE SET last_seen = GREATEST(images.last_seen, EXCLUDED.last_seen)`,
			c.Digest, at); err != nil {
			return ivErr(op, err)
		}
		var known *time.Time
		var stored store.Coverage
		err := d.q.QueryRow(ctx, `SELECT content_collected_at, content_coverage FROM images WHERE digest = $1 FOR UPDATE`,
			c.Digest).Scan(&known, &stored)
		if err != nil {
			return ivErr(op, err)
		}
		if known != nil && !(stored != store.CoverageFull && coverage == store.CoverageFull) {
			return nil
		}
		if _, err := d.ivUpsertComponents(ctx, list, at); err != nil {
			return ivErr(op, err)
		}
		rows := make([]ivObsRow, len(list))
		for i, o := range list {
			rows[i] = o.row
		}
		js, err := ivJSON(rows)
		if err != nil {
			return err
		}
		if _, err := d.q.Exec(ctx, `DELETE FROM image_components WHERE digest = $1`, c.Digest); err != nil {
			return ivErr(op, err)
		}
		if _, err := d.q.Exec(ctx, `
			INSERT INTO image_components (digest, source, component_id, locations, in_use, method,
				version_command, version_raw)
			SELECT $1, x.source, x.component_id, x.locations, x.in_use, x.method, x.version_command, x.version_raw
			FROM jsonb_to_recordset($2::jsonb) AS x(source text, component_id uuid, locations text[],
				in_use boolean, method text, version_command text, version_raw text)`, c.Digest, js); err != nil {
			return ivErr(op, err)
		}
		if _, err := d.q.Exec(ctx, `
			UPDATE images SET content_coverage = $2, content_collected_at = $3 WHERE digest = $1`,
			c.Digest, string(coverage), at); err != nil {
			return ivErr(op, err)
		}
		written = true
		return nil
	})
	return written, err
}

// KnownImageContent implements store.ComponentIngest.
func (d *DB) KnownImageContent(ctx context.Context, digests []string) ([]string, error) {
	const op = "known image content"
	rows, err := d.q.Query(ctx, `
		SELECT digest FROM images WHERE digest = ANY($1) AND content_collected_at IS NOT NULL ORDER BY digest`,
		ivStrings(digests))
	if err != nil {
		return nil, ivErr(op, err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	return out, ivErr(op, err)
}

// ImageContentCoverage implements store.ComponentIngest.
func (d *DB) ImageContentCoverage(ctx context.Context, digest string) (store.Coverage, error) {
	const op = "image content coverage"
	var cov string
	err := d.q.QueryRow(ctx, `
		SELECT content_coverage FROM images WHERE digest = $1 AND content_collected_at IS NOT NULL`, digest).Scan(&cov)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", ivErr(op, err)
	}
	if cov == "" {
		cov = string(store.CoverageFull)
	}
	return store.Coverage(cov), nil
}

// RecordFileHashes implements store.ComponentIngest.
func (d *DB) RecordFileHashes(ctx context.Context, hashes []store.FileHash, at time.Time) error {
	const op = "record file hashes"
	type row struct {
		SHA256      string `json:"sha256"`
		ComponentID string `json:"component_id"`
		Path        string `json:"path"`
	}
	seen := map[[2]string]bool{}
	var rows []row
	for _, h := range hashes {
		if h.SHA256 == "" || !ivValidID(h.ComponentID) {
			continue
		}
		k := [2]string{h.SHA256, h.ComponentID}
		if seen[k] {
			continue
		}
		seen[k] = true
		rows = append(rows, row{h.SHA256, h.ComponentID, h.Path})
	}
	if len(rows) == 0 {
		return nil
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].SHA256 != rows[j].SHA256 {
			return rows[i].SHA256 < rows[j].SHA256
		}
		return rows[i].ComponentID < rows[j].ComponentID
	})
	js, err := ivJSON(rows)
	if err != nil {
		return err
	}
	_, err = d.q.Exec(ctx, `
		INSERT INTO file_hashes (sha256, component_id, path, first_seen, last_seen)
		SELECT x.sha256, x.component_id, x.path, $2, $2
		FROM jsonb_to_recordset($1::jsonb) AS x(sha256 text, component_id uuid, path text)
		ON CONFLICT (sha256, component_id) DO UPDATE SET
			path = EXCLUDED.path, last_seen = GREATEST(file_hashes.last_seen, EXCLUDED.last_seen)`,
		js, ivAt(at))
	return ivErr(op, err)
}

// ComponentsByFileHash implements store.ComponentIngest.
func (d *DB) ComponentsByFileHash(ctx context.Context, sha256s []string) (map[string]string, error) {
	const op = "components by file hash"
	rows, err := d.q.Query(ctx, `
		SELECT DISTINCT ON (sha256) sha256, component_id::text FROM file_hashes
		WHERE sha256 = ANY($1) ORDER BY sha256, last_seen DESC, component_id`, ivStrings(sha256s))
	if err != nil {
		return nil, ivErr(op, err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var h, id string
		if err := rows.Scan(&h, &id); err != nil {
			return nil, ivErr(op, err)
		}
		out[h] = id
	}
	return out, ivErr(op, rows.Err())
}

const ivPlacementCols = `r.container, r.layer, r.source, r.locations, r.in_use, r.method,
	r.version_command, r.version_raw, r.first_seen, r.removed_at`

func ivPlacementDest(p *store.Placement) []any {
	return []any{&p.Container, &p.Layer, &p.Source, &p.Locations, &p.InUse, &p.Method,
		&p.VersionCommand, &p.VersionRaw, &p.FirstSeen, &p.RemovedAt}
}

func ivFixPlacement(p *store.Placement) {
	p.FirstSeen = p.FirstSeen.UTC()
	p.RemovedAt = ivUTC(p.RemovedAt)
	p.Locations = ivStrings(p.Locations)
}

// ListAssetComponents implements store.InventoryQuery.
func (d *DB) ListAssetComponents(ctx context.Context, assetID string, f store.AssetComponentFilter, p store.Page) ([]store.AssetComponentRow, int, error) {
	const op = "list asset components"
	order, err := ivOrder(op, f.Sort, "name", map[string]string{
		"name":       "c.name",
		"version":    "c.version",
		"type":       "c.type",
		"origin":     "c.origin",
		"method":     "r.method",
		"in_use":     "r.in_use",
		"container":  "r.container",
		"first_seen": "r.first_seen",
	}, "c.name, c.version, r.container, r.layer, r.source, c.id, r.first_seen")
	if err != nil {
		return nil, 0, err
	}
	if err := d.ivScopeAsset(ctx, op, assetID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	if !ivValidID(assetID) {
		return nil, 0, nil
	}
	q := &ivQuery{}
	a := q.arg(assetID)
	current, currentCt := " AND ac.removed_at IS NULL", " AND ct.gone_at IS NULL"
	if f.IncludeRemoved {
		current, currentCt = "", ""
	}
	if f.Container != nil {
		q.where("r.container = %s", *f.Container)
	}
	if f.Type != "" {
		q.where("c.type = %s", f.Type)
	}
	if f.Origin != "" {
		q.where("c.origin = %s", string(f.Origin))
	}
	if f.Source != "" {
		q.where("r.source = %s", string(f.Source))
	}
	if f.Layer != "" {
		q.where("r.layer = %s", f.Layer)
	}
	if f.InUseOnly {
		q.where("r.in_use")
	}
	if f.InUse != nil {
		q.where("r.in_use = %s", *f.InUse)
	}
	if f.Q != "" {
		q.where(`(c.name ILIKE %[1]s OR c.version ILIKE %[1]s OR c.purl ILIKE %[1]s OR r.container ILIKE %[1]s
			OR array_to_string(r.locations, ' ') ILIKE %[1]s)`, ivLike(f.Q))
	}
	from := `FROM (
			SELECT ac.component_id, ac.container, ac.layer, ac.source, ac.locations, ac.in_use, ac.method,
				ac.version_command, ac.version_raw, ac.first_seen, ac.removed_at
			FROM asset_components ac WHERE ac.asset_id = ` + a + current + `
			UNION ALL
			SELECT ic.component_id, ct.name, 'image', ic.source, ic.locations, ic.in_use, ic.method,
				ic.version_command, ic.version_raw, ct.digest_since, ct.gone_at
			FROM asset_containers ct JOIN image_components ic ON ic.digest = ct.image_digest
			WHERE ct.asset_id = ` + a + ` AND ct.image_digest <> ''` + currentCt + `
		) r JOIN components c ON c.id = r.component_id` + q.whereSQL()
	var out []store.AssetComponentRow
	total, err := ivPage(ctx, d, op, q, ivComponentCols+", "+ivPlacementCols, from, order, p, func(rows pgx.Rows) error {
		var r store.AssetComponentRow
		if err := rows.Scan(append(ivComponentDest(&r.Component), ivPlacementDest(&r.Placement)...)...); err != nil {
			return err
		}
		ivFixPlacement(&r.Placement)
		out = append(out, r)
		return nil
	})
	return out, total, err
}

// ivInstalledAssets counts the assets in the scope where component c.id is
// installed now.
func ivInstalledAssets(sc sqlScope) string {
	in := sc.col("aa.scope_id")
	return `(SELECT count(*) FROM (
		SELECT ac.asset_id FROM asset_components ac JOIN assets aa ON aa.id = ac.asset_id
		WHERE ac.component_id = c.id AND ac.removed_at IS NULL AND aa.gone_at IS NULL AND ` + in + `
		UNION
		SELECT ct.asset_id FROM image_components ic
		JOIN asset_containers ct ON ct.image_digest = ic.digest AND ct.gone_at IS NULL
		JOIN assets aa ON aa.id = ct.asset_id AND aa.gone_at IS NULL
		WHERE ic.component_id = c.id AND ` + in + `) s)`
}

// ivRunningAssets counts the assets in the scope where a running process
// uses component c.id now: an installation marked in use, or an in-use component of the
// image of a running container. The in-use marks of a container stay when
// it stops, so a container's rows count only while it runs.
func ivRunningAssets(sc sqlScope) string {
	in := sc.col("aa.scope_id")
	return `(SELECT count(*) FROM (
		SELECT ac.asset_id FROM asset_components ac JOIN assets aa ON aa.id = ac.asset_id
		WHERE ac.component_id = c.id AND ac.in_use AND ac.removed_at IS NULL AND aa.gone_at IS NULL AND ` + in + `
		  AND (ac.container = '' OR EXISTS (SELECT 1 FROM asset_containers ct
			WHERE ct.asset_id = ac.asset_id AND ct.name = ac.container AND ct.gone_at IS NULL AND ct.instances > 0))
		UNION
		SELECT ct.asset_id FROM image_components ic
		JOIN asset_containers ct ON ct.image_digest = ic.digest AND ct.gone_at IS NULL AND ct.instances > 0
		JOIN assets aa ON aa.id = ct.asset_id AND aa.gone_at IS NULL
		WHERE ic.component_id = c.id AND ic.in_use AND ` + in + `) s)`
}

// ListComponents implements store.InventoryQuery.
func (d *DB) ListComponents(ctx context.Context, f store.ComponentFilter, p store.Page) ([]store.ComponentRow, int, error) {
	const op = "list components"
	order, err := ivOrder(op, f.Sort, "name", map[string]string{
		"name":    "c.name",
		"version": "c.version",
		"type":    "c.type",
		"origin":  "c.origin",
		"purl":    "c.purl",
		"assets":  "c.assets",
		"running": "c.running",
	}, "c.name, c.version, c.id")
	if err != nil {
		return nil, 0, err
	}
	q, sc, err := scoped(ctx, op)
	if err != nil {
		return nil, 0, err
	}
	q.and(sc.component("c.id"))
	if f.Type != "" {
		q.where("c.type = %s", f.Type)
	}
	if f.Origin != "" {
		q.where("c.origin = %s", string(f.Origin))
	}
	if f.Source != "" {
		q.where(`(EXISTS (SELECT 1 FROM asset_components ac WHERE ac.component_id = c.id AND ac.source = %[1]s)
			OR EXISTS (SELECT 1 FROM image_components ic WHERE ic.component_id = c.id AND ic.source = %[1]s))`,
			string(f.Source))
	}
	if f.InstalledOnly {
		q.where("c.assets > 0")
	}
	if f.RunningOnly {
		q.where("c.running > 0")
	}
	if f.Q != "" {
		q.where("(c.name ILIKE %[1]s OR c.purl ILIKE %[1]s)", ivLike(f.Q))
	}
	from := `FROM (SELECT c.*, ` + ivInstalledAssets(sc) + ` AS assets, ` + ivRunningAssets(sc) + ` AS running FROM components c) c` + q.whereSQL()
	var out []store.ComponentRow
	total, err := ivPage(ctx, d, op, q, ivComponentCols+", c.assets, c.running", from, order, p, func(rows pgx.Rows) error {
		var r store.ComponentRow
		if err := rows.Scan(append(ivComponentDest(&r.Component), &r.Assets, &r.RunningAssets)...); err != nil {
			return err
		}
		out = append(out, r)
		return nil
	})
	return out, total, err
}

// GetComponent implements store.InventoryQuery.
func (d *DB) GetComponent(ctx context.Context, id string) (store.ComponentRow, error) {
	const op = "get component"
	var r store.ComponentRow
	q, sc, err := scoped(ctx, op, id)
	if err != nil {
		return r, err
	}
	if !ivValidID(id) {
		return r, ivNotFound(op)
	}
	err = d.q.QueryRow(ctx, `SELECT `+ivComponentCols+`, `+ivInstalledAssets(sc)+`, `+ivRunningAssets(sc)+
		` FROM components c WHERE c.id = $1 AND `+sc.component("c.id"), q.args...).
		Scan(append(ivComponentDest(&r.Component), &r.Assets, &r.RunningAssets)...)
	return r, ivErr(op, err)
}

// ListComponentAssets implements store.InventoryQuery.
func (d *DB) ListComponentAssets(ctx context.Context, componentID string, f store.ComponentAssetFilter, p store.Page) ([]store.ComponentAssetRow, int, error) {
	const op = "list component assets"
	order, err := ivOrder(op, f.Sort, "asset", map[string]string{
		"asset":      "a.name",
		"container":  "r.container",
		"method":     "r.method",
		"in_use":     "r.in_use",
		"first_seen": "r.first_seen",
	}, "a.name, a.id, r.container, r.layer, r.source")
	if err != nil {
		return nil, 0, err
	}
	if !ivValidID(componentID) {
		return nil, 0, nil
	}
	q, sc, err := scoped(ctx, op)
	if err != nil {
		return nil, 0, err
	}
	cid := q.arg(componentID)
	q.and(sc.col("a.scope_id"))
	q.where("a.gone_at IS NULL")
	if f.Kind != "" {
		q.where("a.kind = %s", string(f.Kind))
	}
	if f.InUse != nil {
		q.where("r.in_use = %s", *f.InUse)
	}
	if f.Method != "" {
		q.where("r.method = %s", f.Method)
	}
	if f.Q != "" {
		q.where(`(a.name ILIKE %[1]s OR r.container ILIKE %[1]s OR array_to_string(r.locations, ' ') ILIKE %[1]s)`, ivLike(f.Q))
	}
	current, currentCt := " AND ac.removed_at IS NULL", " AND ct.gone_at IS NULL"
	if f.IncludeRemoved {
		current, currentCt = "", ""
	}
	from := `FROM (
			SELECT ac.asset_id, ac.container, ac.layer, ac.source, ac.locations, ac.in_use, ac.method,
				ac.version_command, ac.version_raw, ac.first_seen, ac.removed_at
			FROM asset_components ac WHERE ac.component_id = ` + cid + current + `
			UNION ALL
			SELECT ct.asset_id, ct.name, 'image', ic.source, ic.locations, ic.in_use, ic.method,
				ic.version_command, ic.version_raw, ct.digest_since, ct.gone_at
			FROM image_components ic
			JOIN asset_containers ct ON ct.image_digest = ic.digest` + currentCt + `
			WHERE ic.component_id = ` + cid + `
		) r JOIN assets a ON a.id = r.asset_id LEFT JOIN k8s_clusters k ON k.id = a.cluster_id` + q.whereSQL()
	var out []store.ComponentAssetRow
	total, err := ivPage(ctx, d, op, q, ivAssetRowCols+", "+ivPlacementCols, from, order, p, func(rows pgx.Rows) error {
		var r store.ComponentAssetRow
		if err := rows.Scan(append(ivAssetRowDest(&r.Asset), ivPlacementDest(&r.Placement)...)...); err != nil {
			return err
		}
		ivFixAssetRow(&r.Asset)
		ivFixPlacement(&r.Placement)
		out = append(out, r)
		return nil
	})
	return out, total, err
}

// ListImageComponents implements store.InventoryQuery.
func (d *DB) ListImageComponents(ctx context.Context, digest string, f store.ImageComponentFilter, p store.Page) ([]store.ImageComponentRow, int, error) {
	const op = "list image components"
	order, err := ivOrder(op, f.Sort, "name", map[string]string{
		"name":    "c.name",
		"version": "c.version",
		"type":    "c.type",
		"source":  "r.source",
	}, "c.name, c.version, r.source, c.id")
	if err != nil {
		return nil, 0, err
	}
	q, sc, err := scoped(ctx, op)
	if err != nil {
		return nil, 0, err
	}
	q.where("r.digest = %s", digest)
	q.and(sc.image("r.digest"))
	if f.Type != "" {
		q.where("c.type = %s", f.Type)
	}
	if f.Source != "" {
		q.where("r.source = %s", string(f.Source))
	}
	if f.Q != "" {
		q.where("(c.name ILIKE %[1]s OR c.version ILIKE %[1]s OR c.purl ILIKE %[1]s)", ivLike(f.Q))
	}
	from := `FROM (SELECT ic.*, ''::text AS container, 'image'::text AS layer,
			COALESCE(i.content_collected_at, i.first_seen) AS first_seen, NULL::timestamptz AS removed_at
			FROM image_components ic JOIN images i ON i.digest = ic.digest) r
		JOIN components c ON c.id = r.component_id` + q.whereSQL()
	var out []store.ImageComponentRow
	total, err := ivPage(ctx, d, op, q, ivComponentCols+", "+ivPlacementCols, from, order, p, func(rows pgx.Rows) error {
		var r store.ImageComponentRow
		if err := rows.Scan(append(ivComponentDest(&r.Component), ivPlacementDest(&r.Placement)...)...); err != nil {
			return err
		}
		ivFixPlacement(&r.Placement)
		out = append(out, r)
		return nil
	})
	return out, total, err
}
