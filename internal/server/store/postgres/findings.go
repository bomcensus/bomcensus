// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

var _ store.Findings = (*DB)(nil)

// DirtyFindingAssets implements store.Findings.
func (d *DB) DirtyFindingAssets(ctx context.Context, limit int) ([]string, error) {
	if err := requireAll(ctx, "dirty finding assets"); err != nil {
		return nil, err
	}
	rows, err := d.q.Query(ctx, `
		SELECT a.id::text FROM assets a
		LEFT JOIN asset_findings_state s ON s.asset_id = a.id
		WHERE (s.asset_id IS NULL AND (a.gone_at IS NULL
				OR EXISTS (SELECT 1 FROM findings f WHERE f.asset_id = a.id AND f.resolved_at IS NULL)))
			OR s.seen_at IS DISTINCT FROM a.last_seen
			OR s.gone IS DISTINCT FROM (a.gone_at IS NOT NULL)
			OR s.vulns_seen IS DISTINCT FROM s.vulns_version
		ORDER BY s.refreshed_at NULLS FIRST, a.id
		LIMIT $1`, limit)
	if err != nil {
		return nil, mgErr("dirty finding assets", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, mgErr("dirty finding assets", err)
		}
		out = append(out, id)
	}
	return out, mgErr("dirty finding assets", rows.Err())
}

// FindingInputs implements store.Findings. The reads share one snapshot,
// so that the stamp tells exactly what they saw.
func (d *DB) FindingInputs(ctx context.Context, assetID string) (store.FindingInputs, error) {
	if d.inTx {
		return d.findingInputs(ctx, assetID)
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return store.FindingInputs{}, fmt.Errorf("postgres: begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // read only
	return (&DB{pool: d.pool, q: tx, inTx: true, feat: d.feat}).findingInputs(ctx, assetID)
}

func (d *DB) findingInputs(ctx context.Context, assetID string) (store.FindingInputs, error) {
	in := store.FindingInputs{ProcessCoverage: map[string]store.Coverage{}, HashComponents: map[string][]string{}}
	if err := d.ivScopeAsset(ctx, "finding inputs", assetID); err != nil {
		return in, err
	}
	var gone *time.Time
	if err := d.q.QueryRow(ctx, `
		SELECT a.kind, a.gone_at, a.last_seen, coalesce(s.vulns_version, 0)
		FROM assets a LEFT JOIN asset_findings_state s ON s.asset_id = a.id
		WHERE a.id = $1`, assetID).Scan(&in.Kind, &gone, &in.Stamp.SeenAt, &in.Stamp.VulnsVersion); err != nil {
		return in, mgErr("finding inputs", err)
	}
	in.Gone = gone != nil
	in.Stamp.Gone = in.Gone
	if in.Gone {
		return in, nil
	}

	// Pod containers belong to their workload asset: a host leaves them
	// out, a workload takes in what node agents saw of its pods.
	pods, err := d.fiPodLinks(ctx, assetID, &in)
	if err != nil {
		return in, mgErr("finding inputs", err)
	}

	// Vulnerable components: installed on the asset or in a container's
	// layers, and the content of the images of current containers.
	rows, err := d.q.Query(ctx, `
		WITH n AS (SELECT * FROM `+fiNodes+`)
		SELECT x.container, x.layer, x.digest, x.locations, x.in_use,
			c.id, c.type, c.name, c.version, c.arch, c.distro, c.purl, c.source_name, c.origin
		FROM (
			SELECT ac.container, CASE WHEN ac.container = '' THEN '' ELSE ac.layer END AS layer, '' AS digest,
				ac.locations, ac.in_use, ac.component_id
			FROM asset_components ac
			WHERE ac.asset_id = $1 AND ac.removed_at IS NULL AND ac.container <> ALL($2::text[])
			UNION ALL
			SELECT ct.name, 'image', ct.image_digest, ic.locations, false, ic.component_id
			FROM asset_containers ct JOIN image_components ic ON ic.digest = ct.image_digest
			WHERE ct.asset_id = $1 AND ct.gone_at IS NULL AND ct.image_digest <> '' AND ct.name <> ALL($2::text[])
			UNION ALL
			SELECT n.container, ac.layer, '', ac.locations, ac.in_use, ac.component_id
			FROM n JOIN asset_components ac ON ac.asset_id = n.host_id AND ac.container = n.host_container
			WHERE ac.removed_at IS NULL
			UNION ALL
			SELECT n.container, 'image', ct.image_digest, ic.locations, false, ic.component_id
			FROM n JOIN asset_containers ct ON ct.asset_id = n.host_id AND ct.name = n.host_container
			JOIN image_components ic ON ic.digest = ct.image_digest
			WHERE ct.image_digest <> ''
		) x
		JOIN components c ON c.id = x.component_id
		WHERE EXISTS (SELECT 1 FROM component_vulns v WHERE v.component_id = x.component_id)`,
		assetID, pods.excluded, pods.nodes)
	if err != nil {
		return in, mgErr("finding inputs", err)
	}
	type key struct{ container, layer, digest, comp string }
	index := map[key]int{}
	for rows.Next() {
		var k key
		var locs []string
		var inUse bool
		var c store.Component
		if err := rows.Scan(&k.container, &k.layer, &k.digest, &locs, &inUse,
			&c.ID, &c.Type, &c.Name, &c.Version, &c.Arch, &c.Distro, &c.PURL, &c.SourceName, &c.Origin); err != nil {
			rows.Close()
			return in, mgErr("finding inputs", err)
		}
		k.comp = c.ID
		i, ok := index[k]
		if !ok {
			in.Sources = append(in.Sources, store.FindingSource{Container: k.container, Layer: k.layer, ImageDigest: k.digest, Component: c})
			i = len(in.Sources) - 1
			index[k] = i
		}
		s := &in.Sources[i]
		s.Locations = append(s.Locations, locs...)
		s.InUse = s.InUse || inUse
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return in, mgErr("finding inputs", err)
	}
	if len(in.Sources) == 0 {
		return in, nil
	}

	var compIDs []string
	byComp := map[string][]int{}
	for i := range in.Sources {
		s := &in.Sources[i]
		slices.Sort(s.Locations)
		s.Locations = slices.Compact(s.Locations)
		if _, ok := byComp[s.Component.ID]; !ok {
			compIDs = append(compIDs, s.Component.ID)
		}
		byComp[s.Component.ID] = append(byComp[s.Component.ID], i)
	}
	rows, err = d.q.Query(ctx, `
		SELECT component_id::text, array_agg(DISTINCT vuln_id ORDER BY vuln_id)
		FROM component_vulns WHERE component_id = ANY($1::uuid[]) GROUP BY component_id`, compIDs)
	if err != nil {
		return in, mgErr("finding inputs", err)
	}
	for rows.Next() {
		var id string
		var vulns []string
		if err := rows.Scan(&id, &vulns); err != nil {
			rows.Close()
			return in, mgErr("finding inputs", err)
		}
		for _, i := range byComp[id] {
			in.Sources[i].VulnIDs = vulns
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return in, mgErr("finding inputs", err)
	}

	if err := d.gsFindingInputs(ctx, assetID, &in, compIDs, pods); err != nil {
		return in, err
	}

	// Processes with their non-loopback listening sockets. A pod container
	// that a node agent saw recently takes the processes it saw, not those
	// of exec collections.
	ports := map[string][]string{}
	rows, err = d.q.Query(ctx, `
		SELECT process_id::text, proto, address, port FROM listen_ports
		WHERE asset_id = ANY($1::uuid[]) AND process_id IS NOT NULL`, append([]string{assetID}, pods.freshHosts...))
	if err != nil {
		return in, mgErr("finding inputs", err)
	}
	for rows.Next() {
		var pid, proto, addr string
		var port int
		if err := rows.Scan(&pid, &proto, &addr, &port); err != nil {
			rows.Close()
			return in, mgErr("finding inputs", err)
		}
		if loopback(addr) {
			continue
		}
		ports[pid] = append(ports[pid], proto+"/"+strconv.Itoa(port))
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return in, mgErr("finding inputs", err)
	}
	rows, err = d.q.Query(ctx, `
		WITH n AS (SELECT * FROM `+fiNodes+` WHERE n.fresh)
		SELECT id::text, pod, container, '' AS node, pid, exe, sha256, coalesce(component_id::text, ''), packages,
			libs::text
		FROM processes p
		WHERE p.asset_id = $1 AND p.container <> ALL($2::text[])
			AND NOT EXISTS (SELECT 1 FROM n WHERE n.container = p.container AND n.pod = p.pod)
		UNION ALL
		SELECT p.id::text, n.pod, n.container, n.host_name, p.pid, p.exe, p.sha256,
			coalesce(p.component_id::text, ''), p.packages, p.libs::text
		FROM n JOIN processes p ON p.asset_id = n.host_id AND p.container = n.host_container
		ORDER BY 3, 2, 4, 5`, assetID, pods.excluded, pods.nodes)
	if err != nil {
		return in, mgErr("finding inputs", err)
	}
	var hashes []string
	for rows.Next() {
		var id, libs string
		var p store.FindingProcess
		if err := rows.Scan(&id, &p.Pod, &p.Container, &p.Node, &p.PID, &p.Exe, &p.SHA256, &p.ComponentID, &p.Packages, &libs); err != nil {
			rows.Close()
			return in, mgErr("finding inputs", err)
		}
		if err := json.Unmarshal([]byte(libs), &p.Libs); err != nil {
			rows.Close()
			return in, fmt.Errorf("postgres: finding inputs: libs: %w", err)
		}
		p.Ports = ports[id]
		slices.Sort(p.Ports)
		p.Ports = slices.Compact(p.Ports)
		if p.SHA256 != "" {
			hashes = append(hashes, p.SHA256)
		}
		for _, l := range p.Libs {
			if l.SHA256 != "" {
				hashes = append(hashes, l.SHA256)
			}
		}
		in.Processes = append(in.Processes, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return in, mgErr("finding inputs", err)
	}

	rows, err = d.q.Query(ctx, `SELECT container, coverage FROM asset_sections WHERE asset_id = $1 AND section = 'processes'`, assetID)
	if err != nil {
		return in, mgErr("finding inputs", err)
	}
	for rows.Next() {
		var container string
		var cov store.Coverage
		if err := rows.Scan(&container, &cov); err != nil {
			rows.Close()
			return in, mgErr("finding inputs", err)
		}
		in.ProcessCoverage[container] = cov
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return in, mgErr("finding inputs", err)
	}
	if err := d.fiNodeProcessCoverage(ctx, &in, pods); err != nil {
		return in, mgErr("finding inputs", err)
	}

	if len(hashes) > 0 {
		rows, err = d.q.Query(ctx, `
			SELECT sha256, component_id::text FROM file_hashes
			WHERE sha256 = ANY($1) AND component_id = ANY($2::uuid[])`, hashes, compIDs)
		if err != nil {
			return in, mgErr("finding inputs", err)
		}
		for rows.Next() {
			var h, c string
			if err := rows.Scan(&h, &c); err != nil {
				rows.Close()
				return in, mgErr("finding inputs", err)
			}
			in.HashComponents[h] = append(in.HashComponents[h], c)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return in, mgErr("finding inputs", err)
		}
	}
	return in, nil
}

// loopback reports whether a listening address is reachable from the
// host only.
func loopback(addr string) bool {
	a := strings.Trim(addr, "[]")
	if a == "localhost" {
		return true
	}
	ip := net.ParseIP(a)
	return ip != nil && ip.IsLoopback()
}

// ApplyFindings implements store.Findings.
func (d *DB) ApplyFindings(ctx context.Context, assetID string, rows []store.FindingRow, stamp store.FindingStamp) (store.FindingsChange, error) {
	type row struct {
		ID          string                    `json:"id"`
		Container   string                    `json:"container"`
		Layer       string                    `json:"layer"`
		ImageDigest string                    `json:"image_digest"`
		ComponentID string                    `json:"component_id"`
		VulnID      string                    `json:"vuln_id"`
		Exposure    string                    `json:"exposure"`
		Reach       *string                   `json:"reachability"`
		Processes   []store.FindingProcessRef `json:"processes"`
	}
	out := make([]row, 0, len(rows))
	for _, r := range rows {
		id, err := mgNewID()
		if err != nil {
			return store.FindingsChange{}, err
		}
		procs := r.Processes
		if procs == nil {
			procs = []store.FindingProcessRef{}
		}
		var reach *string
		if r.Reachability != "" {
			reach = &r.Reachability
		}
		out = append(out, row{ID: id, Container: r.Container, Layer: r.Layer, ImageDigest: r.ImageDigest,
			ComponentID: r.ComponentID, VulnID: r.VulnID, Exposure: r.Exposure, Reach: reach, Processes: procs})
	}
	js, err := json.Marshal(out)
	if err != nil {
		return store.FindingsChange{}, fmt.Errorf("postgres: apply findings: %w", err)
	}
	if err := d.ivScopeAsset(ctx, "apply findings", assetID); err != nil {
		return store.FindingsChange{}, err
	}
	now := mgNow()
	var ch store.FindingsChange
	err = d.mgInTx(ctx, func(tx *DB) error {
		const recs = `jsonb_to_recordset($2::text::jsonb) AS x(id uuid, container text, layer text, image_digest text,
			component_id uuid, vuln_id text, exposure text, reachability text, processes jsonb)`
		if err := tx.q.QueryRow(ctx, `
			WITH up AS (
				INSERT INTO findings AS f (id, asset_id, container, layer, image_digest, component_id, vuln_id,
					exposure, reachability, processes, first_seen, updated_at)
				SELECT x.id, $1, x.container, x.layer, x.image_digest, x.component_id, x.vuln_id,
					x.exposure, x.reachability, x.processes, $3, $3
				FROM `+recs+`
				ON CONFLICT (asset_id, container, component_id, vuln_id) WHERE resolved_at IS NULL
				DO UPDATE SET layer = excluded.layer, image_digest = excluded.image_digest,
					exposure = excluded.exposure, reachability = excluded.reachability,
					processes = excluded.processes, updated_at = excluded.updated_at
				WHERE (f.layer, f.image_digest, f.exposure, f.reachability, f.processes)
					IS DISTINCT FROM (excluded.layer, excluded.image_digest, excluded.exposure, excluded.reachability,
						excluded.processes)
				RETURNING (xmax = 0) AS inserted
			)
			SELECT count(*) FILTER (WHERE inserted) FROM up`, assetID, string(js), now).Scan(&ch.Opened); err != nil {
			return mgErr("apply findings", err)
		}
		tag, err := tx.q.Exec(ctx, `
			UPDATE findings f SET resolved_at = $3, updated_at = $3
			WHERE f.asset_id = $1 AND f.resolved_at IS NULL
				AND NOT EXISTS (SELECT 1 FROM `+recs+`
					WHERE x.container = f.container AND x.component_id = f.component_id AND x.vuln_id = f.vuln_id)`,
			assetID, string(js), now)
		if err != nil {
			return mgErr("apply findings", err)
		}
		ch.Resolved = int(tag.RowsAffected())
		_, err = tx.q.Exec(ctx, `
			INSERT INTO asset_findings_state (asset_id, seen_at, gone, vulns_seen, refreshed_at)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (asset_id) DO UPDATE SET seen_at = excluded.seen_at, gone = excluded.gone,
				vulns_seen = excluded.vulns_seen, refreshed_at = excluded.refreshed_at`,
			assetID, stamp.SeenAt, stamp.Gone, stamp.VulnsVersion, now)
		return mgErr("apply findings", err)
	})
	return ch, err
}

// markVulnsChanged records that the vulnerabilities of components changed,
// for every asset that has one of them.
func (d *DB) markVulnsChanged(ctx context.Context, componentIDs []string) error {
	if len(componentIDs) == 0 {
		return nil
	}
	_, err := d.q.Exec(ctx, `
		INSERT INTO asset_findings_state (asset_id, vulns_version)
		SELECT DISTINCT a, 1 FROM (
			SELECT ac.asset_id AS a FROM asset_components ac
			WHERE ac.component_id = ANY($1::uuid[]) AND ac.removed_at IS NULL
			UNION
			SELECT ct.asset_id FROM asset_containers ct JOIN image_components ic ON ic.digest = ct.image_digest
			WHERE ic.component_id = ANY($1::uuid[]) AND ct.gone_at IS NULL
		) x
		ORDER BY 1
		ON CONFLICT (asset_id) DO UPDATE SET vulns_version = asset_findings_state.vulns_version + 1`,
		componentIDs)
	return mgErr("mark changed vulnerabilities", err)
}
