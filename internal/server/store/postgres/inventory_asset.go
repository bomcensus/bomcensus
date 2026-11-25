// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/server/scope"
)

// UpsertHostAsset implements store.AssetIngest.
func (d *DB) UpsertHostAsset(ctx context.Context, id store.HostIdentity, init store.AssetInit) (store.AssetRef, error) {
	const op = "upsert host asset"
	if id.AgentID == "" && id.MachineID == "" && id.ScanTargetID == "" && (id.ScannerID == "" || id.Address == "") {
		return store.AssetRef{}, ivInvalid(op, "no identity")
	}
	for _, s := range []string{id.AgentID, id.ScannerID, id.ScanTargetID} {
		if s != "" && !ivValidID(s) {
			return store.AssetRef{}, ivInvalid(op, "malformed id")
		}
	}
	s, err := requireScope(ctx, op)
	if err != nil {
		return store.AssetRef{}, err
	}
	var ref store.AssetRef
	err = d.ivAtomic(ctx, func(d *DB) error {
		// Lock every identity key in a fixed order so concurrent reports
		// of the same host do not create two assets.
		var keys []string
		if id.AgentID != "" {
			keys = append(keys, "agent:"+id.AgentID)
		}
		if id.ScanTargetID != "" {
			keys = append(keys, "target:"+id.ScanTargetID)
		}
		if id.MachineID != "" {
			keys = append(keys, "machine:"+id.MachineID)
		}
		if id.ScannerID != "" && id.Address != "" {
			keys = append(keys, "scan:"+id.ScannerID+"|"+id.Address)
		}
		for _, k := range keys {
			if err := d.ivLock(ctx, "asset-identity:"+k); err != nil {
				return err
			}
		}
		scopeID, err := d.ivHostScope(ctx, id)
		if err != nil {
			return ivErr(op, err)
		}
		if err := checkScope(op, s, scopeID); err != nil {
			return err
		}
		var found string
		if id.ScanTargetID != "" {
			linked, err := d.ivScanTargetAsset(ctx, id.ScanTargetID)
			if err != nil {
				return ivErr(op, err)
			}
			if id.AgentID == "" {
				found = linked
			}
		}
		if found == "" {
			var err error
			if found, err = d.ivFindHost(ctx, id, scopeID); err != nil {
				return ivErr(op, err)
			}
		}
		if found != "" {
			ref.ID = found
			_, err := d.q.Exec(ctx, `
				UPDATE assets SET
					agent_id = COALESCE(agent_id, $2::uuid),
					machine_id = COALESCE($3, machine_id),
					scanner_id = COALESCE(scanner_id, $4::uuid),
					address = CASE WHEN address = '' THEN $5 ELSE address END
				WHERE id = $1`,
				found, ivNull(id.AgentID), ivNull(id.MachineID), ivNull(id.ScannerID), id.Address)
			if err != nil {
				return ivErr(op, err)
			}
		} else {
			ref.ID = ivNewID()
			ref.Created = true
			at := ivAt(init.SeenAt)
			_, err := d.q.Exec(ctx, `
				INSERT INTO assets (id, kind, name, group_name, tags, method, address,
					agent_id, machine_id, scanner_id, first_seen, last_seen, scope_id)
				VALUES ($1, 'host', $2, $3, $4, $5, $6, $7, $8, $9, $10, $10, $11)`,
				ref.ID, init.Name, init.Group, ivSortedUnique(init.Tags), string(init.Method), id.Address,
				ivNull(id.AgentID), ivNull(id.MachineID), ivNull(id.ScannerID), at, scopeID)
			if err != nil {
				return ivErr(op, err)
			}
		}
		if id.ScanTargetID != "" {
			if _, err := d.q.Exec(ctx, `
				UPDATE scan_targets SET asset_id = $2 WHERE id = $1 AND asset_id IS DISTINCT FROM $2`,
				id.ScanTargetID, ref.ID); err != nil {
				return ivErr(op, err)
			}
		}
		if id.MachineID != "" {
			err := d.q.QueryRow(ctx, `
				SELECT EXISTS (SELECT 1 FROM assets
					WHERE machine_id = $1 AND kind = 'host' AND id <> $2 AND scope_id = $3)`,
				id.MachineID, ref.ID, scopeID).Scan(&ref.DuplicateMachineID)
			if err != nil {
				return ivErr(op, err)
			}
		}
		return nil
	})
	return ref, err
}

// ivHostScope is the scope id of a host asset with identity id: that of
// its agent (the default scope for a scanner or an unknown agent), else
// that of its scan target, else the default scope. It is read from the
// parent row whether or not the caller sees it; the caller checks it
// against its scope.
func (d *DB) ivHostScope(ctx context.Context, id store.HostIdentity) (string, error) {
	var out string
	switch {
	case id.AgentID != "":
		err := d.q.QueryRow(ctx, `SELECT coalesce(scope_id, '') FROM agents WHERE id = $1`, id.AgentID).Scan(&out)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return "", err
		}
	case id.ScanTargetID != "":
		if err := d.q.QueryRow(ctx, `SELECT scope_id FROM scan_targets WHERE id = $1`, id.ScanTargetID).Scan(&out); err != nil {
			return "", err
		}
	}
	if out == "" {
		out = scope.Default
	}
	return out, nil
}

// ivScanTargetAsset returns the host asset linked to a scan target, or "".
// ErrNoRows when the target does not exist.
func (d *DB) ivScanTargetAsset(ctx context.Context, targetID string) (string, error) {
	var found string
	err := d.q.QueryRow(ctx, `
		SELECT COALESCE(a.id::text, '') FROM scan_targets t
		LEFT JOIN assets a ON a.id = t.asset_id AND a.kind = 'host'
		WHERE t.id = $1`, targetID).Scan(&found)
	return found, err
}

// ivFindHost returns the asset id for id in the scope scopeID, or "".
// Hosts of different scopes are never merged.
func (d *DB) ivFindHost(ctx context.Context, id store.HostIdentity, scopeID string) (string, error) {
	var found string
	scan := func(sql string, args ...any) error {
		err := d.q.QueryRow(ctx, sql, append(args, scopeID)...).Scan(&found)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}
	if id.AgentID != "" {
		if err := scan(`SELECT id::text FROM assets WHERE agent_id = $1 AND scope_id = $2`, id.AgentID); err != nil || found != "" {
			return found, err
		}
		if id.MachineID == "" {
			return "", nil
		}
		// A new agent takes over an agentless asset of the same machine.
		err := scan(`
			SELECT id::text FROM assets
			WHERE machine_id = $1 AND kind = 'host' AND agent_id IS NULL AND scope_id = $2
			ORDER BY first_seen, id LIMIT 1`, id.MachineID)
		return found, err
	}
	if id.MachineID != "" {
		err := scan(`
			SELECT id::text FROM assets
			WHERE machine_id = $1 AND kind = 'host' AND scope_id = $4
			ORDER BY (scanner_id IS NOT DISTINCT FROM $2::uuid AND address = $3) DESC, first_seen, id
			LIMIT 1`, id.MachineID, ivNull(id.ScannerID), id.Address)
		if err != nil || found != "" || id.ScannerID == "" {
			return found, err
		}
	}
	if id.ScannerID == "" || id.Address == "" {
		return "", nil
	}
	err := scan(`
		SELECT id::text FROM assets
		WHERE scanner_id = $1 AND address = $2 AND kind = 'host' AND agent_id IS NULL
		  AND (machine_id IS NULL OR $3::text IS NULL OR machine_id = $3) AND scope_id = $4
		ORDER BY first_seen, id LIMIT 1`, id.ScannerID, id.Address, ivNull(id.MachineID))
	return found, err
}

// UpsertWorkloadAsset implements store.AssetIngest.
func (d *DB) UpsertWorkloadAsset(ctx context.Context, id store.WorkloadIdentity, init store.AssetInit) (store.AssetRef, error) {
	const op = "upsert workload asset"
	if !ivValidID(id.ClusterID) || id.Namespace == "" || id.Kind == "" || id.Name == "" {
		return store.AssetRef{}, ivInvalid(op, "incomplete workload identity")
	}
	name := init.Name
	if name == "" {
		name = id.Name
	}
	method := init.Method
	if method == "" {
		method = store.CollectK8sInventory
	}
	at := ivAt(init.SeenAt)
	ref := store.AssetRef{}
	if err := d.ivScopeCluster(ctx, op, id.ClusterID); err != nil {
		return ref, err
	}
	err := d.q.QueryRow(ctx, `
		INSERT INTO assets (id, kind, name, group_name, tags, method, cluster_id, namespace,
			workload_kind, workload_name, first_seen, last_seen, scope_id)
		VALUES ($1, 'workload', $2, $3, $4, $5, $6, $7, $8, $9, $10, $10,
			(SELECT k.scope_id FROM k8s_clusters k WHERE k.id = $6))
		ON CONFLICT (cluster_id, namespace, workload_kind, workload_name) WHERE kind = 'workload'
		DO UPDATE SET gone_at = NULL, last_seen = GREATEST(assets.last_seen, EXCLUDED.last_seen)
		RETURNING id::text, xmax = 0`,
		ivNewID(), name, init.Group, ivSortedUnique(init.Tags), string(method), id.ClusterID,
		id.Namespace, id.Kind, id.Name, at).Scan(&ref.ID, &ref.Created)
	return ref, ivErr(op, err)
}

// UpdateAssetFacts implements store.AssetIngest.
func (d *DB) UpdateAssetFacts(ctx context.Context, assetID string, f store.AssetFacts) error {
	const op = "update asset facts"
	if !ivValidID(assetID) {
		return ivNotFound(op)
	}
	var tags []string
	if f.Tags != nil {
		tags = ivSortedUnique(f.Tags)
	}
	setOS := f.OS != (store.OSInfo{})
	q, sc, err := scoped(ctx, op, assetID, f.Name, f.Group, tags, setOS, f.OS.Family, f.OS.ID, f.OS.Name, f.OS.Version,
		f.Kernel, f.Arch, f.Address, string(f.Method), string(f.Privilege), string(f.Coverage),
		f.CoverageReason, ivTimeOrNil(f.SeenAt))
	if err != nil {
		return err
	}
	tag, err := d.q.Exec(ctx, `
		UPDATE assets SET
			name = COALESCE(NULLIF($2, ''), name),
			group_name = COALESCE(NULLIF($3, ''), group_name),
			tags = COALESCE($4::text[], tags),
			os_family = CASE WHEN $5 THEN $6 ELSE os_family END,
			os_id = CASE WHEN $5 THEN $7 ELSE os_id END,
			os_name = CASE WHEN $5 THEN $8 ELSE os_name END,
			os_version = CASE WHEN $5 THEN $9 ELSE os_version END,
			kernel = COALESCE(NULLIF($10, ''), kernel),
			arch = COALESCE(NULLIF($11, ''), arch),
			address = COALESCE(NULLIF($12, ''), address),
			method = COALESCE(NULLIF($13, ''), method),
			privilege = COALESCE(NULLIF($14, ''), privilege),
			coverage = COALESCE(NULLIF($15, ''), coverage),
			coverage_reason = CASE WHEN $15 <> '' THEN $16 ELSE coverage_reason END,
			first_seen = LEAST(first_seen, COALESCE($17, first_seen)),
			last_seen = GREATEST(last_seen, COALESCE($17, last_seen)),
			gone_at = CASE WHEN $17::timestamptz IS NULL THEN gone_at END,
			collect_requested_at = CASE WHEN collect_requested_at <= $17::timestamptz THEN NULL
				ELSE collect_requested_at END
		WHERE id = $1 AND `+sc.col("scope_id"), q.args...)
	if err != nil {
		return ivErr(op, err)
	}
	if tag.RowsAffected() == 0 {
		return ivNotFound(op)
	}
	return nil
}

// SetSectionStates implements store.AssetIngest.
func (d *DB) SetSectionStates(ctx context.Context, assetID string, states []store.SectionState) error {
	const op = "set section states"
	if !ivValidID(assetID) {
		return ivNotFound(op)
	}
	if err := d.ivScopeAsset(ctx, op, assetID); err != nil {
		return err
	}
	if len(states) == 0 {
		return nil
	}
	type row struct {
		Container   string    `json:"container"`
		Section     string    `json:"section"`
		Coverage    string    `json:"coverage"`
		Reason      string    `json:"reason"`
		Digest      string    `json:"digest"`
		CollectedAt time.Time `json:"collected_at"`
	}
	rows := make([]row, len(states))
	for i, s := range states {
		rows[i] = row{s.Container, s.Section, string(s.Coverage), s.Reason, s.Digest, ivAt(s.CollectedAt)}
	}
	js, err := ivJSON(rows)
	if err != nil {
		return err
	}
	_, err = d.q.Exec(ctx, `
		INSERT INTO asset_sections (asset_id, container, section, coverage, reason, digest, collected_at,
			baseline_coverage)
		SELECT DISTINCT ON (x.container, x.section) $1, x.container, x.section, x.coverage, x.reason, x.digest,
			x.collected_at, x.coverage
		FROM jsonb_to_recordset($2::jsonb) AS x(container text, section text, coverage text, reason text,
			digest text, collected_at timestamptz)
		ORDER BY x.container, x.section, x.collected_at DESC
		ON CONFLICT (asset_id, container, section) DO UPDATE SET
			coverage = EXCLUDED.coverage, reason = EXCLUDED.reason, digest = EXCLUDED.digest,
			collected_at = EXCLUDED.collected_at,
			baseline_coverage = CASE
				WHEN `+ivRankSQL("EXCLUDED.coverage")+` >= `+ivRankSQL("asset_sections.baseline_coverage")+`
				THEN EXCLUDED.coverage ELSE asset_sections.baseline_coverage END`, assetID, js)
	return ivErr(op, err)
}

// ivRankSQL is store.CoverageRank of the SQL expression expr.
func ivRankSQL(expr string) string {
	return `(CASE ` + expr + ` WHEN 'full' THEN 3 WHEN 'partial' THEN 2 WHEN 'process_only' THEN 1 ELSE 0 END)`
}

const ivAssetCols = `a.id::text, a.kind, a.name, a.group_name, a.tags, a.os_family, a.os_id, a.os_name,
	a.os_version, a.kernel, a.arch, a.address, a.method, a.coverage, a.coverage_reason, a.privilege,
	COALESCE(a.agent_id::text, ''), COALESCE(a.machine_id, ''), COALESCE(a.scanner_id::text, ''),
	COALESCE(a.cluster_id::text, ''), COALESCE(k.name, ''), COALESCE(a.namespace, ''),
	COALESCE(a.workload_kind, ''), COALESCE(a.workload_name, ''), a.first_seen, a.last_seen, a.gone_at,
	(a.machine_id IS NOT NULL AND EXISTS (SELECT 1 FROM assets o
		WHERE o.machine_id = a.machine_id AND o.kind = 'host' AND o.id <> a.id AND o.scope_id = a.scope_id)),
	COALESCE((SELECT t.id::text FROM scan_targets t WHERE t.asset_id = a.id ORDER BY t.created_at, t.id LIMIT 1), ''),
	a.collect_requested_at, a.scope_id`

// ivImagesCol lists the distinct image references of the current
// containers of asset alias a.
const ivImagesCol = `ARRAY(SELECT DISTINCT ct.image_ref FROM asset_containers ct
	WHERE ct.asset_id = a.id AND ct.gone_at IS NULL AND ct.image_ref <> '' ORDER BY 1)`

// ivAssetRowCols are the columns of a store.AssetRow of asset alias a and
// cluster alias k, scanned by ivAssetRowDest.
const ivAssetRowCols = ivAssetCols + `, (SELECT count(*) FROM asset_containers ct
	WHERE ct.asset_id = a.id AND ct.gone_at IS NULL), ` + ivImagesCol

func ivAssetDest(a *store.Asset) []any {
	return []any{&a.ID, &a.Kind, &a.Name, &a.Group, &a.Tags, &a.OS.Family, &a.OS.ID, &a.OS.Name,
		&a.OS.Version, &a.Kernel, &a.Arch, &a.Address, &a.Method, &a.Coverage, &a.CoverageReason,
		&a.Privilege, &a.AgentID, &a.MachineID, &a.ScannerID, &a.ClusterID, &a.ClusterName,
		&a.Namespace, &a.WorkloadKind, &a.WorkloadName, &a.FirstSeen, &a.LastSeen, &a.GoneAt,
		&a.DuplicateMachineID, &a.ScanTargetID, &a.CollectRequestedAt, &a.ScopeID}
}

func ivAssetRowDest(r *store.AssetRow) []any {
	return append(ivAssetDest(&r.Asset), &r.Containers, &r.Images)
}

func ivFixAsset(a *store.Asset) {
	a.FirstSeen = a.FirstSeen.UTC()
	a.LastSeen = a.LastSeen.UTC()
	a.GoneAt = ivUTC(a.GoneAt)
	a.CollectRequestedAt = ivUTC(a.CollectRequestedAt)
}

func ivFixAssetRow(r *store.AssetRow) {
	ivFixAsset(&r.Asset)
	r.Images = ivStrings(r.Images)
}

// ListAssets implements store.InventoryQuery.
func (d *DB) ListAssets(ctx context.Context, f store.AssetFilter, p store.Page) ([]store.AssetRow, int, error) {
	const op = "list assets"
	order, err := ivOrder(op, f.Sort, "name", map[string]string{
		"name":       "a.name",
		"kind":       "a.kind",
		"os":         "a.os_name",
		"group":      "a.group_name",
		"method":     "a.method",
		"coverage":   "a.coverage",
		"containers": "a.containers",
		"first_seen": "a.first_seen",
		"last_seen":  "a.last_seen",
	}, "a.id")
	if err != nil {
		return nil, 0, err
	}
	q, sc, err := scoped(ctx, op)
	if err != nil {
		return nil, 0, err
	}
	q.and(sc.col("a.scope_id"))
	if f.ScopeID != "" {
		q.where("a.scope_id = %s", f.ScopeID)
	}
	if !f.IncludeGone {
		q.where("a.gone_at IS NULL")
	}
	if f.Kind != "" {
		q.where("a.kind = %s", string(f.Kind))
	}
	if f.Group != "" {
		q.where("a.group_name = %s", f.Group)
	}
	if f.Method != "" {
		q.where("a.method = %s", string(f.Method))
	}
	switch f.Coverage {
	case "":
	case store.CoverageLimited:
		q.where("a.coverage <> 'full'")
	default:
		q.where("a.coverage = %s", string(f.Coverage))
	}
	if f.ClusterID != "" {
		if !ivValidID(f.ClusterID) {
			return nil, 0, nil
		}
		q.where("a.cluster_id = %s", f.ClusterID)
	}
	if f.Tag != "" {
		q.where("a.tags @> ARRAY[%s]::text[]", f.Tag)
	}
	if f.Q != "" {
		q.where(`(a.name ILIKE %[1]s OR a.address ILIKE %[1]s OR a.os_name ILIKE %[1]s
			OR a.os_version ILIKE %[1]s OR array_to_string(a.tags, ' ') ILIKE %[1]s
			OR EXISTS (SELECT 1 FROM asset_containers ct WHERE ct.asset_id = a.id
				AND ct.gone_at IS NULL AND ct.image_ref ILIKE %[1]s))`, ivLike(f.Q))
	}
	from := `FROM (SELECT a.*, (SELECT count(*) FROM asset_containers ct
			WHERE ct.asset_id = a.id AND ct.gone_at IS NULL) AS containers FROM assets a) a
		LEFT JOIN k8s_clusters k ON k.id = a.cluster_id` + q.whereSQL()
	var out []store.AssetRow
	total, err := ivPage(ctx, d, op, q, ivAssetCols+", a.containers, "+ivImagesCol, from, order, p, func(rows pgx.Rows) error {
		var r store.AssetRow
		if err := rows.Scan(ivAssetRowDest(&r)...); err != nil {
			return err
		}
		ivFixAssetRow(&r)
		out = append(out, r)
		return nil
	})
	return out, total, err
}

// ListAssetGroups implements store.InventoryQuery.
func (d *DB) ListAssetGroups(ctx context.Context, f store.AssetGroupFilter, p store.Page) ([]store.AssetGroupRow, int, error) {
	const op = "list asset groups"
	order, err := ivOrder(op, f.Sort, "name", map[string]string{
		"name":   "g.name",
		"assets": "g.assets",
	}, "g.name")
	if err != nil {
		return nil, 0, err
	}
	q, sc, err := scoped(ctx, op)
	if err != nil {
		return nil, 0, err
	}
	if f.Q != "" {
		q.where("g.name ILIKE %s", ivLike(f.Q))
	}
	from := `FROM (SELECT a.group_name AS name, count(*) AS assets FROM assets a
		WHERE a.gone_at IS NULL AND a.group_name <> '' AND ` + sc.col("a.scope_id") + ` GROUP BY a.group_name) g` + q.whereSQL()
	var out []store.AssetGroupRow
	total, err := ivPage(ctx, d, op, q, "g.name, g.assets", from, order, p, func(rows pgx.Rows) error {
		var r store.AssetGroupRow
		if err := rows.Scan(&r.Name, &r.Assets); err != nil {
			return err
		}
		out = append(out, r)
		return nil
	})
	return out, total, err
}

// MarkCollectRequested implements store.AssetRequests.
func (d *DB) MarkCollectRequested(ctx context.Context, assetID string, at time.Time) error {
	const op = "mark collect requested"
	q, sc, err := scoped(ctx, op, assetID, ivAt(at))
	if err != nil {
		return err
	}
	if !ivValidID(assetID) {
		return ivNotFound(op)
	}
	tag, err := d.q.Exec(ctx, `UPDATE assets SET collect_requested_at = $2 WHERE id = $1 AND `+sc.col("scope_id"), q.args...)
	if err != nil {
		return ivErr(op, err)
	}
	if tag.RowsAffected() == 0 {
		return ivNotFound(op)
	}
	return nil
}

// GetAsset implements store.InventoryQuery.
func (d *DB) GetAsset(ctx context.Context, id string) (store.AssetDetail, error) {
	const op = "get asset"
	var out store.AssetDetail
	q, sc, err := scoped(ctx, op, id)
	if err != nil {
		return out, err
	}
	if !ivValidID(id) {
		return out, ivNotFound(op)
	}
	err = d.q.QueryRow(ctx, `SELECT `+ivAssetCols+` FROM assets a
		LEFT JOIN k8s_clusters k ON k.id = a.cluster_id WHERE a.id = $1 AND `+sc.col("a.scope_id"), q.args...).
		Scan(ivAssetDest(&out.Asset)...)
	if err != nil {
		return out, ivErr(op, err)
	}
	ivFixAsset(&out.Asset)

	rows, err := d.q.Query(ctx, `
		SELECT container, section, coverage, reason, digest, collected_at, baseline_coverage
		FROM asset_sections WHERE asset_id = $1 ORDER BY container, section`, id)
	if err != nil {
		return out, ivErr(op, err)
	}
	for rows.Next() {
		var s store.SectionState
		if err := rows.Scan(&s.Container, &s.Section, &s.Coverage, &s.Reason, &s.Digest, &s.CollectedAt, &s.Baseline); err != nil {
			rows.Close()
			return out, ivErr(op, err)
		}
		s.CollectedAt = s.CollectedAt.UTC()
		out.Sections = append(out.Sections, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, ivErr(op, err)
	}

	if out.Kind == store.AssetWorkload {
		err := d.q.QueryRow(ctx, `
			SELECT id::text, replicas FROM k8s_workloads WHERE asset_id = $1
			ORDER BY gone_at IS NOT NULL, last_seen DESC, id LIMIT 1`, id).Scan(&out.WorkloadID, &out.Replicas)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return out, ivErr(op, err)
		}
	}

	out.Containers, err = d.ivContainers(ctx, `ct.asset_id = $1`, id)
	return out, ivErr(op, err)
}

// Dashboard implements store.InventoryQuery.
func (d *DB) Dashboard(ctx context.Context) (store.InventoryCounts, error) {
	const op = "dashboard"
	out := store.InventoryCounts{AssetsByCoverage: map[store.Coverage]int{}}
	q, sc, err := scoped(ctx, op)
	if err != nil {
		return out, err
	}
	rows, err := d.q.Query(ctx, `SELECT kind, coverage, count(*) FROM assets a WHERE gone_at IS NULL AND `+
		sc.col("a.scope_id")+` GROUP BY kind, coverage`, q.args...)
	if err != nil {
		return out, ivErr(op, err)
	}
	for rows.Next() {
		var kind store.AssetKind
		var c store.Coverage
		var n int
		if err := rows.Scan(&kind, &c, &n); err != nil {
			rows.Close()
			return out, ivErr(op, err)
		}
		out.AssetsByCoverage[c] += n
		out.Assets += n
		if kind == store.AssetWorkload {
			out.Workloads += n
		} else {
			out.Hosts += n
		}
		if c != store.CoverageFull {
			out.LimitedCoverage += n
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, ivErr(op, err)
	}
	err = d.q.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM processes p JOIN assets a ON a.id = p.asset_id
				WHERE a.gone_at IS NULL AND p.needs_restart AND `+sc.col("a.scope_id")+`),
			(SELECT count(*) FROM processes p JOIN assets a ON a.id = p.asset_id
				WHERE a.gone_at IS NULL AND p.suspicious AND `+sc.col("a.scope_id")+`),
			(SELECT count(*) FROM components c WHERE `+sc.component("c.id")+`),
			(SELECT count(*) FROM images i WHERE `+sc.image("i.digest")+`),
			(SELECT count(*) FROM k8s_clusters k WHERE `+sc.col("k.scope_id")+`)`, q.args...).
		Scan(&out.NeedsRestart, &out.Suspicious, &out.Components, &out.Images, &out.Clusters)
	return out, ivErr(op, err)
}

// PurgeGone implements store.InventoryRetention.
func (d *DB) PurgeGone(ctx context.Context, before time.Time) (store.PurgeResult, error) {
	const op = "purge gone"
	var out store.PurgeResult
	if err := requireAll(ctx, op); err != nil {
		return out, err
	}
	err := d.ivAtomic(ctx, func(d *DB) error {
		for _, s := range []struct {
			sql string
			n   *int64
		}{
			{`DELETE FROM k8s_pods WHERE gone_at < $1`, &out.Pods},
			{`DELETE FROM k8s_workloads WHERE gone_at < $1`, &out.Workloads},
			{`DELETE FROM asset_containers WHERE gone_at < $1`, &out.Containers},
			{`DELETE FROM assets WHERE gone_at < $1`, &out.Assets},
			// Images that no container row refers to, gone or not, and that
			// were not seen since the cutoff. Rows are locked in digest
			// order like ingest does, and last_seen is re-checked on the
			// locked row: an ingest that touched the image first keeps it,
			// one that comes after re-creates the row. image_components and
			// image_tags go with the delete.
			{`DELETE FROM images WHERE digest IN (
				SELECT i.digest FROM images i WHERE i.last_seen < $1
				AND NOT EXISTS (SELECT 1 FROM asset_containers ct WHERE ct.image_digest = i.digest)
				AND NOT EXISTS (SELECT 1 FROM asset_containers ct WHERE ct.previous_digest = i.digest)
				AND NOT EXISTS (SELECT 1 FROM k8s_pod_containers pc WHERE pc.image_digest = i.digest)
				ORDER BY i.digest FOR UPDATE OF i)`, &out.Images},
		} {
			tag, err := d.q.Exec(ctx, s.sql, before.UTC())
			if err != nil {
				return ivErr(op, err)
			}
			*s.n = tag.RowsAffected()
		}
		return nil
	})
	return out, err
}
