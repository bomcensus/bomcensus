// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

func ivClusterArgs(op string, c store.K8sClusterConfig) (filter string, err error) {
	if c.Name == "" {
		return "", ivInvalid(op, "empty name")
	}
	if c.Connection != store.K8sInCluster && c.Connection != store.K8sKubeconfig {
		return "", ivInvalid(op, "unknown connection")
	}
	for _, id := range []string{c.CredentialID, c.ScannerID} {
		if id != "" && !ivValidID(id) {
			return "", ivInvalid(op, "malformed id")
		}
	}
	f := c.Filter
	for _, s := range []*[]string{&f.NSInclude, &f.NSExclude, &f.LabelInclude, &f.LabelExclude,
		&f.AnnotationInclude, &f.AnnotationExclude} {
		*s = ivStrings(*s)
	}
	return ivJSON(f)
}

// CreateCluster implements store.K8sClusters.
func (d *DB) CreateCluster(ctx context.Context, c store.K8sClusterConfig) (store.K8sCluster, error) {
	const op = "create cluster"
	filter, err := ivClusterArgs(op, c)
	if err != nil {
		return store.K8sCluster{}, err
	}
	s, err := requireScope(ctx, op)
	if err != nil {
		return store.K8sCluster{}, err
	}
	if c.ScopeID, err = resolveScope(op, s, c.ScopeID); err != nil {
		return store.K8sCluster{}, err
	}
	if err := d.mgCredentialIn(ctx, op, c.CredentialID, c.ScopeID); err != nil {
		return store.K8sCluster{}, err
	}
	id := ivNewID()
	now := ivNow()
	_, err = d.q.Exec(ctx, `
		INSERT INTO k8s_clusters (id, name, connection, credential_id, scanner_id, exec_enabled, filter,
			created_at, updated_at, scope_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $8, $9)`,
		id, c.Name, string(c.Connection), ivNull(c.CredentialID), ivNull(c.ScannerID), c.ExecEnabled, filter, now,
		c.ScopeID)
	if err != nil {
		return store.K8sCluster{}, ivErr(op, err)
	}
	return d.GetCluster(ctx, id)
}

// ivClusterFrom adds the workload counts to the clusters (alias c).
const ivClusterFrom = `FROM (SELECT c.*,
		(SELECT count(*) FROM k8s_workloads w WHERE w.cluster_id = c.id AND w.gone_at IS NULL) AS workloads,
		(SELECT count(*) FROM k8s_workloads w WHERE w.cluster_id = c.id AND w.gone_at IS NULL AND w.excluded) AS excluded
	FROM k8s_clusters c) c`

const ivClusterCols = `c.id::text, c.name, c.connection, COALESCE(c.credential_id::text, ''),
	COALESCE(c.scanner_id::text, ''), c.exec_enabled, c.filter, c.version, c.last_sync, c.sync_status,
	c.sync_message, c.workloads, c.excluded, c.created_at, c.updated_at, c.scope_id`

func ivScanCluster(row pgx.Row, extra ...any) (store.K8sCluster, error) {
	var c store.K8sCluster
	var filter []byte
	dest := []any{&c.ID, &c.Name, &c.Connection, &c.CredentialID, &c.ScannerID, &c.ExecEnabled, &filter,
		&c.Version, &c.LastSync, &c.SyncStatus, &c.SyncMessage, &c.Workloads, &c.Excluded, &c.CreatedAt, &c.UpdatedAt,
		&c.ScopeID}
	if err := row.Scan(append(dest, extra...)...); err != nil {
		return c, err
	}
	if err := json.Unmarshal(filter, &c.Filter); err != nil {
		return c, fmt.Errorf("filter: %w", err)
	}
	c.LastSync = ivUTC(c.LastSync)
	c.CreatedAt = c.CreatedAt.UTC()
	c.UpdatedAt = c.UpdatedAt.UTC()
	return c, nil
}

// GetCluster implements store.K8sClusters.
func (d *DB) GetCluster(ctx context.Context, id string) (store.K8sCluster, error) {
	const op = "get cluster"
	q, sc, err := scoped(ctx, op, id)
	if err != nil {
		return store.K8sCluster{}, err
	}
	if !ivValidID(id) {
		return store.K8sCluster{}, ivNotFound(op)
	}
	c, err := ivScanCluster(d.q.QueryRow(ctx, `SELECT `+ivClusterCols+` `+ivClusterFrom+` WHERE c.id = $1 AND `+
		sc.col("c.scope_id"), q.args...))
	return c, ivErr(op, err)
}

// RecordClusterSync implements store.K8sClusters.
func (d *DB) RecordClusterSync(ctx context.Context, id string, status store.K8sSyncStatus, message string, at time.Time) error {
	const op = "record cluster sync"
	if !ivValidID(id) {
		return ivNotFound(op)
	}
	switch status {
	case store.K8sSyncOK, store.K8sSyncFailed:
	default:
		return ivInvalid(op, "unknown sync status")
	}
	q, sc, err := scoped(ctx, op, id, string(status), message, ivAt(at))
	if err != nil {
		return err
	}
	cond := sc.col("scope_id")
	var one int
	err = d.q.QueryRow(ctx, `
		WITH upd AS (
			UPDATE k8s_clusters SET sync_status = $2, sync_message = $3, sync_status_at = $4
			WHERE id = $1 AND (sync_status_at IS NULL OR sync_status_at <= $4) AND `+cond+`
			RETURNING 1
		)
		SELECT 1 FROM k8s_clusters WHERE id = $1 AND `+cond, q.args...).Scan(&one)
	return ivErr(op, err)
}

// UpdateCluster implements store.K8sClusters.
func (d *DB) UpdateCluster(ctx context.Context, id string, c store.K8sClusterConfig) (store.K8sCluster, error) {
	const op = "update cluster"
	if !ivValidID(id) {
		return store.K8sCluster{}, ivNotFound(op)
	}
	filter, err := ivClusterArgs(op, c)
	if err != nil {
		return store.K8sCluster{}, err
	}
	cur, err := d.GetCluster(ctx, id)
	if err != nil {
		return store.K8sCluster{}, err
	}
	if err := d.mgCredentialIn(ctx, op, c.CredentialID, cur.ScopeID); err != nil {
		return store.K8sCluster{}, err
	}
	q, sc, err := scoped(ctx, op, id, c.Name, string(c.Connection), ivNull(c.CredentialID), ivNull(c.ScannerID),
		c.ExecEnabled, filter, ivNow())
	if err != nil {
		return store.K8sCluster{}, err
	}
	tag, err := d.q.Exec(ctx, `
		UPDATE k8s_clusters SET name = $2, connection = $3, credential_id = $4, scanner_id = $5,
			exec_enabled = $6, filter = $7::jsonb, updated_at = $8
		WHERE id = $1 AND `+sc.col("scope_id"), q.args...)
	if err != nil {
		return store.K8sCluster{}, ivErr(op, err)
	}
	if tag.RowsAffected() == 0 {
		return store.K8sCluster{}, ivNotFound(op)
	}
	return d.GetCluster(ctx, id)
}

// DeleteCluster implements store.K8sClusters.
func (d *DB) DeleteCluster(ctx context.Context, id string) error {
	const op = "delete cluster"
	q, sc, err := scoped(ctx, op, id)
	if err != nil {
		return err
	}
	if !ivValidID(id) {
		return ivNotFound(op)
	}
	tag, err := d.q.Exec(ctx, `DELETE FROM k8s_clusters WHERE id = $1 AND `+sc.col("scope_id"), q.args...)
	if err != nil {
		return ivErr(op, err)
	}
	if tag.RowsAffected() == 0 {
		return ivNotFound(op)
	}
	return nil
}

// ListClusters implements store.K8sClusters.
func (d *DB) ListClusters(ctx context.Context, f store.ClusterFilter, p store.Page) ([]store.K8sClusterRow, int, error) {
	const op = "list clusters"
	order, err := ivOrder(op, f.Sort, "name", map[string]string{
		"name":         "c.name",
		"version":      `version_sort_key('semver', c.version) COLLATE "C"`,
		"connection":   "c.connection",
		"exec_enabled": "c.exec_enabled",
		"workloads":    "c.workloads",
		"excluded":     "c.excluded",
		// Failed, then never synced, then synced.
		"sync_status": "CASE c.sync_status WHEN 'failed' THEN 0 WHEN 'never' THEN 1 ELSE 2 END",
		"last_sync":   "c.last_sync",
	}, "c.name, c.id")
	if err != nil {
		return nil, 0, err
	}
	q, sc, err := scoped(ctx, op)
	if err != nil {
		return nil, 0, err
	}
	q.and(sc.col("c.scope_id"))
	if f.Q != "" {
		q.where("(c.name ILIKE %[1]s OR c.version ILIKE %[1]s)", ivLike(f.Q))
	}
	if f.ScopeID != "" {
		q.where("c.scope_id = %s", f.ScopeID)
	}
	from := ivClusterFrom + q.whereSQL()
	var out []store.K8sClusterRow
	total, err := ivPage(ctx, d, op, q, ivClusterCols, from, order, p, func(rows pgx.Rows) error {
		c, err := ivScanCluster(rows)
		if err != nil {
			return err
		}
		out = append(out, store.K8sClusterRow{K8sCluster: c})
		return nil
	})
	return out, total, err
}

// ReplaceClusterInventory implements store.K8sIngest.
func (d *DB) ReplaceClusterInventory(ctx context.Context, clusterID string, inv store.K8sInventory) (store.K8sInventoryResult, error) {
	const op = "replace cluster inventory"
	var res store.K8sInventoryResult
	if !ivValidID(clusterID) {
		return res, ivNotFound(op)
	}
	at := ivAt(inv.At)

	type workloadRow struct {
		NewID      string `json:"new_id"`
		NewAssetID string `json:"new_asset_id"`
		Namespace  string `json:"namespace"`
		Kind       string `json:"kind"`
		Name       string `json:"name"`
		Replicas   int    `json:"replicas"`
		Excluded   bool   `json:"excluded"`
		ExcludedBy string `json:"excluded_by"`
	}
	type podRow struct {
		NewID     string     `json:"new_id"`
		UID       string     `json:"uid"`
		Namespace string     `json:"namespace"`
		WKind     string     `json:"wkind"`
		WName     string     `json:"wname"`
		Name      string     `json:"name"`
		Node      string     `json:"node"`
		Phase     string     `json:"phase"`
		StartedAt *time.Time `json:"started_at"`
	}
	type podContainerRow struct {
		Namespace   string `json:"namespace"`
		Pod         string `json:"pod"`
		Name        string `json:"name"`
		ImageRef    string `json:"image_ref"`
		ImageDigest string `json:"image_digest"`
	}
	workloads := map[[3]string]workloadRow{}
	pods := map[[2]string]podRow{}
	podContainers := map[[3]string]podContainerRow{}
	for _, w := range inv.Workloads {
		if w.Namespace == "" || w.Kind == "" || w.Name == "" {
			return res, ivInvalid(op, "incomplete workload")
		}
		workloads[[3]string{w.Namespace, w.Kind, w.Name}] = workloadRow{
			ivNewID(), ivNewID(), w.Namespace, w.Kind, w.Name, w.Replicas, w.Excluded, w.ExcludedBy,
		}
		for _, p := range w.Pods {
			if p.Name == "" {
				return res, ivInvalid(op, "pod without name")
			}
			pods[[2]string{w.Namespace, p.Name}] = podRow{
				ivNewID(), p.UID, w.Namespace, w.Kind, w.Name, p.Name, p.Node, p.Phase, ivTimeOrNil(p.StartedAt),
			}
			for _, c := range p.Containers {
				podContainers[[3]string{w.Namespace, p.Name, c.Name}] = podContainerRow{
					w.Namespace, p.Name, c.Name, c.ImageRef, c.ImageDigest,
				}
			}
		}
	}
	wRows := make([]workloadRow, 0, len(workloads))
	for _, r := range workloads {
		wRows = append(wRows, r)
	}
	sort.Slice(wRows, func(i, j int) bool {
		a, b := wRows[i], wRows[j]
		return a.Namespace+"\x00"+a.Kind+"\x00"+a.Name < b.Namespace+"\x00"+b.Kind+"\x00"+b.Name
	})
	pRows := make([]podRow, 0, len(pods))
	for _, r := range pods {
		pRows = append(pRows, r)
	}
	sort.Slice(pRows, func(i, j int) bool {
		return pRows[i].Namespace+"\x00"+pRows[i].Name < pRows[j].Namespace+"\x00"+pRows[j].Name
	})
	pcRows := make([]podContainerRow, 0, len(podContainers))
	for _, r := range podContainers {
		pcRows = append(pcRows, r)
	}
	wJS, err := ivJSON(wRows)
	if err != nil {
		return res, err
	}
	pJS, err := ivJSON(pRows)
	if err != nil {
		return res, err
	}
	pcJS, err := ivJSON(pcRows)
	if err != nil {
		return res, err
	}

	err = d.ivAtomic(ctx, func(d *DB) error {
		if err := d.ivLockCluster(ctx, op, clusterID); err != nil {
			return err
		}

		// Workloads.
		rows, err := d.q.Query(ctx, `
			INSERT INTO k8s_workloads (id, cluster_id, namespace, kind, name, replicas, excluded, excluded_by,
				first_seen, last_seen)
			SELECT x.new_id, $1, x.namespace, x.kind, x.name, x.replicas, x.excluded, x.excluded_by, $3, $3
			FROM jsonb_to_recordset($2::jsonb) AS x(new_id uuid, namespace text, kind text, name text,
				replicas integer, excluded boolean, excluded_by text)
			ORDER BY x.namespace, x.kind, x.name
			ON CONFLICT (cluster_id, namespace, kind, name) DO UPDATE SET
				replicas = EXCLUDED.replicas, excluded = EXCLUDED.excluded, excluded_by = EXCLUDED.excluded_by,
				last_seen = GREATEST(k8s_workloads.last_seen, EXCLUDED.last_seen), gone_at = NULL
			RETURNING id::text`, clusterID, wJS, at)
		if err != nil {
			return ivErr(op, err)
		}
		current, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return ivErr(op, err)
		}
		current = ivStrings(current)
		tag, err := d.q.Exec(ctx, `
			UPDATE k8s_workloads SET gone_at = $2
			WHERE cluster_id = $1 AND gone_at IS NULL AND id <> ALL($3::uuid[])`, clusterID, at, current)
		if err != nil {
			return ivErr(op, err)
		}
		res.GoneWorkloads = int(tag.RowsAffected())

		// Assets of the workloads that are not excluded.
		rows, err = d.q.Query(ctx, `
			INSERT INTO assets (id, kind, name, method, cluster_id, namespace, workload_kind, workload_name,
				first_seen, last_seen, scope_id)
			SELECT x.new_asset_id, 'workload', x.name, 'k8s_inventory', $1, x.namespace, x.kind, x.name, $3, $3,
				(SELECT k.scope_id FROM k8s_clusters k WHERE k.id = $1)
			FROM jsonb_to_recordset($2::jsonb) AS x(new_asset_id uuid, namespace text, kind text, name text,
				excluded boolean)
			WHERE NOT x.excluded
			ORDER BY x.namespace, x.kind, x.name
			ON CONFLICT (cluster_id, namespace, workload_kind, workload_name) WHERE kind = 'workload'
			DO UPDATE SET gone_at = NULL, last_seen = GREATEST(assets.last_seen, EXCLUDED.last_seen)
			RETURNING id::text, xmax = 0`, clusterID, wJS, at)
		if err != nil {
			return ivErr(op, err)
		}
		created := map[string]bool{}
		var assetIDs []string
		for rows.Next() {
			var id string
			var isNew bool
			if err := rows.Scan(&id, &isNew); err != nil {
				rows.Close()
				return ivErr(op, err)
			}
			created[id] = isNew
			assetIDs = append(assetIDs, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return ivErr(op, err)
		}
		sort.Strings(assetIDs)
		assetIDs = ivStrings(assetIDs)
		if _, err := d.q.Exec(ctx, `SELECT 1 FROM assets WHERE id = ANY($1::uuid[]) ORDER BY id FOR NO KEY UPDATE`, assetIDs); err != nil {
			return ivErr(op, err)
		}
		if _, err := d.q.Exec(ctx, `
			UPDATE k8s_workloads w SET asset_id = a.id
			FROM assets a
			WHERE w.cluster_id = $1 AND w.gone_at IS NULL AND NOT w.excluded
			  AND a.kind = 'workload' AND a.cluster_id = w.cluster_id AND a.namespace = w.namespace
			  AND a.workload_kind = w.kind AND a.workload_name = w.name
			  AND w.asset_id IS DISTINCT FROM a.id`, clusterID); err != nil {
			return ivErr(op, err)
		}
		if _, err := d.q.Exec(ctx, `
			UPDATE assets SET gone_at = $2
			WHERE cluster_id = $1 AND kind = 'workload' AND gone_at IS NULL AND id <> ALL($3::uuid[])`,
			clusterID, at, assetIDs); err != nil {
			return ivErr(op, err)
		}

		// Pods and their containers.
		rows, err = d.q.Query(ctx, `
			INSERT INTO k8s_pods (id, uid, cluster_id, workload_id, namespace, name, node, phase, started_at,
				first_seen, last_seen)
			SELECT x.new_id, COALESCE(x.uid, ''), $1, w.id, x.namespace, x.name, x.node, x.phase, x.started_at, $3, $3
			FROM jsonb_to_recordset($2::jsonb) AS x(new_id uuid, uid text, namespace text, wkind text, wname text,
				name text, node text, phase text, started_at timestamptz)
			JOIN k8s_workloads w ON w.cluster_id = $1 AND w.namespace = x.namespace AND w.kind = x.wkind
				AND w.name = x.wname
			ORDER BY x.namespace, x.name
			ON CONFLICT (cluster_id, namespace, name) DO UPDATE SET
				workload_id = EXCLUDED.workload_id, uid = EXCLUDED.uid, node = EXCLUDED.node, phase = EXCLUDED.phase,
				started_at = EXCLUDED.started_at,
				last_seen = GREATEST(k8s_pods.last_seen, EXCLUDED.last_seen), gone_at = NULL
			RETURNING id::text`, clusterID, pJS, at)
		if err != nil {
			return ivErr(op, err)
		}
		podIDs, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return ivErr(op, err)
		}
		podIDs = ivStrings(podIDs)
		if _, err := d.q.Exec(ctx, `
			UPDATE k8s_pods SET gone_at = $2
			WHERE cluster_id = $1 AND gone_at IS NULL AND id <> ALL($3::uuid[])`, clusterID, at, podIDs); err != nil {
			return ivErr(op, err)
		}
		const pcObs = `jsonb_to_recordset($2::jsonb) AS x(namespace text, pod text, name text, image_ref text,
			image_digest text)`
		if _, err := d.q.Exec(ctx, `
			DELETE FROM k8s_pod_containers pc USING k8s_pods p
			WHERE pc.pod_id = p.id AND p.cluster_id = $1 AND p.id = ANY($3::uuid[])
			  AND NOT EXISTS (SELECT 1 FROM `+pcObs+`
				WHERE x.namespace = p.namespace AND x.pod = p.name AND x.name = pc.name)`,
			clusterID, pcJS, podIDs); err != nil {
			return ivErr(op, err)
		}
		if _, err := d.q.Exec(ctx, `
			INSERT INTO k8s_pod_containers (pod_id, name, image_ref, image_digest)
			SELECT p.id, x.name, x.image_ref, x.image_digest
			FROM `+pcObs+`
			JOIN k8s_pods p ON p.cluster_id = $1 AND p.namespace = x.namespace AND p.name = x.pod
			ORDER BY p.id, x.name
			ON CONFLICT (pod_id, name) DO UPDATE SET
				image_ref = EXCLUDED.image_ref, image_digest = EXCLUDED.image_digest,
				coverage = CASE WHEN k8s_pod_containers.image_digest <> EXCLUDED.image_digest
					THEN 'inventory_only' ELSE k8s_pod_containers.coverage END,
				coverage_reason = CASE WHEN k8s_pod_containers.image_digest <> EXCLUDED.image_digest
					THEN '' ELSE k8s_pod_containers.coverage_reason END`, clusterID, pcJS); err != nil {
			return ivErr(op, err)
		}

		// Containers of the workload assets, derived from their pods.
		rows, err = d.q.Query(ctx, `
			SELECT DISTINCT ON (w.asset_id, pc.name) w.asset_id::text, pc.name, pc.image_ref, pc.image_digest,
				count(*) FILTER (WHERE p.phase = 'Running') OVER (PARTITION BY w.asset_id, pc.name)
			FROM k8s_workloads w
			JOIN k8s_pods p ON p.workload_id = w.id AND p.gone_at IS NULL
			JOIN k8s_pod_containers pc ON pc.pod_id = p.id
			WHERE w.cluster_id = $1 AND w.gone_at IS NULL AND NOT w.excluded AND w.asset_id IS NOT NULL
			ORDER BY w.asset_id, pc.name, (p.phase = 'Running') DESC, p.started_at DESC NULLS LAST, p.name`, clusterID)
		if err != nil {
			return ivErr(op, err)
		}
		var cRows []ivContainerRow
		for rows.Next() {
			r := ivContainerRow{Runtime: store.RuntimeKubernetes}
			if err := rows.Scan(&r.AssetID, &r.Name, &r.ImageRef, &r.ImageDigest, &r.Instances); err != nil {
				rows.Close()
				return ivErr(op, err)
			}
			cRows = append(cRows, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return ivErr(op, err)
		}
		if cRows == nil {
			cRows = []ivContainerRow{}
		}
		if err := d.ivReplaceContainers(ctx, assetIDs, cRows, at, false); err != nil {
			return ivErr(op, err)
		}

		if _, err := d.q.Exec(ctx, `
			UPDATE k8s_clusters SET version = COALESCE(NULLIF($2, ''), version), last_sync = $3,
				sync_status = CASE WHEN sync_status_at IS NULL OR sync_status_at <= $3 THEN 'ok' ELSE sync_status END,
				sync_message = CASE WHEN sync_status_at IS NULL OR sync_status_at <= $3 THEN '' ELSE sync_message END,
				sync_status_at = GREATEST(sync_status_at, $3)
			WHERE id = $1`,
			clusterID, inv.Version, at); err != nil {
			return ivErr(op, err)
		}
		if err := d.pdTouchClusterLinks(ctx, clusterID); err != nil {
			return ivErr(op, err)
		}

		rows, err = d.q.Query(ctx, `
			SELECT id::text, namespace, kind, name, excluded, COALESCE(asset_id::text, '')
			FROM k8s_workloads WHERE cluster_id = $1 AND gone_at IS NULL
			ORDER BY namespace, kind, name`, clusterID)
		if err != nil {
			return ivErr(op, err)
		}
		defer rows.Close()
		for rows.Next() {
			var w store.K8sWorkloadRef
			if err := rows.Scan(&w.ID, &w.Namespace, &w.Kind, &w.Name, &w.Excluded, &w.AssetID); err != nil {
				return ivErr(op, err)
			}
			if w.Excluded {
				w.AssetID = ""
			}
			w.AssetCreated = created[w.AssetID]
			res.Workloads = append(res.Workloads, w)
		}
		return ivErr(op, rows.Err())
	})
	if err != nil {
		return store.K8sInventoryResult{}, err
	}
	return res, nil
}

// SetPodContainerCoverage implements store.K8sIngest.
func (d *DB) SetPodContainerCoverage(ctx context.Context, clusterID, namespace, pod, container string, coverage store.Coverage, reason string) error {
	const op = "set pod container coverage"
	if !ivValidID(clusterID) {
		return ivNotFound(op)
	}
	if err := d.ivScopeCluster(ctx, op, clusterID); err != nil {
		return err
	}
	tag, err := d.q.Exec(ctx, `
		UPDATE k8s_pod_containers pc SET coverage = $5, coverage_reason = $6
		FROM k8s_pods p
		WHERE pc.pod_id = p.id AND p.cluster_id = $1 AND p.namespace = $2 AND p.name = $3 AND pc.name = $4`,
		clusterID, namespace, pod, container, string(coverage), reason)
	if err != nil {
		return ivErr(op, err)
	}
	if tag.RowsAffected() == 0 {
		return ivNotFound(op)
	}
	return nil
}

// ListWorkloads implements store.InventoryQuery.
func (d *DB) ListWorkloads(ctx context.Context, clusterID string, f store.WorkloadFilter, p store.Page) ([]store.K8sWorkloadRow, int, error) {
	const op = "list workloads"
	order, err := ivOrder(op, f.Sort, "namespace", map[string]string{
		"namespace": "w.namespace",
		"kind":      "w.kind",
		"name":      "w.name",
		"replicas":  "w.replicas",
		"pods":      "w.pods",
	}, "w.namespace, w.kind, w.name, w.id")
	if err != nil {
		return nil, 0, err
	}
	q, sc, err := scoped(ctx, op)
	if err != nil {
		return nil, 0, err
	}
	if !ivValidID(clusterID) {
		return nil, 0, nil
	}
	q.where("w.cluster_id = %s", clusterID)
	q.and(sc.cluster("w.cluster_id"))
	if !f.IncludeGone {
		q.where("w.gone_at IS NULL")
	}
	if f.Namespace != "" {
		q.where("w.namespace = %s", f.Namespace)
	}
	if f.Kind != "" {
		q.where("w.kind = %s", f.Kind)
	}
	if f.Excluded != nil {
		q.where("w.excluded = %s", *f.Excluded)
	}
	if f.Q != "" {
		q.where("(w.name ILIKE %[1]s OR w.namespace ILIKE %[1]s OR w.kind ILIKE %[1]s)", ivLike(f.Q))
	}
	from := `FROM (SELECT w.*,
			(SELECT count(*) FROM k8s_pods p WHERE p.workload_id = w.id AND p.gone_at IS NULL) AS pods
		FROM k8s_workloads w) w` + q.whereSQL()
	sel := `w.id::text, w.cluster_id::text, w.namespace, w.kind, w.name, w.replicas, COALESCE(w.asset_id::text, ''),
		w.excluded, w.excluded_by, w.first_seen, w.last_seen, w.gone_at, w.pods,
		ARRAY(SELECT DISTINCT pc.coverage FROM k8s_pods p JOIN k8s_pod_containers pc ON pc.pod_id = p.id
			WHERE p.workload_id = w.id AND p.gone_at IS NULL ORDER BY 1)`
	var out []store.K8sWorkloadRow
	total, err := ivPage(ctx, d, op, q, sel, from, order, p, func(rows pgx.Rows) error {
		var r store.K8sWorkloadRow
		var covs []string
		if err := rows.Scan(&r.ID, &r.ClusterID, &r.Namespace, &r.Kind, &r.Name, &r.Replicas, &r.AssetID,
			&r.Excluded, &r.ExcludedBy, &r.FirstSeen, &r.LastSeen, &r.GoneAt, &r.Pods, &covs); err != nil {
			return err
		}
		r.FirstSeen = r.FirstSeen.UTC()
		r.LastSeen = r.LastSeen.UTC()
		r.GoneAt = ivUTC(r.GoneAt)
		r.Coverages = make([]store.Coverage, len(covs))
		for i, c := range covs {
			r.Coverages[i] = store.Coverage(c)
		}
		out = append(out, r)
		return nil
	})
	return out, total, err
}

// ListWorkloadNamespaces implements store.InventoryQuery.
func (d *DB) ListWorkloadNamespaces(ctx context.Context, clusterID string) ([]store.WorkloadNamespace, error) {
	const op = "list workload namespaces"
	q, sc, err := scoped(ctx, op, clusterID)
	if err != nil {
		return nil, err
	}
	if !ivValidID(clusterID) {
		return nil, nil
	}
	rows, err := d.q.Query(ctx, `
		SELECT namespace, count(*) FROM k8s_workloads
		WHERE cluster_id = $1 AND gone_at IS NULL AND `+sc.cluster("cluster_id")+`
		GROUP BY namespace ORDER BY namespace`, q.args...)
	if err != nil {
		return nil, ivErr(op, err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (store.WorkloadNamespace, error) {
		var n store.WorkloadNamespace
		err := r.Scan(&n.Name, &n.Workloads)
		return n, err
	})
	if err != nil {
		return nil, ivErr(op, err)
	}
	return out, nil
}

// GetWorkload implements store.InventoryQuery.
func (d *DB) GetWorkload(ctx context.Context, id string) (store.K8sWorkload, error) {
	const op = "get workload"
	var w store.K8sWorkload
	q, sc, err := scoped(ctx, op, id)
	if err != nil {
		return w, err
	}
	if !ivValidID(id) {
		return w, ivNotFound(op)
	}
	err = d.q.QueryRow(ctx, `
		SELECT id::text, cluster_id::text, namespace, kind, name, replicas, COALESCE(asset_id::text, ''),
			excluded, excluded_by, first_seen, last_seen, gone_at
		FROM k8s_workloads WHERE id = $1 AND `+sc.cluster("cluster_id"), q.args...).
		Scan(&w.ID, &w.ClusterID, &w.Namespace, &w.Kind, &w.Name, &w.Replicas, &w.AssetID,
			&w.Excluded, &w.ExcludedBy, &w.FirstSeen, &w.LastSeen, &w.GoneAt)
	if err != nil {
		return w, ivErr(op, err)
	}
	w.FirstSeen = w.FirstSeen.UTC()
	w.LastSeen = w.LastSeen.UTC()
	w.GoneAt = ivUTC(w.GoneAt)
	return w, nil
}

// GetPod implements store.InventoryQuery.
func (d *DB) GetPod(ctx context.Context, clusterID, namespace, name string) (store.K8sPod, error) {
	const op = "get pod"
	if !ivValidID(clusterID) {
		return store.K8sPod{}, ivNotFound(op)
	}
	pods, _, err := d.ivPods(ctx, op, func(q *ivQuery) {
		q.where("p.cluster_id = %s AND p.namespace = %s AND p.name = %s", clusterID, namespace, name)
	}, store.PodFilter{IncludeGone: true}, store.Page{Limit: 1})
	if err != nil {
		return store.K8sPod{}, err
	}
	if len(pods) == 0 {
		return store.K8sPod{}, ivNotFound(op)
	}
	return pods[0], nil
}

// ListWorkloadPods implements store.InventoryQuery.
func (d *DB) ListWorkloadPods(ctx context.Context, workloadID string, f store.PodFilter, p store.Page) ([]store.K8sPod, int, error) {
	if !ivValidID(workloadID) {
		return nil, 0, nil
	}
	return d.ivPods(ctx, "list workload pods", func(q *ivQuery) { q.where("p.workload_id = %s", workloadID) }, f, p)
}

// ListAssetInstances implements store.InventoryQuery.
func (d *DB) ListAssetInstances(ctx context.Context, assetID string, f store.PodFilter, p store.Page) ([]store.K8sPod, int, error) {
	if !ivValidID(assetID) {
		return nil, 0, nil
	}
	return d.ivPods(ctx, "list asset instances", func(q *ivQuery) {
		q.where("p.workload_id IN (SELECT w.id FROM k8s_workloads w WHERE w.asset_id = %s)", assetID)
	}, f, p)
}

// ivPods lists the pods selected by the conditions that sel adds and f, in
// the clusters of the scope of ctx.
func (d *DB) ivPods(ctx context.Context, op string, by func(*ivQuery), f store.PodFilter, p store.Page) ([]store.K8sPod, int, error) {
	order, err := ivOrder(op, f.Sort, "name", map[string]string{
		"name":       "p.name",
		"node":       "p.node",
		"phase":      "p.phase",
		"started_at": "p.started_at",
	}, "p.namespace, p.name, p.id")
	if err != nil {
		return nil, 0, err
	}
	q, sc, err := scoped(ctx, op)
	if err != nil {
		return nil, 0, err
	}
	by(q)
	q.and(sc.cluster("p.cluster_id"))
	if !f.IncludeGone {
		q.where("p.gone_at IS NULL")
	}
	if f.Phase != "" {
		q.where("p.phase = %s", f.Phase)
	}
	if f.Q != "" {
		q.where("(p.name ILIKE %[1]s OR p.node ILIKE %[1]s)", ivLike(f.Q))
	}
	sel := `p.id::text, p.uid, p.workload_id::text, p.namespace, p.name, p.node, p.phase, p.started_at,
		p.first_seen, p.last_seen, p.gone_at,
		COALESCE((SELECT jsonb_agg(jsonb_build_object('name', pc.name, 'image_ref', pc.image_ref,
			'image_digest', pc.image_digest, 'coverage', pc.coverage, 'coverage_reason', pc.coverage_reason)
			ORDER BY pc.name) FROM k8s_pod_containers pc WHERE pc.pod_id = p.id), '[]')`
	var out []store.K8sPod
	total, err := ivPage(ctx, d, op, q, sel, "FROM k8s_pods p"+q.whereSQL(), order, p, func(rows pgx.Rows) error {
		var r store.K8sPod
		var cs []byte
		if err := rows.Scan(&r.ID, &r.UID, &r.WorkloadID, &r.Namespace, &r.Name, &r.Node, &r.Phase, &r.StartedAt,
			&r.FirstSeen, &r.LastSeen, &r.GoneAt, &cs); err != nil {
			return err
		}
		if err := json.Unmarshal(cs, &r.Containers); err != nil {
			return fmt.Errorf("pod containers: %w", err)
		}
		r.StartedAt = ivUTC(r.StartedAt)
		r.FirstSeen = r.FirstSeen.UTC()
		r.LastSeen = r.LastSeen.UTC()
		r.GoneAt = ivUTC(r.GoneAt)
		out = append(out, r)
		return nil
	})
	return out, total, err
}
