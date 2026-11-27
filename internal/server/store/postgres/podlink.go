// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

// pdLinks links the containers that node agents report for pods to the
// workload assets of those pods: a current container of a current host
// with a pod uid, a current pod with that uid, its current workload that is
// not excluded, and that workload's current asset.
const pdLinks = `(SELECT hc.asset_id AS host_id, ha.name AS host_name, ha.last_seen AS host_seen,
		hc.name AS host_container, hc.runtime_id, hc.instances, hc.coverage, hc.coverage_reason,
		w.asset_id AS workload_id, p.cluster_id, p.namespace, p.name AS pod, hc.pod_container AS container
	FROM asset_containers hc
	JOIN assets ha ON ha.id = hc.asset_id AND ha.kind = 'host' AND ha.gone_at IS NULL
	JOIN k8s_pods p ON p.uid = hc.pod_uid AND p.gone_at IS NULL
	JOIN k8s_workloads w ON w.id = p.workload_id AND w.gone_at IS NULL AND NOT w.excluded
		AND w.asset_id IS NOT NULL
	JOIN assets wa ON wa.id = w.asset_id AND wa.gone_at IS NULL
	WHERE hc.pod_uid <> '' AND hc.pod_container <> '' AND hc.gone_at IS NULL)`

// pdLinkedContainers returns the containers of a host that belong to a
// workload asset.
func (d *DB) pdLinkedContainers(ctx context.Context, hostID string) ([]string, error) {
	rows, err := d.q.Query(ctx, `SELECT DISTINCT l.host_container FROM `+pdLinks+` l
		WHERE l.host_id = $1 ORDER BY 1`, hostID)
	if err != nil {
		return nil, err
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	return ivStrings(names), err
}

// pdContainerWorkloads fills the workload links of a host's containers,
// for workload assets in the scope of ctx.
func (d *DB) pdContainerWorkloads(ctx context.Context, op, hostID string, cs []store.Container) error {
	q, sc, err := scoped(ctx, op, hostID)
	if err != nil {
		return err
	}
	rows, err := d.q.Query(ctx, `
		SELECT DISTINCT ON (l.host_container) l.host_container, l.workload_id::text, a.name, l.pod
		FROM `+pdLinks+` l JOIN assets a ON a.id = l.workload_id
		WHERE l.host_id = $1 AND `+sc.col("a.scope_id")+`
		ORDER BY l.host_container, l.workload_id`, q.args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	links := map[string]*store.ContainerWorkload{}
	for rows.Next() {
		var name string
		var w store.ContainerWorkload
		if err := rows.Scan(&name, &w.AssetID, &w.Name, &w.Pod); err != nil {
			return err
		}
		links[name] = &w
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range cs {
		if cs[i].GoneAt == nil {
			cs[i].Workload = links[cs[i].Name]
		}
	}
	return nil
}

// pdNodeContainers returns the host containers of a workload's pods. A
// host that reported after freshSince is fresh.
func (d *DB) pdNodeContainers(ctx context.Context, workloadID string, freshSince time.Time) ([]store.FindingNodeContainer, error) {
	rows, err := d.q.Query(ctx, `
		SELECT DISTINCT l.container, l.pod, l.host_id::text, l.host_name, l.host_container, l.runtime_id,
			l.host_seen >= $2
		FROM `+pdLinks+` l WHERE l.workload_id = $1
		ORDER BY l.container, l.pod, l.host_id::text, l.host_container`, workloadID, freshSince)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.FindingNodeContainer
	for rows.Next() {
		var n store.FindingNodeContainer
		if err := rows.Scan(&n.Container, &n.Pod, &n.HostID, &n.HostName, &n.HostContainer, &n.RuntimeID, &n.Fresh); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// pdTouchHostLinks marks the findings of the workloads linked to a host's
// containers, now or before this change, out of date. Pods that are gone
// count too: the workload then loses what the host saw of them.
func (d *DB) pdTouchHostLinks(ctx context.Context, hostID string) error {
	_, err := d.q.Exec(ctx, `
		INSERT INTO asset_findings_state (asset_id, vulns_version)
		SELECT DISTINCT w.asset_id, 1
		FROM asset_containers hc
		JOIN k8s_pods p ON p.uid = hc.pod_uid
		JOIN k8s_workloads w ON w.id = p.workload_id AND w.asset_id IS NOT NULL
		WHERE hc.asset_id = $1 AND hc.pod_uid <> ''
		ORDER BY 1
		ON CONFLICT (asset_id) DO UPDATE SET vulns_version = asset_findings_state.vulns_version + 1`, hostID)
	return err
}

// TouchPodLinks implements store.ContainerIngest.
func (d *DB) TouchPodLinks(ctx context.Context, hostID string) error {
	const op = "touch pod links"
	if !ivValidID(hostID) {
		return ivNotFound(op)
	}
	if err := d.ivScopeAsset(ctx, op, hostID); err != nil {
		return err
	}
	return ivErr(op, d.pdTouchHostLinks(ctx, hostID))
}

// pdTouchClusterLinks marks the findings of the hosts with containers of
// a cluster's pods out of date: a sync can link or unlink them.
func (d *DB) pdTouchClusterLinks(ctx context.Context, clusterID string) error {
	_, err := d.q.Exec(ctx, `
		INSERT INTO asset_findings_state (asset_id, vulns_version)
		SELECT DISTINCT hc.asset_id, 1
		FROM k8s_pods p JOIN asset_containers hc ON hc.pod_uid = p.uid
		WHERE p.cluster_id = $1 AND p.uid <> ''
		ORDER BY 1
		ON CONFLICT (asset_id) DO UPDATE SET vulns_version = asset_findings_state.vulns_version + 1`, clusterID)
	return err
}

// fiNodes reads the node containers of fiPodLinks ($3).
const fiNodes = `jsonb_to_recordset($3::jsonb) AS n(host_id uuid, host_container text, container text, pod text,
	host_name text, fresh boolean)`

// fiPods is what FindingInputs needs of the pod links of an asset.
type fiPods struct {
	// excluded are the host's containers that belong to a workload.
	excluded []string
	// nodes is the JSON of the workload's node containers (fiNodes).
	nodes string
	// hosts and freshHosts are the hosts of the node containers, and those
	// among them that reported recently.
	hosts, freshHosts []string
}

// fiPodLinks reads the pod links of an asset and sets in.NodeContainers.
func (d *DB) fiPodLinks(ctx context.Context, assetID string, in *store.FindingInputs) (fiPods, error) {
	out := fiPods{excluded: []string{}, nodes: "[]"}
	var err error
	switch in.Kind {
	case store.AssetHost:
		out.excluded, err = d.pdLinkedContainers(ctx, assetID)
		return out, err
	case store.AssetWorkload:
		in.NodeContainers, err = d.pdNodeContainers(ctx, assetID, mgNow().Add(-store.NodeEvidenceMaxAge))
		if err != nil {
			return out, err
		}
	default:
		return out, nil
	}
	type row struct {
		HostID        string `json:"host_id"`
		HostContainer string `json:"host_container"`
		Container     string `json:"container"`
		Pod           string `json:"pod"`
		HostName      string `json:"host_name"`
		Fresh         bool   `json:"fresh"`
	}
	rows := make([]row, 0, len(in.NodeContainers))
	seen, fresh := map[string]bool{}, map[string]bool{}
	for _, n := range in.NodeContainers {
		rows = append(rows, row{n.HostID, n.HostContainer, n.Container, n.Pod, n.HostName, n.Fresh})
		if !seen[n.HostID] {
			seen[n.HostID] = true
			out.hosts = append(out.hosts, n.HostID)
		}
		if n.Fresh && !fresh[n.HostID] {
			fresh[n.HostID] = true
			out.freshHosts = append(out.freshHosts, n.HostID)
		}
	}
	out.nodes, err = ivJSON(rows)
	return out, err
}

// fiNodeProcessCoverage sets the process coverage of the workload
// containers that node agents saw recently: the least coverage of the
// processes sections of those hosts.
func (d *DB) fiNodeProcessCoverage(ctx context.Context, in *store.FindingInputs, pods fiPods) error {
	if len(pods.freshHosts) == 0 {
		return nil
	}
	rows, err := d.q.Query(ctx, `SELECT asset_id::text, coverage FROM asset_sections
		WHERE asset_id = ANY($1::uuid[]) AND container = '' AND section = 'processes'`, pods.freshHosts)
	if err != nil {
		return err
	}
	byHost := map[string]store.Coverage{}
	for rows.Next() {
		var id string
		var cov store.Coverage
		if err := rows.Scan(&id, &cov); err != nil {
			rows.Close()
			return err
		}
		byHost[id] = cov
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	rank := map[store.Coverage]int{store.CoverageFull: 2, store.CoveragePartial: 1}
	cov := map[string]store.Coverage{}
	for _, n := range in.NodeContainers {
		if !n.Fresh {
			continue
		}
		c := byHost[n.HostID]
		if old, ok := cov[n.Container]; !ok || rank[c] < rank[old] {
			cov[n.Container] = c
		}
	}
	for name, c := range cov {
		in.ProcessCoverage[name] = c
	}
	return nil
}
