// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

// ReplaceProcesses implements store.ProcessIngest.
func (d *DB) ReplaceProcesses(ctx context.Context, scope store.ProcessScope, snap store.ProcessSnapshot) (store.ProcessDelta, error) {
	const op = "replace processes"
	var delta store.ProcessDelta
	if scope.Pod == "" && scope.Container != "" {
		return delta, ivInvalid(op, "container scope without pod")
	}
	at := ivAt(snap.At)

	type procRow struct {
		NewID        string            `json:"new_id"`
		Container    string            `json:"container"`
		PID          int               `json:"pid"`
		PPID         int               `json:"ppid"`
		User         string            `json:"user_name"`
		UID          int               `json:"uid"`
		Exe          string            `json:"exe"`
		ExeSource    string            `json:"exe_source"`
		ExeState     string            `json:"exe_state"`
		SHA256       string            `json:"sha256"`
		Cmdline      string            `json:"cmdline"`
		StartedAt    time.Time         `json:"started_at"`
		Libs         []store.MappedLib `json:"libs"`
		NeedsRestart bool              `json:"needs_restart"`
		Suspicious   bool              `json:"suspicious"`
		ComponentID  *string           `json:"component_id"`
		Packages     []string          `json:"packages"`
	}
	type listenRow struct {
		Container  string    `json:"container"`
		PID        int       `json:"pid"`
		StartedAt  time.Time `json:"started_at"`
		Proto      string    `json:"proto"`
		Address    string    `json:"address"`
		Port       int       `json:"port"`
		OtherNetNS bool      `json:"other_netns"`
	}
	type unownedRow struct {
		Proto   string `json:"proto"`
		Address string `json:"address"`
		Port    int    `json:"port"`
		UID     int    `json:"uid"`
	}
	type procKey struct {
		container string
		pid       int
		started   time.Time
	}
	type listenKey struct {
		procKey
		proto, address string
		port           int
	}
	procs := map[procKey]procRow{}
	listens := map[listenKey]listenRow{}
	for _, p := range snap.Processes {
		container := p.Container
		if scope.Pod != "" {
			container = scope.Container
		}
		started := p.StartedAt.UTC().Truncate(time.Microsecond)
		state := p.ExeState
		if state == "" {
			state = store.ExeNormal
		}
		libs := p.Libs
		if libs == nil {
			libs = []store.MappedLib{}
		}
		proc := store.Process{ExeState: state, Libs: libs}
		var comp *string
		if ivValidID(p.ComponentID) {
			c := p.ComponentID
			comp = &c
		}
		k := procKey{container, p.PID, started}
		procs[k] = procRow{
			NewID: ivNewID(), Container: container, PID: p.PID, PPID: p.PPID, User: p.User, UID: p.UID,
			Exe: p.Exe, ExeSource: p.ExeSource, ExeState: state, SHA256: p.SHA256, Cmdline: p.Cmdline,
			StartedAt: started, Libs: libs, NeedsRestart: proc.NeedsRestart(), Suspicious: proc.Suspicious(),
			ComponentID: comp, Packages: p.Packages,
		}
		for _, l := range p.Listen {
			listens[listenKey{k, l.Proto, l.Address, l.Port}] = listenRow{container, p.PID, started, l.Proto, l.Address, l.Port, p.OtherNetNS}
		}
	}
	unownedSet := map[unownedRow]bool{}
	for _, u := range snap.UnownedPorts {
		unownedSet[unownedRow{u.Proto, u.Address, u.Port, u.UID}] = true
	}
	procRows := make([]procRow, 0, len(procs))
	for _, r := range procs {
		procRows = append(procRows, r)
	}
	sort.Slice(procRows, func(i, j int) bool {
		a, b := procRows[i], procRows[j]
		if a.Container != b.Container {
			return a.Container < b.Container
		}
		if a.PID != b.PID {
			return a.PID < b.PID
		}
		return a.StartedAt.Before(b.StartedAt)
	})
	listenRows := make([]listenRow, 0, len(listens))
	for _, r := range listens {
		listenRows = append(listenRows, r)
	}
	unowned := make([]unownedRow, 0, len(unownedSet))
	for r := range unownedSet {
		unowned = append(unowned, r)
	}
	procJS, err := ivJSON(procRows)
	if err != nil {
		return delta, err
	}
	listenJS, err := ivJSON(listenRows)
	if err != nil {
		return delta, err
	}
	unownedJS, err := ivJSON(unowned)
	if err != nil {
		return delta, err
	}

	const scopeCond = `p.asset_id = $1 AND p.pod = $2 AND ($2 = '' OR p.container = $3)`
	const obs = `jsonb_to_recordset($4::jsonb) AS o(new_id uuid, container text, pid integer, ppid integer,
		user_name text, uid integer, exe text, exe_source text, exe_state text, sha256 text, cmdline text,
		started_at timestamptz, libs jsonb, needs_restart boolean, suspicious boolean, component_id uuid,
		packages text[])`
	const match = `o.container = p.container AND o.pid = p.pid AND o.started_at = p.started_at`
	const byHash = `(SELECT fh.component_id FROM file_hashes fh WHERE fh.sha256 = o.sha256 AND o.sha256 <> ''
		ORDER BY fh.last_seen DESC, fh.component_id LIMIT 1)`

	err = d.ivAtomic(ctx, func(d *DB) error {
		if err := d.ivLockAsset(ctx, op, scope.AssetID); err != nil {
			return err
		}
		args := []any{scope.AssetID, scope.Pod, scope.Container, procJS, at}
		err := d.q.QueryRow(ctx, `
			WITH gone AS (
				DELETE FROM processes p
				WHERE `+scopeCond+` AND NOT EXISTS (SELECT 1 FROM `+obs+` WHERE `+match+`)
				RETURNING p.*
			), ev AS (
				INSERT INTO process_events (asset_id, at, kind, pod, container, pid, user_name, exe, exe_state, sha256, started_at)
				SELECT asset_id, $5, 'disappeared', pod, container, pid, user_name, exe, exe_state, sha256, started_at FROM gone
			)
			SELECT count(*) FROM gone`, args...).Scan(&delta.Disappeared)
		if err != nil {
			return ivErr(op, err)
		}
		tag, err := d.q.Exec(ctx, `
			UPDATE processes p SET ppid = o.ppid, user_name = o.user_name, uid = o.uid, exe = o.exe,
				exe_source = o.exe_source, exe_state = o.exe_state, sha256 = o.sha256, cmdline = o.cmdline,
				libs = o.libs, needs_restart = o.needs_restart, suspicious = o.suspicious, packages = o.packages,
				component_id = COALESCE(o.component_id, `+byHash+`, p.component_id),
				last_seen = GREATEST(p.last_seen, $5)
			FROM `+obs+`
			WHERE `+scopeCond+` AND `+match, args...)
		if err != nil {
			return ivErr(op, err)
		}
		delta.Kept = int(tag.RowsAffected())
		err = d.q.QueryRow(ctx, `
			WITH added AS (
				INSERT INTO processes (id, asset_id, pod, container, pid, ppid, user_name, uid, exe, exe_source,
					exe_state, sha256, cmdline, started_at, libs, needs_restart, suspicious, component_id,
					packages, first_seen, last_seen)
				SELECT o.new_id, $1, $2, o.container, o.pid, o.ppid, o.user_name, o.uid, o.exe, o.exe_source,
					o.exe_state, o.sha256, o.cmdline, o.started_at, o.libs, o.needs_restart, o.suspicious,
					COALESCE(o.component_id, `+byHash+`), o.packages, $5, $5
				FROM `+obs+`
				WHERE NOT EXISTS (SELECT 1 FROM processes p WHERE `+scopeCond+` AND `+match+`)
				RETURNING *
			), ev AS (
				INSERT INTO process_events (asset_id, at, kind, pod, container, pid, user_name, exe, exe_state, sha256, started_at)
				SELECT asset_id, $5, 'appeared', pod, container, pid, user_name, exe, exe_state, sha256, started_at FROM added
			)
			SELECT count(*) FROM added`, args...).Scan(&delta.Appeared)
		if err != nil {
			return ivErr(op, err)
		}
		if _, err := d.q.Exec(ctx, `DELETE FROM listen_ports p WHERE `+scopeCond, scope.AssetID, scope.Pod, scope.Container); err != nil {
			return ivErr(op, err)
		}
		_, err = d.q.Exec(ctx, `
			INSERT INTO listen_ports (asset_id, pod, container, process_id, proto, address, port, uid, other_netns)
			SELECT $1, $2, p.container, p.id, l.proto, l.address, l.port, NULL, l.other_netns
			FROM jsonb_to_recordset($4::jsonb) AS l(container text, pid integer, started_at timestamptz,
				proto text, address text, port integer, other_netns boolean)
			JOIN processes p ON `+scopeCond+` AND p.container = l.container AND p.pid = l.pid
				AND p.started_at = l.started_at
			UNION ALL
			SELECT $1, $2, $3, NULL, u.proto, u.address, u.port, u.uid, false
			FROM jsonb_to_recordset($5::jsonb) AS u(proto text, address text, port integer, uid integer)`,
			scope.AssetID, scope.Pod, scope.Container, listenJS, unownedJS)
		return ivErr(op, err)
	})
	if err != nil {
		return store.ProcessDelta{}, err
	}
	return delta, nil
}

// DeleteProcessEventsBefore implements store.InventoryRetention.
func (d *DB) DeleteProcessEventsBefore(ctx context.Context, t time.Time) (int64, error) {
	if err := requireAll(ctx, "delete process events"); err != nil {
		return 0, err
	}
	tag, err := d.q.Exec(ctx, `DELETE FROM process_events WHERE at < $1`, t.UTC())
	if err != nil {
		return 0, ivErr("delete process events", err)
	}
	return tag.RowsAffected(), nil
}

const ivProcessCols = `p.id::text, p.asset_id::text, p.pod, p.container, p.pid, p.ppid, p.user_name, p.uid,
	p.exe, p.exe_source, p.exe_state, p.sha256, p.cmdline, p.started_at, p.libs,
	COALESCE((SELECT jsonb_agg(jsonb_build_object('proto', l.proto, 'address', l.address, 'port', l.port)
		ORDER BY l.port, l.proto, l.address) FROM listen_ports l WHERE l.process_id = p.id), '[]'),
	COALESCE(p.component_id::text, ''), p.first_seen, p.last_seen`

type ivProcessScan struct {
	libs, listen []byte
}

func ivProcessDest(p *store.Process, s *ivProcessScan) []any {
	return []any{&p.ID, &p.AssetID, &p.Pod, &p.Container, &p.PID, &p.PPID, &p.User, &p.UID,
		&p.Exe, &p.ExeSource, &p.ExeState, &p.SHA256, &p.Cmdline, &p.StartedAt, &s.libs, &s.listen,
		&p.ComponentID, &p.FirstSeen, &p.LastSeen}
}

func ivFixProcess(p *store.Process, s *ivProcessScan) error {
	p.StartedAt = p.StartedAt.UTC()
	p.FirstSeen = p.FirstSeen.UTC()
	p.LastSeen = p.LastSeen.UTC()
	if err := json.Unmarshal(s.libs, &p.Libs); err != nil {
		return fmt.Errorf("libs: %w", err)
	}
	var listen []struct {
		Proto   string `json:"proto"`
		Address string `json:"address"`
		Port    int    `json:"port"`
	}
	if err := json.Unmarshal(s.listen, &listen); err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	p.Listen = make([]store.ListenAddr, len(listen))
	for i, l := range listen {
		p.Listen[i] = store.ListenAddr{Proto: l.Proto, Address: l.Address, Port: l.Port}
	}
	return nil
}

func ivOptComponent(c store.Component) *store.Component {
	if c.ID == "" {
		return nil
	}
	return &c
}

// ivExecShown is the condition on a row t of processes or listen_ports that
// keeps it: rows of an exec collection of a pod container that a node agent
// saw since fresh are left out, as in the findings; the node agent's rows
// stand for the container.
func ivExecShown(t, fresh string) string {
	return `(` + t + `.pod = '' OR NOT EXISTS (SELECT 1 FROM ` + pdLinks + ` lk WHERE lk.workload_id = ` + t + `.asset_id
		AND lk.pod = ` + t + `.pod AND lk.container = ` + t + `.container AND lk.host_seen >= ` + fresh + `))`
}

// ivOwnedProcesses lists the processes under the asset they belong to, as
// the findings do: the processes of a host container linked to a pod go to
// the pod's workload, with the host as node, while the host reported since
// fresh; after that the exec collections stand for the container. narrow
// is an extra condition on processes p.
func ivOwnedProcesses(fresh, narrow string) string {
	return `(SELECT p.id, coalesce(k.workload_id, p.asset_id) AS asset_id, coalesce(k.pod, p.pod) AS pod,
			coalesce(k.container, p.container) AS container, coalesce(k.host_name, '') AS node,
			p.pid, p.ppid, p.user_name, p.uid, p.exe, p.exe_source, p.exe_state, p.sha256, p.cmdline, p.started_at,
			p.libs, p.needs_restart, p.suspicious, p.component_id, p.first_seen, p.last_seen
		FROM processes p
		LEFT JOIN LATERAL ` + ivNodeLink("p", "true") + ` k ON true
		WHERE ` + ivExecShown("p", fresh) + ` AND (k.workload_id IS NULL OR k.host_seen >= ` + fresh + `)` + narrow + `)`
}

// ivNodeLink is the pod link of the host container of a row t of processes
// or listen_ports, if cond holds.
func ivNodeLink(t, cond string) string {
	return `(SELECT lk.workload_id, lk.pod, lk.container, lk.host_name, lk.host_seen FROM ` + pdLinks + ` lk
			WHERE ` + cond + ` AND lk.host_id = ` + t + `.asset_id AND lk.host_container = ` + t + `.container
			ORDER BY lk.workload_id LIMIT 1)`
}

// ListProcesses implements store.InventoryQuery.
func (d *DB) ListProcesses(ctx context.Context, f store.ProcessFilter, p store.Page) ([]store.ProcessRow, int, error) {
	const op = "list processes"
	order, err := ivOrder(op, f.Sort, "asset", map[string]string{
		"asset":      "a.name",
		"pid":        "p.pid",
		"exe":        "p.exe",
		"user":       "p.user_name",
		"state":      "p.exe_state",
		"started_at": "p.started_at",
		// Suspicious, then needing a restart, then the rest (descending).
		"risk": "(p.suspicious::int * 2 + p.needs_restart::int)",
	}, "a.name, a.id, p.pod, p.container, p.pid, p.id")
	if err != nil {
		return nil, 0, err
	}
	q, sc, err := scoped(ctx, op)
	if err != nil {
		return nil, 0, err
	}
	q.and(sc.col("a.scope_id"))
	q.where("a.gone_at IS NULL")
	fresh := q.arg(mgNow().Add(-store.NodeEvidenceMaxAge))
	narrow := ""
	if f.AssetID != "" {
		if !ivValidID(f.AssetID) {
			return nil, 0, nil
		}
		// The rows of the asset and of the hosts linked to it, read
		// through the index before ownership is worked out.
		a := q.arg(f.AssetID)
		narrow = ` AND (p.asset_id = ` + a + ` OR p.asset_id IN (SELECT lk.host_id FROM ` + pdLinks + ` lk
			WHERE lk.workload_id = ` + a + `))`
		q.where("p.asset_id = %s", f.AssetID)
	}
	if f.ID != "" {
		if !ivValidID(f.ID) {
			return nil, 0, nil
		}
		q.where("p.id = %s", f.ID)
	}
	if f.Container != nil {
		q.where("p.container = %s", *f.Container)
	}
	switch f.View {
	case "", store.ProcessViewAll:
	case store.ProcessViewRestart:
		q.where("p.needs_restart")
	case store.ProcessViewSuspicious:
		q.where("p.suspicious")
	case store.ProcessViewListen:
		q.where("EXISTS (SELECT 1 FROM listen_ports l WHERE l.process_id = p.id)")
	default:
		return nil, 0, ivInvalid(op, fmt.Sprintf("unknown view %q", f.View))
	}
	if f.ExeState != "" {
		q.where("p.exe_state = %s", f.ExeState)
	}
	switch {
	case f.Q == "":
	case f.AssetID == "" && d.useTrigram(ctx, f.Q):
		// Each branch reads one table so the trigram indexes apply; the OR
		// across the join below scans every process.
		q.where(`p.id IN (SELECT x.id FROM processes x WHERE x.exe ILIKE %[1]s OR x.user_name ILIKE %[1]s
				OR x.cmdline ILIKE %[1]s OR x.pid::text ILIKE %[1]s
			UNION ALL SELECT x.id FROM processes x JOIN assets xa ON xa.id = x.asset_id WHERE xa.name ILIKE %[1]s)`,
			ivLike(f.Q))
	default:
		q.where(`(p.exe ILIKE %[1]s OR p.user_name ILIKE %[1]s OR p.cmdline ILIKE %[1]s
			OR p.pid::text ILIKE %[1]s OR a.name ILIKE %[1]s)`, ivLike(f.Q))
	}
	from := `FROM ` + ivOwnedProcesses(fresh, narrow) + ` p JOIN assets a ON a.id = p.asset_id
		LEFT JOIN k8s_clusters k ON k.id = a.cluster_id
		LEFT JOIN components c ON c.id = p.component_id` + q.whereSQL()
	var out []store.ProcessRow
	sel := ivProcessCols + ", p.node, " + ivBriefCols + ", " + ivComponentCols
	total, err := ivPage(ctx, d, op, q, sel, from, order, p, func(rows pgx.Rows) error {
		var r store.ProcessRow
		var s ivProcessScan
		var c store.Component
		dest := append(ivProcessDest(&r.Process, &s), &r.Node)
		dest = append(dest, ivBriefDest(&r.Asset)...)
		if err := rows.Scan(append(dest, ivComponentDest(&c)...)...); err != nil {
			return err
		}
		if err := ivFixProcess(&r.Process, &s); err != nil {
			return err
		}
		r.Component = ivOptComponent(c)
		out = append(out, r)
		return nil
	})
	return out, total, err
}

// ListListenPorts implements store.InventoryQuery.
func (d *DB) ListListenPorts(ctx context.Context, f store.ListenPortFilter, p store.Page) ([]store.ListenPortRow, int, error) {
	const op = "list listen ports"
	order, err := ivOrder(op, f.Sort, "port", map[string]string{
		"port":    "l.port",
		"address": "l.address",
		"proto":   "l.proto",
		"exe":     "COALESCE(p.exe, '')",
		"user":    "COALESCE(p.user_name, '')",
		"asset":   "a.name",
	}, "a.name, a.id, l.pod, l.container, l.proto, l.address, l.port, l.process_id, l.uid")
	if err != nil {
		return nil, 0, err
	}
	q, sc, err := scoped(ctx, op)
	if err != nil {
		return nil, 0, err
	}
	q.and(sc.col("a.scope_id"))
	q.where("a.gone_at IS NULL")
	if f.AssetID != "" {
		if !ivValidID(f.AssetID) {
			return nil, 0, nil
		}
		q.where("l.asset_id = %s", f.AssetID)
	}
	if f.Proto != "" {
		q.where("l.proto = %s", f.Proto)
	}
	if f.Port != 0 {
		q.where("l.port = %s", f.Port)
	}
	if f.Q != "" {
		q.where(`(l.address ILIKE %[1]s OR l.port::text ILIKE %[1]s OR p.exe ILIKE %[1]s
			OR p.user_name ILIKE %[1]s OR a.name ILIKE %[1]s)`, ivLike(f.Q))
	}
	// A socket in the network of a host container linked to a pod belongs
	// to the pod's workload; the node agent's or the exec collections'
	// sockets are listed as with ivOwnedProcesses.
	fresh := q.arg(mgNow().Add(-store.NodeEvidenceMaxAge))
	owned := `(SELECT l.proto, l.address, l.port, l.process_id, l.uid,
			coalesce(k.workload_id, l.asset_id) AS asset_id, coalesce(k.pod, l.pod) AS pod,
			coalesce(k.container, l.container) AS container, coalesce(k.host_name, '') AS node
		FROM listen_ports l
		LEFT JOIN LATERAL ` + ivNodeLink("l", "l.other_netns") + ` k ON true
		WHERE ` + ivExecShown("l", fresh) + ` AND (k.workload_id IS NULL OR k.host_seen >= ` + fresh + `))`
	from := `FROM ` + owned + ` l JOIN assets a ON a.id = l.asset_id
		LEFT JOIN k8s_clusters k ON k.id = a.cluster_id
		LEFT JOIN processes p ON p.id = l.process_id
		LEFT JOIN components c ON c.id = p.component_id` + q.whereSQL()
	sel := `l.proto, l.address, l.port, ` + ivBriefCols + `, l.pod, l.container, l.node, COALESCE(p.id::text, ''),
		COALESCE(p.pid, 0), COALESCE(p.exe, ''), COALESCE(p.user_name, ''), COALESCE(l.uid, p.uid, 0), ` + ivComponentCols
	var out []store.ListenPortRow
	total, err := ivPage(ctx, d, op, q, sel, from, order, p, func(rows pgx.Rows) error {
		var r store.ListenPortRow
		var c store.Component
		dest := []any{&r.Proto, &r.Address, &r.Port}
		dest = append(dest, ivBriefDest(&r.Asset)...)
		dest = append(dest, &r.Pod, &r.Container, &r.Node, &r.ProcessID, &r.PID, &r.Exe, &r.User, &r.UID)
		if err := rows.Scan(append(dest, ivComponentDest(&c)...)...); err != nil {
			return err
		}
		r.Component = ivOptComponent(c)
		out = append(out, r)
		return nil
	})
	return out, total, err
}

// ivPruneGonePods removes the processes and listening ports that exec
// collections stored for pods of a cluster that are no longer running, and
// marks the findings of their workloads out of date.
func (d *DB) ivPruneGonePods(ctx context.Context, clusterID string, at time.Time) error {
	const gonePod = `w.cluster_id = $1 AND w.asset_id = %[1]s.asset_id AND %[1]s.pod <> ''
		AND NOT EXISTS (SELECT 1 FROM k8s_pods p JOIN k8s_workloads pw ON pw.id = p.workload_id
			WHERE pw.asset_id = %[1]s.asset_id AND p.name = %[1]s.pod AND p.gone_at IS NULL)`
	rows, err := d.q.Query(ctx, `
		WITH gone AS (
			DELETE FROM processes pr USING k8s_workloads w
			WHERE `+fmt.Sprintf(gonePod, "pr")+`
			RETURNING pr.*
		), ev AS (
			INSERT INTO process_events (asset_id, at, kind, pod, container, pid, user_name, exe, exe_state, sha256, started_at)
			SELECT asset_id, $2, 'disappeared', pod, container, pid, user_name, exe, exe_state, sha256, started_at FROM gone
		)
		SELECT DISTINCT asset_id::text FROM gone`, clusterID, at)
	if err != nil {
		return err
	}
	touched, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	// Ports of the removed processes went with them; these are the
	// sockets without a process.
	rows, err = d.q.Query(ctx, `
		DELETE FROM listen_ports l USING k8s_workloads w
		WHERE `+fmt.Sprintf(gonePod, "l")+`
		RETURNING l.asset_id::text`, clusterID)
	if err != nil {
		return err
	}
	ports, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	touched = append(touched, ports...)
	if len(touched) == 0 {
		return nil
	}
	slices.Sort(touched)
	_, err = d.q.Exec(ctx, `
		INSERT INTO asset_findings_state (asset_id, vulns_version)
		SELECT DISTINCT id, 1 FROM unnest($1::uuid[]) AS id
		ORDER BY 1
		ON CONFLICT (asset_id) DO UPDATE SET vulns_version = asset_findings_state.vulns_version + 1`,
		slices.Compact(touched))
	return err
}
