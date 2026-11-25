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
		Container string    `json:"container"`
		PID       int       `json:"pid"`
		StartedAt time.Time `json:"started_at"`
		Proto     string    `json:"proto"`
		Address   string    `json:"address"`
		Port      int       `json:"port"`
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
			listens[listenKey{k, l.Proto, l.Address, l.Port}] = listenRow{container, p.PID, started, l.Proto, l.Address, l.Port}
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
			INSERT INTO listen_ports (asset_id, pod, container, process_id, proto, address, port, uid)
			SELECT $1, $2, p.container, p.id, l.proto, l.address, l.port, NULL
			FROM jsonb_to_recordset($4::jsonb) AS l(container text, pid integer, started_at timestamptz,
				proto text, address text, port integer)
			JOIN processes p ON `+scopeCond+` AND p.container = l.container AND p.pid = l.pid
				AND p.started_at = l.started_at
			UNION ALL
			SELECT $1, $2, $3, NULL, u.proto, u.address, u.port, u.uid
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
	if f.AssetID != "" {
		if !ivValidID(f.AssetID) {
			return nil, 0, nil
		}
		q.where("p.asset_id = %s", f.AssetID)
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
	if f.Q != "" {
		q.where(`(p.exe ILIKE %[1]s OR p.user_name ILIKE %[1]s OR p.cmdline ILIKE %[1]s
			OR p.pid::text ILIKE %[1]s OR a.name ILIKE %[1]s)`, ivLike(f.Q))
	}
	from := `FROM processes p JOIN assets a ON a.id = p.asset_id
		LEFT JOIN k8s_clusters k ON k.id = a.cluster_id
		LEFT JOIN components c ON c.id = p.component_id` + q.whereSQL()
	var out []store.ProcessRow
	sel := ivProcessCols + ", " + ivBriefCols + ", " + ivComponentCols
	total, err := ivPage(ctx, d, op, q, sel, from, order, p, func(rows pgx.Rows) error {
		var r store.ProcessRow
		var s ivProcessScan
		var c store.Component
		dest := append(ivProcessDest(&r.Process, &s), ivBriefDest(&r.Asset)...)
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
	from := `FROM listen_ports l JOIN assets a ON a.id = l.asset_id
		LEFT JOIN k8s_clusters k ON k.id = a.cluster_id
		LEFT JOIN processes p ON p.id = l.process_id
		LEFT JOIN components c ON c.id = p.component_id` + q.whereSQL()
	sel := `l.proto, l.address, l.port, ` + ivBriefCols + `, l.pod, l.container, COALESCE(p.id::text, ''),
		COALESCE(p.pid, 0), COALESCE(p.exe, ''), COALESCE(p.user_name, ''), COALESCE(l.uid, p.uid, 0), ` + ivComponentCols
	var out []store.ListenPortRow
	total, err := ivPage(ctx, d, op, q, sel, from, order, p, func(rows pgx.Rows) error {
		var r store.ListenPortRow
		var c store.Component
		dest := []any{&r.Proto, &r.Address, &r.Port}
		dest = append(dest, ivBriefDest(&r.Asset)...)
		dest = append(dest, &r.Pod, &r.Container, &r.ProcessID, &r.PID, &r.Exe, &r.User, &r.UID)
		if err := rows.Scan(append(dest, ivComponentDest(&c)...)...); err != nil {
			return err
		}
		r.Component = ivOptComponent(c)
		out = append(out, r)
		return nil
	})
	return out, total, err
}
