// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

func TestReplaceProcessesAndEvents(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	asset := ivHost(t, db, "web-01")
	other := ivHost(t, db, "web-02")
	scope := store.ProcessScope{AssetID: asset}
	t1, t2 := ivT0, ivT0.Add(10*time.Minute)
	boot := ivT0.Add(-24 * time.Hour)

	sshd := store.ProcessObservation{PID: 900, User: "root", Exe: "/usr/sbin/sshd", ExeSource: "proc", ExeState: store.ExeNormal,
		SHA256: "s1", StartedAt: boot, Listen: []store.ListenAddr{{Proto: "tcp", Address: "0.0.0.0", Port: 22}, {Proto: "tcp", Address: "::", Port: 22}}}
	nginx := store.ProcessObservation{PID: 1200, User: "www-data", Exe: "/usr/sbin/nginx", ExeSource: "proc", ExeState: store.ExeReplaced,
		StartedAt: boot.Add(time.Hour), Listen: []store.ListenAddr{{Proto: "tcp", Address: "0.0.0.0", Port: 443}}, Container: "proxy"}
	java := store.ProcessObservation{PID: 3000, User: "app", Exe: "/opt/jdk/bin/java", ExeSource: "proc", ExeState: store.ExeNormal,
		StartedAt: boot.Add(2 * time.Hour), Libs: []store.MappedLib{{Path: "/usr/lib/libssl.so.3", State: store.ExeReplaced}}}
	payload := store.ProcessObservation{PID: 4000, User: "nobody", Exe: "/memfd:x", ExeSource: "proc", ExeState: store.ExeMemfd,
		StartedAt: boot.Add(3 * time.Hour)}

	// A file hash links sshd to a component.
	comp := ivDeb("openssh-server", "1:9.6p1-3ubuntu13")
	_, err := db.ReplaceAssetComponents(ctx, store.ComponentScope{AssetID: asset, Source: store.SourcePackages}, ivPkgObs(comp), store.ReplaceOptions{At: t1})
	ivMust(t, err)
	comps, _, err := db.ListComponents(ctx, store.ComponentFilter{Q: "openssh"}, store.Page{})
	ivMust(t, err)
	ivMust(t, db.RecordFileHashes(ctx, []store.FileHash{{SHA256: "s1", ComponentID: comps[0].ID}}, t1))

	d, err := db.ReplaceProcesses(ctx, scope, store.ProcessSnapshot{At: t1, Processes: []store.ProcessObservation{sshd, nginx, java},
		UnownedPorts: []store.UnownedPort{{ListenAddr: store.ListenAddr{Proto: "udp", Address: "0.0.0.0", Port: 161}, UID: 110}}})
	ivMust(t, err)
	if d.Appeared != 3 || d.Disappeared != 0 {
		t.Fatalf("first: %+v", d)
	}
	_, err = db.ReplaceProcesses(ctx, store.ProcessScope{AssetID: other}, store.ProcessSnapshot{At: t1, Processes: []store.ProcessObservation{sshd}})
	ivMust(t, err)

	before, _, err := db.ListProcesses(ctx, store.ProcessFilter{AssetID: asset, Sort: "pid"}, store.Page{})
	ivMust(t, err)

	// nginx exits, payload appears, sshd stays.
	d, err = db.ReplaceProcesses(ctx, scope, store.ProcessSnapshot{At: t2, Processes: []store.ProcessObservation{sshd, java, payload}})
	ivMust(t, err)
	if d.Appeared != 1 || d.Disappeared != 1 || d.Kept != 2 {
		t.Fatalf("second: %+v", d)
	}
	if n := ivCount(t, db, `SELECT count(*) FROM process_events WHERE asset_id = $1`, asset); n != 5 {
		t.Fatalf("events: %d", n)
	}
	if n := ivCount(t, db, `SELECT count(*) FROM process_events WHERE asset_id = $1 AND kind = 'disappeared' AND pid = 1200 AND at = $2`, asset, t2); n != 1 {
		t.Fatalf("disappeared event: %d", n)
	}

	procs, total, err := db.ListProcesses(ctx, store.ProcessFilter{AssetID: asset, Sort: "pid"}, store.Page{})
	ivMust(t, err)
	if total != 3 || procs[0].PID != 900 {
		t.Fatalf("processes: %+v", procs)
	}
	if procs[0].ID != before[0].ID || !procs[0].FirstSeen.Equal(t1) || !procs[0].LastSeen.Equal(t2) {
		t.Fatalf("kept process identity: %+v vs %+v", procs[0].Process, before[0].Process)
	}
	if procs[0].Component == nil || procs[0].Component.Name != "openssh-server" || len(procs[0].Listen) != 2 {
		t.Fatalf("sshd: %+v", procs[0])
	}

	restart, total, err := db.ListProcesses(ctx, store.ProcessFilter{View: store.ProcessViewRestart}, store.Page{})
	ivMust(t, err)
	if total != 1 || restart[0].PID != 3000 || !restart[0].NeedsRestart() || len(restart[0].Libs) != 1 {
		t.Fatalf("restart: %+v", restart)
	}
	sus, total, err := db.ListProcesses(ctx, store.ProcessFilter{View: store.ProcessViewSuspicious}, store.Page{})
	ivMust(t, err)
	if total != 1 || sus[0].PID != 4000 || sus[0].Asset.Name != "web-01" {
		t.Fatalf("suspicious: %+v", sus)
	}
	risky, _, err := db.ListProcesses(ctx, store.ProcessFilter{Sort: "-risk"}, store.Page{Limit: 2})
	ivMust(t, err)
	if len(risky) != 2 || risky[0].PID != 4000 || risky[1].PID != 3000 {
		t.Fatalf("risk order: %+v", risky)
	}
	all, total, err := db.ListProcesses(ctx, store.ProcessFilter{Q: "sshd", Sort: "asset"}, store.Page{Limit: 1, Offset: 1})
	ivMust(t, err)
	if total != 2 || len(all) != 1 || all[0].Asset.Name != "web-02" {
		t.Fatalf("search page: %d %+v", total, all)
	}
	// One process by id: only on its own asset.
	one, total, err := db.ListProcesses(ctx, store.ProcessFilter{AssetID: asset, ID: procs[1].ID}, store.Page{})
	ivMust(t, err)
	if total != 1 || one[0].ID != procs[1].ID || one[0].PID != procs[1].PID {
		t.Fatalf("by id: %+v", one)
	}
	for name, f := range map[string]store.ProcessFilter{
		"other asset": {AssetID: other, ID: procs[1].ID},
		"bad id":      {AssetID: asset, ID: "x"},
	} {
		if rows, total, err := db.ListProcesses(ctx, f, store.Page{}); err != nil || total != 0 || len(rows) != 0 {
			t.Fatalf("by id, %s: %d %+v %v", name, total, rows, err)
		}
	}
	if _, _, err := db.ListProcesses(ctx, store.ProcessFilter{View: "bogus"}, store.Page{}); err == nil {
		t.Fatal("bad view accepted")
	}

	ports, total, err := db.ListListenPorts(ctx, store.ListenPortFilter{AssetID: asset}, store.Page{})
	ivMust(t, err)
	if total != 2 || ports[0].Port != 22 {
		t.Fatalf("ports after second snapshot: %+v", ports)
	}
	ports, total, err = db.ListListenPorts(ctx, store.ListenPortFilter{Port: 22, Sort: "asset"}, store.Page{Limit: 2})
	ivMust(t, err)
	if total != 4 || len(ports) != 2 || ports[0].Exe != "/usr/sbin/sshd" || ports[0].Component == nil {
		t.Fatalf("port 22: %d %+v", total, ports)
	}

	counts, err := db.Dashboard(ctx)
	ivMust(t, err)
	if counts.NeedsRestart != 1 || counts.Suspicious != 1 {
		t.Fatalf("dashboard: %+v", counts)
	}

	// Unowned ports from the first snapshot are gone with the second.
	if n := ivCount(t, db, `SELECT count(*) FROM listen_ports WHERE process_id IS NULL`); n != 0 {
		t.Fatalf("unowned: %d", n)
	}

	// Pod scopes do not touch each other.
	podA := store.ProcessScope{AssetID: other, Pod: "api-1", Container: "api"}
	podB := store.ProcessScope{AssetID: other, Pod: "api-2", Container: "api"}
	_, err = db.ReplaceProcesses(ctx, podA, store.ProcessSnapshot{At: t1, Processes: []store.ProcessObservation{{PID: 1, Exe: "/app", StartedAt: boot}}})
	ivMust(t, err)
	_, err = db.ReplaceProcesses(ctx, podB, store.ProcessSnapshot{At: t1, Processes: []store.ProcessObservation{{PID: 1, Exe: "/app", StartedAt: boot}}})
	ivMust(t, err)
	d, err = db.ReplaceProcesses(ctx, podA, store.ProcessSnapshot{At: t2})
	ivMust(t, err)
	if d.Disappeared != 1 {
		t.Fatalf("pod scope: %+v", d)
	}
	if n := ivCount(t, db, `SELECT count(*) FROM processes WHERE asset_id = $1`, other); n != 2 {
		t.Fatalf("processes of other: %d", n)
	}

	n, err := db.DeleteProcessEventsBefore(ctx, t2)
	ivMust(t, err)
	if n == 0 {
		t.Fatal("no events deleted")
	}
}
