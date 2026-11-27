// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"slices"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

func TestTrigramProcessSearch(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	if ok, err := db.TrigramSearch(ctx); err != nil || !ok {
		t.Fatalf("search indexes: %v %v", ok, err)
	}
	ivMust(t, db.ensureSearchIndexes(ctx)) // again: nothing to do

	web, dbHost := ivHost(t, db, "web-01"), ivHost(t, db, "db-01")
	boot := ivT0.Add(-time.Hour)
	for _, a := range []struct {
		id    string
		procs []store.ProcessObservation
	}{
		{web, []store.ProcessObservation{
			{PID: 900, User: "root", Exe: "/usr/sbin/sshd", ExeSource: "proc", ExeState: store.ExeNormal, StartedAt: boot},
			{PID: 1200, User: "www-data", Exe: "/usr/sbin/nginx", Cmdline: "nginx -c /etc/nginx/web.conf", ExeSource: "proc", ExeState: store.ExeNormal, StartedAt: boot},
		}},
		{dbHost, []store.ProcessObservation{
			{PID: 4321, User: "postgres", Exe: "/usr/lib/postgresql/16/bin/postgres", ExeSource: "proc", ExeState: store.ExeNormal, StartedAt: boot},
			{PID: 901, User: "root", Exe: "/usr/sbin/sshd", ExeSource: "proc", ExeState: store.ExeNormal, StartedAt: boot},
		}},
	} {
		_, err := db.ReplaceProcesses(ctx, store.ProcessScope{AssetID: a.id}, store.ProcessSnapshot{At: ivT0, Processes: a.procs})
		ivMust(t, err)
	}

	search := func(q string) []int {
		t.Helper()
		rows, total, err := db.ListProcesses(ctx, store.ProcessFilter{Q: q, Sort: "pid"}, store.Page{})
		ivMust(t, err)
		if total != len(rows) {
			t.Fatalf("%q: total %d, %d rows", q, total, len(rows))
		}
		pids := make([]int, len(rows))
		for i, r := range rows {
			pids[i] = r.PID
		}
		return pids
	}
	cases := map[string][]int{
		"sshd":     {900, 901},  // exe
		"web.conf": {1200},      // cmdline
		"db-01":    {901, 4321}, // asset name
		"www-data": {1200},      // user
		"432":      {4321},      // pid
		"SSHD":     {900, 901},  // case
		"50%":      nil,         // escaped wildcard
		"gr":       {4321},      // short: plain form (postgresql)
	}
	indexed := map[string][]int{}
	for q, want := range cases {
		got := search(q)
		if !slices.Equal(got, want) {
			t.Errorf("indexed %q: %v, want %v", q, got, want)
		}
		indexed[q] = got
	}
	// The plain form gives the same rows.
	db.feat.mu.Lock()
	db.feat.trgm, db.feat.checkedAt = false, time.Now()
	db.feat.mu.Unlock()
	for q := range cases {
		if got := search(q); !slices.Equal(got, indexed[q]) {
			t.Errorf("plain %q: %v, indexed %v", q, got, indexed[q])
		}
	}
}

func TestComponentVersionSort(t *testing.T) {
	db := newTestDB(t)
	ctx := ivCtx(t)
	asset := ivHost(t, db, "web-01")
	versions := []string{"1.10", "1:0.1", "1.9", "1.10~rc1", "1.10-1", "1.2.13"}
	var cs []store.Component
	for _, v := range versions {
		cs = append(cs, ivDeb("zlib1g", v))
	}
	_, err := db.ReplaceAssetComponents(ctx, store.ComponentScope{AssetID: asset, Source: store.SourcePackages}, ivPkgObs(cs...), store.ReplaceOptions{At: ivT0})
	ivMust(t, err)

	want := []string{"1.2.13", "1.9", "1.10~rc1", "1.10", "1.10-1", "1:0.1"}
	for _, sort := range []string{"version", "-version"} {
		rows, _, err := db.ListComponents(ctx, store.ComponentFilter{Q: "zlib1g", Sort: sort}, store.Page{})
		ivMust(t, err)
		got := make([]string, len(rows))
		for i, r := range rows {
			got[i] = r.Version
		}
		w := slices.Clone(want)
		if sort == "-version" {
			slices.Reverse(w)
		}
		if !slices.Equal(got, w) {
			t.Errorf("%s: %v, want %v", sort, got, w)
		}
		ac, _, err := db.ListAssetComponents(ctx, asset, store.AssetComponentFilter{Sort: sort}, store.Page{})
		ivMust(t, err)
		if len(ac) != len(w) || ac[0].Component.Version != w[0] || ac[len(ac)-1].Component.Version != w[len(w)-1] {
			t.Errorf("asset components %s: first %q last %q", sort, ac[0].Component.Version, ac[len(ac)-1].Component.Version)
		}
	}

	var keys []string
	ivMust(t, db.pool.QueryRow(ctx, `SELECT array_agg(version_sort_key(k, v) ORDER BY version_sort_key(k, v) COLLATE "C")
		FROM (VALUES ('golang', 'v1.2.3'), ('golang', 'v1.2.3-rc.1'), ('golang', 'v1.10.0'), ('golang', 'v0.0.0-20200101-abc'),
			('maven', '1.0-SNAPSHOT'), ('maven', '1.0'), ('binary', '')) x(k, v)`).Scan(&keys))
	var order []string
	ivMust(t, db.pool.QueryRow(ctx, `SELECT array_agg(k || ' ' || v ORDER BY version_sort_key(k, v) COLLATE "C", k)
		FROM (VALUES ('golang', 'v1.2.3'), ('golang', 'v1.2.3-rc.1'), ('golang', 'v1.10.0'), ('golang', 'v0.0.0-20200101-abc')) x(k, v)`).Scan(&order))
	if w := []string{"golang v0.0.0-20200101-abc", "golang v1.2.3-rc.1", "golang v1.2.3", "golang v1.10.0"}; !slices.Equal(order, w) {
		t.Errorf("golang order: %v, want %v", order, w)
	}
	var semver []string
	ivMust(t, db.pool.QueryRow(ctx, `SELECT array_agg(v ORDER BY version_sort_key('semver', v) COLLATE "C")
		FROM unnest(ARRAY['1.10.0', '1.2.0', 'v1.9.1', '1.2.0-rc.1']) v`).Scan(&semver))
	if w := []string{"1.2.0-rc.1", "1.2.0", "v1.9.1", "1.10.0"}; !slices.Equal(semver, w) {
		t.Errorf("semver order: %v, want %v", semver, w)
	}
	if keys[0] != "" {
		t.Errorf("empty version key: %q", keys[0])
	}
}
