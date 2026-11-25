// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/server/scope"
)

var ivT0 = time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)

func ivCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(scope.System(context.Background()), time.Minute)
	t.Cleanup(cancel)
	return ctx
}

func ivMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func ivHost(t *testing.T, db *DB, name string) string {
	t.Helper()
	ref, err := db.UpsertHostAsset(ivCtx(t), store.HostIdentity{AgentID: uuid.NewString()},
		store.AssetInit{Name: name, Method: store.CollectAgent, SeenAt: ivT0})
	ivMust(t, err)
	return ref.ID
}

func ivDeb(name, version string) store.Component {
	return store.Component{
		Type: "deb", Name: name, Version: version, Arch: "amd64", Distro: "ubuntu-24.04",
		PURL:   "pkg:deb/ubuntu/" + name + "@" + version + "?arch=amd64&distro=ubuntu-24.04",
		Origin: store.OriginDistro,
	}
}

func ivPkgObs(cs ...store.Component) []store.ComponentObservation {
	out := make([]store.ComponentObservation, len(cs))
	for i, c := range cs {
		out[i] = store.ComponentObservation{Component: c, Locations: []string{"/var/lib/dpkg/status"}, Method: store.DetectPackageDB}
	}
	return out
}

func ivCount(t *testing.T, db *DB, sql string, args ...any) int {
	t.Helper()
	var n int
	ivMust(t, db.q.QueryRow(ivCtx(t), sql, args...).Scan(&n))
	return n
}
