// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"bytes"
	"testing"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

func TestComponentBuildIsIdentity(t *testing.T) {
	plain := store.Component{Type: "binary", Name: "genian-nac", Version: "5.0.54.0720",
		PURL: "pkg:generic/genians/genian-nac@5.0.54.0720"}
	b1, b2 := plain, plain
	b1.Build, b2.Build = "117458", "117460"
	if bytes.Equal(ivIdent(plain), ivIdent(b1)) || bytes.Equal(ivIdent(b1), ivIdent(b2)) {
		t.Fatal("builds must change the identity")
	}

	db := newTestDB(t)
	ctx := ivCtx(t)
	a := ivHost(t, db, "nac")
	obs := func(cs ...store.Component) []store.ComponentObservation {
		var out []store.ComponentObservation
		for _, c := range cs {
			out = append(out, store.ComponentObservation{Component: c, Locations: []string{"/usr/geni/centerd"}, Method: store.DetectStatic})
		}
		return out
	}
	_, err := db.ReplaceAssetComponents(ctx, store.ComponentScope{AssetID: a, Source: store.SourceArtifacts},
		obs(plain, b1, b2), store.ReplaceOptions{At: ivT0})
	ivMust(t, err)
	if n := ivCount(t, db, `SELECT count(*) FROM components`); n != 3 {
		t.Fatalf("components: %d", n)
	}
	comps, _, err := db.ListComponents(ctx, store.ComponentFilter{Q: "genian"}, store.Page{})
	ivMust(t, err)
	builds := map[string]bool{}
	for _, c := range comps {
		builds[c.Build] = true
	}
	if len(comps) != 3 || !builds[""] || !builds["117458"] || !builds["117460"] {
		t.Fatalf("listed: %+v", comps)
	}
	got, err := db.GetComponent(ctx, comps[0].ID)
	ivMust(t, err)
	if got.Build != comps[0].Build {
		t.Fatalf("get: %+v", got)
	}
}
