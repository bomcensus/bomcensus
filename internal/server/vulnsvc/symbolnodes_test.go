// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package vulnsvc

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/server/dispatch"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

type symbolFake struct {
	inputs  map[string]store.FindingInputs
	assets  map[string]store.AssetDetail
	agents  map[string]store.Agent
	queries map[[2]string]store.GoSymbolQuery
	sent    map[string]int
}

func (f *symbolFake) GoSymbolAssets(context.Context, time.Time, int) ([]string, error) {
	return nil, nil
}
func (f *symbolFake) FindingInputs(_ context.Context, id string) (store.FindingInputs, error) {
	in, ok := f.inputs[id]
	if !ok {
		return in, store.ErrNotFound
	}
	return in, nil
}
func (f *symbolFake) GetAsset(_ context.Context, id string) (store.AssetDetail, error) {
	a, ok := f.assets[id]
	if !ok {
		return a, store.ErrNotFound
	}
	return a, nil
}
func (f *symbolFake) GetAgent(_ context.Context, id string) (store.Agent, error) {
	return f.agents[id], nil
}
func (f *symbolFake) PutGoSymbolQuery(_ context.Context, q store.GoSymbolQuery) error {
	f.queries[[2]string{q.AssetID, q.Container}] = q
	return nil
}
func (f *symbolFake) GoSymbolQueryFor(_ context.Context, asset, container string) (store.GoSymbolQuery, error) {
	q, ok := f.queries[[2]string{asset, container}]
	if !ok {
		return q, store.ErrNotFound
	}
	return q, nil
}
func (f *symbolFake) Enqueue(_ context.Context, agentID string, _ dispatch.Directive) (string, error) {
	f.sent[agentID]++
	return "d", nil
}

func (f *symbolFake) query(t *testing.T, asset, container string) report.GoSymbolQuery {
	t.Helper()
	raw, ok := f.queries[[2]string{asset, container}]
	if !ok {
		t.Fatalf("no query for %s/%q", asset, container)
	}
	var q report.GoSymbolQuery
	if err := json.Unmarshal(raw.Query, &q); err != nil {
		t.Fatal(err)
	}
	return q
}

// TestSymbolCheckNodes: the needs of a workload container that a node agent
// runs go to that agent, together with the host's own.
func TestSymbolCheckNodes(t *testing.T) {
	host := goInputs()
	host.Sources = host.Sources[:1]
	host.GoBinaries = host.GoBinaries[:1]

	wl := goInputs()
	wl.Kind = store.AssetWorkload
	wl.Sources = wl.Sources[1:]
	wl.GoBinaries = wl.GoBinaries[1:]
	wl.NodeContainers = []store.FindingNodeContainer{{Container: "web", Pod: "web-1", HostID: "h", HostName: "node-1",
		HostContainer: "app/web-1/web", RuntimeID: "rid-web", Fresh: true}}

	f := &symbolFake{
		inputs: map[string]store.FindingInputs{"h": host, "w": wl},
		assets: map[string]store.AssetDetail{
			"h": {Asset: store.Asset{ID: "h", Kind: store.AssetHost, AgentID: "ag"}},
			"w": {Asset: store.Asset{ID: "w", Kind: store.AssetWorkload}},
		},
		agents:  map[string]store.Agent{"ag": {ID: "ag", Features: []string{store.FeatureGoSymbols}}},
		queries: map[[2]string]store.GoSymbolQuery{},
		sent:    map[string]int{},
	}
	c := NewSymbolChecker(f, f, nil)
	now := time.Now()
	n, err := c.check(context.Background(), "w", now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || f.sent["ag"] != 1 {
		t.Fatalf("queries %d, directives %v", n, f.sent)
	}
	// The exec path keeps its query for the scanner.
	if q := f.query(t, "w", "web"); len(q.Files) != 1 {
		t.Errorf("workload query %+v", q)
	}
	q := f.query(t, "h", "")
	var containers []string
	for _, file := range q.Files {
		containers = append(containers, file.Container)
	}
	slices.Sort(containers)
	if !slices.Equal(containers, []string{"", "rid-web"}) {
		t.Fatalf("host query files %+v", q.Files)
	}

	// Another workload's needs later join the waiting query.
	other := wl
	other.NodeContainers = []store.FindingNodeContainer{{Container: "web", Pod: "api-1", HostID: "h",
		HostContainer: "app/api-1/web", RuntimeID: "rid-api", Fresh: true}}
	f.inputs["w2"] = other
	f.assets["w2"] = store.AssetDetail{Asset: store.Asset{ID: "w2", Kind: store.AssetWorkload}}
	if _, err := c.check(context.Background(), "w2", now); err != nil {
		t.Fatal(err)
	}
	containers = nil
	for _, file := range f.query(t, "h", "").Files {
		containers = append(containers, file.Container)
	}
	slices.Sort(containers)
	if !slices.Equal(containers, []string{"", "rid-api", "rid-web"}) {
		t.Fatalf("merged host query %v", containers)
	}

	// A host that stopped reporting is not asked.
	stale := wl
	stale.NodeContainers = []store.FindingNodeContainer{{Container: "web", HostID: "h", RuntimeID: "rid-web"}}
	f.inputs["w3"] = stale
	f.assets["w3"] = store.AssetDetail{Asset: store.Asset{ID: "w3", Kind: store.AssetWorkload}}
	before := f.sent["ag"]
	if _, err := c.check(context.Background(), "w3", now); err != nil {
		t.Fatal(err)
	}
	if f.sent["ag"] != before {
		t.Error("stale host asked")
	}
}

func TestMergeQuery(t *testing.T) {
	sha1, sha2 := strings.Repeat("1", 64), strings.Repeat("2", 64)
	a := report.GoSymbolQuery{Files: []report.GoSymbolFile{{Container: "c", Path: "/a", SHA256: sha1, Names: []string{"x"}}}}
	b := report.GoSymbolQuery{Files: []report.GoSymbolFile{
		{Container: "c", Path: "/a", SHA256: sha1, Names: []string{"x", "y"}},
		{Container: "d", Path: "/b", SHA256: sha2, Names: []string{"z"}},
	}}
	got := mergeQuery(a, b)
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(got.Files) != 2 || !slices.Equal(got.Files[0].Names, []string{"x", "y"}) || got.Files[1].Path != "/b" {
		t.Errorf("merged %+v", got.Files)
	}
}
