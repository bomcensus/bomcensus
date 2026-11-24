// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/server/dispatch"
	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/internal/server/vulnsvc"
)

type recordedDirectives struct{ sent []dispatch.Directive }

func (r *recordedDirectives) Enqueue(_ context.Context, _ string, d dispatch.Directive) (string, error) {
	r.sent = append(r.sent, d)
	return "d1", nil
}

type findingState struct{ exposure, reach string }

func goFindings(t *testing.T, f *fixture, assetID string) map[string]findingState {
	t.Helper()
	rows, err := f.db.Pool().Query(f.ctx, `
		SELECT vuln_id, exposure, coalesce(reachability, '') FROM findings
		WHERE asset_id = $1 AND resolved_at IS NULL AND vuln_id LIKE 'GO-%'`, assetID)
	must(t, err)
	defer rows.Close()
	out := map[string]findingState{}
	for rows.Next() {
		var id string
		var s findingState
		must(t, rows.Scan(&id, &s.exposure, &s.reach))
		out[id] = s
	}
	must(t, rows.Err())
	return out
}

func TestGoSymbolQuery(t *testing.T) {
	f := newFixture(t)
	ctx := f.ctx
	r := hostReport(t0)
	for i := range r.Artifacts.Artifacts {
		if r.Artifacts.Artifacts[i].Path == "/opt/app/app" && r.Artifacts.Artifacts[i].Kind == "go_binary" {
			r.Artifacts.Artifacts[i].GOOS, r.Artifacts.Artifacts[i].GOARCH = "linux", "amd64"
		}
	}
	must(t, f.ingest(t, f.agent, r))
	agent, err := f.db.GetAgent(ctx, f.agent.ID)
	must(t, err)
	assetID := agent.AssetID

	// A second host runs the same binary; answers of the first are not
	// used for it.
	other := f.newAgent(t, store.AgentKindAgent, "regkey00001")
	r2 := hostReport(t0)
	r2.Host.Hostname, r2.Host.MachineID = "web-02", "machine-web-02"
	r2.Artifacts = r.Artifacts
	must(t, f.ingest(t, other, r2))
	other, err = f.db.GetAgent(ctx, other.ID)
	must(t, err)

	// Match: golang.org/x/net and the standard library of the app have a
	// vulnerability each, with their functions.
	srv, err := f.db.GetActiveFeedServer(ctx)
	must(t, err)
	epoch := store.MatchEpoch{ServerID: srv.ID, Revision: 1}
	pending, err := f.db.PendingMatches(ctx, epoch, 100)
	must(t, err)
	var batch []store.ComponentMatch
	for _, c := range pending {
		m := store.ComponentMatch{ComponentID: c.ID, Status: store.MatchChecked}
		switch {
		case c.Name == "golang.org/x/net":
			m.Vulns = []store.ComponentVuln{{VulnID: "GO-1", Method: "package", FixState: "fixed",
				Symbols: []store.GoImport{{Path: "golang.org/x/net/html", Symbols: []string{"Parse"}}}}}
		case c.Name == "stdlib" && c.Version == "1.22.1":
			m.Vulns = []store.ComponentVuln{{VulnID: "GO-2", Method: "package", FixState: "fixed",
				Symbols: []store.GoImport{{Path: "net/http", Symbols: []string{"Serve"}}}}}
		}
		batch = append(batch, m)
	}
	must(t, f.db.SaveMatches(ctx, store.MatchBatch{Epoch: epoch, Components: batch,
		Vulns: []store.VulnMeta{{ID: "GO-1"}, {ID: "GO-2"}}}))
	refresh := func() {
		t.Helper()
		rf, err := vulnsvc.NewRefresher(f.db, nil, nil)
		must(t, err)
		must(t, rf.Run(ctx))
	}
	refresh()
	got := goFindings(t, f, assetID)
	if got["GO-1"] != (findingState{store.ExposureListening, ""}) || got["GO-2"] != (findingState{store.ExposureListening, ""}) {
		t.Fatalf("before the query: %+v", got)
	}

	// An agent without the feature is not asked.
	sent := &recordedDirectives{}
	checker := vulnsvc.NewSymbolChecker(f.db, sent, nil)
	must(t, checker.Run(ctx))
	if len(sent.sent) != 0 {
		t.Fatalf("asked an agent without the feature: %+v", sent.sent)
	}
	for _, a := range []store.Agent{agent, other} {
		must(t, f.db.UpdateAgentPoll(ctx, a.ID, store.AgentPollStatus{Hostname: a.Hostname, Version: "test", OS: "linux",
			Arch: "amd64", ConnectMode: a.ConnectMode, TLSMode: a.TLSMode, Privilege: a.Privilege, UpdateState: a.UpdateState,
			Features: []string{store.FeatureGoSymbols}, SeenAt: t0}))
	}
	must(t, checker.Run(ctx))
	if len(sent.sent) != 2 {
		t.Fatalf("directives %d, want one per host", len(sent.sent))
	}
	w, err := f.db.GoSymbolQueryFor(ctx, assetID, "")
	must(t, err)
	var q report.GoSymbolQuery
	must(t, json.Unmarshal(w.Query, &q))
	if len(q.Files) != 1 || q.Files[0].Path != "/opt/app/app" || q.Files[0].SHA256 != appSHA || len(q.Files[0].Names) != 2 {
		t.Fatalf("query %+v", q)
	}
	// Asked once: the next run within the query's lifetime asks nothing.
	must(t, checker.Run(ctx))
	if len(sent.sent) != 2 {
		t.Fatalf("asked again: %d", len(sent.sent))
	}

	// The answer: html.Parse is not linked, net/http.Serve is. A name that
	// was not asked is ignored.
	ans := &report.Report{SchemaVersion: report.SchemaVersion, ProbeVersion: "test", CollectedAt: t0.Add(time.Hour),
		Subject: &report.Subject{Kind: report.SubjectSelf}, Privilege: report.Privilege{Level: report.PrivilegePrivileged},
		GoSymbols: &report.GoSymbolsSection{SectionMeta: meta(t0.Add(time.Hour), report.CoverageFull),
			Files: []report.GoSymbolAnswer{{Path: "/opt/app/app", SHA256: appSHA, Results: map[string]string{
				"golang.org/x/net/html.Parse": report.GoSymbolAbsent,
				"net/http.Serve":              report.GoSymbolPresent,
				"os.Open":                     report.GoSymbolAbsent,
			}}}}}
	must(t, f.ingest(t, f.agent, ans))
	if _, err := f.db.GoSymbolQueryFor(ctx, assetID, ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("query after the answer: %v", err)
	}
	var n int
	must(t, f.db.Pool().QueryRow(ctx, `SELECT count(*) FROM go_symbol_results WHERE asset_id = $1`, assetID).Scan(&n))
	if n != 2 {
		t.Fatalf("%d results stored, want 2", n)
	}

	refresh()
	got = goFindings(t, f, assetID)
	if got["GO-1"] != (findingState{store.ExposureInstalled, store.ReachSymbolAbsent}) {
		t.Errorf("absent: %+v", got["GO-1"])
	}
	if got["GO-2"] != (findingState{store.ExposureListening, store.ReachSymbolPresent}) {
		t.Errorf("present: %+v", got["GO-2"])
	}
	for id, s := range goFindings(t, f, other.AssetID) {
		if s.reach != "" {
			t.Errorf("other host %s: %+v", id, s)
		}
	}

	// New functions for a known vulnerability make the findings out of
	// date.
	if dirty, err := f.db.DirtyFindingAssets(ctx, 10); err != nil || len(dirty) != 0 {
		t.Fatalf("dirty before: %v %v", dirty, err)
	}
	for i := range batch {
		for j := range batch[i].Vulns {
			if batch[i].Vulns[j].VulnID == "GO-1" {
				batch[i].Vulns[j].Symbols = append(batch[i].Vulns[j].Symbols,
					store.GoImport{Path: "golang.org/x/net/html", Symbols: []string{"Render"}})
			}
		}
	}
	must(t, f.db.SaveMatches(ctx, store.MatchBatch{Epoch: epoch, Components: batch,
		Vulns: []store.VulnMeta{{ID: "GO-1"}, {ID: "GO-2"}}}))
	dirty, err := f.db.DirtyFindingAssets(ctx, 10)
	must(t, err)
	if len(dirty) != 2 {
		t.Fatalf("dirty after new functions: %v", dirty)
	}
	refresh()
	if got := goFindings(t, f, assetID)["GO-1"]; got.reach != "" {
		t.Errorf("GO-1 with an unanswered function: %+v", got)
	}

	// Answers arriving without a query are dropped.
	must(t, f.ingest(t, f.agent, ans))
	must(t, f.db.Pool().QueryRow(ctx, `SELECT count(*) FROM go_symbol_results WHERE asset_id = $1`, assetID).Scan(&n))
	if n != 2 {
		t.Fatalf("%d results after an unasked answer", n)
	}
}
