// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package vulnsvc

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// goInputs is a host running one Go binary that has stdlib with two
// vulnerabilities, and the same binary in container "web".
func goInputs() store.FindingInputs {
	std := store.Component{ID: "std", Type: "golang", Name: "stdlib", Version: "1.22.0"}
	bin := "/usr/local/bin/app"
	return store.FindingInputs{
		Kind: store.AssetHost,
		Sources: []store.FindingSource{
			{Component: std, Locations: []string{bin}, VulnIDs: []string{"GO-1", "GO-2", "GO-3"}},
			{Container: "web", Layer: store.FindingLayerRuntime, Component: std, Locations: []string{bin}, VulnIDs: []string{"GO-1"}},
		},
		Processes: []store.FindingProcess{
			{PID: 1, Exe: bin, Ports: []string{"tcp/443"}},
			{Container: "web", PID: 2, Exe: bin},
		},
		ProcessCoverage: map[string]store.Coverage{"": store.CoverageFull},
		HashComponents:  map[string][]string{},
		Symbols: map[string][]store.GoImport{
			store.SymbolKey("std", "GO-1"): {{Path: "net/http", Symbols: []string{"Server.Serve", "Serve"}}},
			store.SymbolKey("std", "GO-2"): {{Path: "crypto/tls", Symbols: []string{"Conn.Handshake"}}},
			// Only for windows builds.
			store.SymbolKey("std", "GO-3"): {{Path: "os", Symbols: []string{"Open"}, GOOS: []string{"windows"}}},
		},
		GoBinaries: []store.FindingGoBinary{
			{GoBinary: store.GoBinary{Path: bin, SHA256: "aa", GOOS: "linux", GOARCH: "amd64"}},
			{Container: "web", Layer: store.FindingLayerRuntime, GoBinary: store.GoBinary{Path: bin, SHA256: "bb", GOOS: "linux"}},
		},
		SymbolResults: map[string]map[string]store.GoSymbolResult{},
	}
}

func setAnswer(in store.FindingInputs, sha, name, result string) {
	if in.SymbolResults[sha] == nil {
		in.SymbolResults[sha] = map[string]store.GoSymbolResult{}
	}
	in.SymbolResults[sha][name] = store.GoSymbolResult{SHA256: sha, Name: name, Result: result, CheckedAt: time.Now()}
}

func rowsByKey(rows []store.FindingRow) map[string]store.FindingRow {
	out := map[string]store.FindingRow{}
	for _, r := range rows {
		out[r.Container+"/"+r.VulnID] = r
	}
	return out
}

func TestReachability(t *testing.T) {
	in := goInputs()
	// Nothing answered: not known, exposure from the processes.
	got := rowsByKey(Compute(in))
	if r := got["/GO-1"]; r.Reachability != "" || r.Exposure != store.ExposureListening {
		t.Fatalf("unanswered: %+v", r)
	}
	// An import for another target does not count: GO-3 is absent on linux.
	if r := got["/GO-3"]; r.Reachability != store.ReachSymbolAbsent || r.Exposure != store.ExposureInstalled {
		t.Errorf("other target: %+v", r)
	}

	// One name absent, the other not checked: still not known.
	setAnswer(in, "aa", "net/http.Server.Serve", store.GoSymbolAbsent)
	setAnswer(in, "aa", "net/http.Serve", store.GoSymbolNotChecked)
	if r := rowsByKey(Compute(in))["/GO-1"]; r.Reachability != "" {
		t.Errorf("not checked: %+v", r)
	}
	// Both absent: absent, and the listening exposure drops to installed.
	setAnswer(in, "aa", "net/http.Serve", store.GoSymbolAbsent)
	setAnswer(in, "aa", "crypto/tls.Conn.Handshake", store.GoSymbolPresent)
	got = rowsByKey(Compute(in))
	if r := got["/GO-1"]; r.Reachability != store.ReachSymbolAbsent || r.Exposure != store.ExposureInstalled {
		t.Errorf("absent: %+v", r)
	}
	if r := got["/GO-2"]; r.Reachability != store.ReachSymbolPresent || r.Exposure != store.ExposureListening {
		t.Errorf("present: %+v", r)
	}
	// The container's binary has another hash: the host's answers are not
	// its answers.
	if r := got["web/GO-1"]; r.Reachability != "" {
		t.Errorf("container: %+v", r)
	}
	setAnswer(in, "bb", "net/http.Serve", store.GoSymbolPresent)
	if r := rowsByKey(Compute(in))["web/GO-1"]; r.Reachability != store.ReachSymbolPresent || r.Exposure != store.ExposureRunning {
		t.Errorf("container present: %+v", r)
	}

	// Without a Go binary at the location there is nothing to decide.
	in = goInputs()
	in.GoBinaries = nil
	for k, r := range rowsByKey(Compute(in)) {
		if r.Reachability != "" {
			t.Errorf("%s without binaries: %+v", k, r)
		}
	}
}

func TestSymbolNeeds(t *testing.T) {
	in := goInputs()
	now := time.Now()
	needs := SymbolNeeds(in, now.Add(-SymbolRetryAfter))
	slices.SortFunc(needs, func(a, b SymbolNeed) int { return compareStrings(a.Container, b.Container) })
	if len(needs) != 2 || needs[0].Container != "" || needs[1].Container != "web" {
		t.Fatalf("needs %+v", needs)
	}
	// GO-3 is for windows only and not asked.
	if want := []string{"crypto/tls.Conn.Handshake", "net/http.Serve", "net/http.Server.Serve"}; !slices.Equal(needs[0].Names, want) {
		t.Errorf("host names %v", needs[0].Names)
	}

	// Answered names are not asked again; a recent not checked neither, an
	// old one is.
	setAnswer(in, "aa", "net/http.Server.Serve", store.GoSymbolAbsent)
	setAnswer(in, "aa", "net/http.Serve", store.GoSymbolNotChecked)
	in.SymbolResults["aa"]["crypto/tls.Conn.Handshake"] = store.GoSymbolResult{Result: store.GoSymbolNotChecked,
		CheckedAt: now.Add(-2 * SymbolRetryAfter)}
	for _, n := range SymbolNeeds(in, now.Add(-SymbolRetryAfter)) {
		if n.Container == "" && !slices.Equal(n.Names, []string{"crypto/tls.Conn.Handshake"}) {
			t.Errorf("retry: %v", n.Names)
		}
	}
	// A binary already known to link a vulnerable function of every
	// vulnerability is left out.
	setAnswer(in, "bb", "net/http.Serve", store.GoSymbolPresent)
	for _, n := range SymbolNeeds(in, now.Add(-SymbolRetryAfter)) {
		if n.Container == "web" {
			t.Errorf("decided binary asked: %+v", n)
		}
	}
}

func compareStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func TestBuildQuery(t *testing.T) {
	var needs []SymbolNeed
	for i := range report.MaxGoSymbolFiles + 10 {
		names := make([]string, 100)
		for j := range names {
			names[j] = fmt.Sprintf("p.F%d", j)
		}
		needs = append(needs, SymbolNeed{Container: []string{"", "web", "gone"}[i%3], Path: fmt.Sprintf("/bin/%d", i),
			SHA256: fmt.Sprintf("%064d", i), Names: names})
	}
	runtime := containerRuntime(map[string]string{"web": "abc123"})
	q := buildQuery(needs, runtime)
	if err := q.Validate(); err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, f := range q.Files {
		total += len(f.Names)
		if f.Path == "" || (f.Container != "" && f.Container != "abc123") {
			t.Errorf("file %+v", f)
		}
	}
	if total != report.MaxGoSymbolNames {
		t.Errorf("%d names, want the limit %d", total, report.MaxGoSymbolNames)
	}
	// Needs of containers without a runtime id are left out.
	for _, f := range q.Files {
		if f.Path == "/bin/2" {
			t.Error("container without runtime id asked")
		}
	}
}
