// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package probe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bomcensus/bomcensus/internal/report"
)

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestGoSymbols(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe, _ = filepath.EvalSymlinks(exe)
	sum := fileSHA256(t, exe)
	text := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(text, []byte("not a binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	own := "github.com/bomcensus/bomcensus/internal/probe.answerGoSymbols"
	names := []string{own, "nope.Missing"}
	q := &report.GoSymbolQuery{Files: []report.GoSymbolFile{
		{Path: exe, SHA256: sum, Names: names},
		{Path: exe, SHA256: strings.Repeat("0", 64), Names: names},
		{Path: text, SHA256: fileSHA256(t, text), Names: names},
		{Path: filepath.Join(t.TempDir(), "gone"), SHA256: sum, Names: names},
		{Container: strings.Repeat("a", 64), Path: exe, SHA256: sum, Names: names},
	}}
	priv := report.Privilege{Level: report.PrivilegeNonRoot}
	rep, err := Run(context.Background(), report.Request{Sections: []string{report.SectionGoSymbols}, GoSymbols: q},
		Options{Privilege: &priv})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Host != nil || rep.Packages != nil || rep.Artifacts != nil || rep.Processes != nil || rep.Containers != nil {
		t.Fatalf("sections collected for a symbol query alone: %+v", rep)
	}
	sec := rep.GoSymbols
	if sec == nil || len(sec.Files) != len(q.Files) {
		t.Fatalf("answer %+v", sec)
	}
	first := sec.Files[0]
	if first.Results[own] != report.GoSymbolPresent || first.Results["nope.Missing"] != report.GoSymbolAbsent || first.Reason != "" {
		t.Errorf("own binary: %+v", first)
	}
	for i, want := range []string{"", "file changed", "not a Go binary", "no longer exists", "container"} {
		ans := sec.Files[i]
		if i == 0 {
			continue
		}
		if !strings.Contains(ans.Reason, want) {
			t.Errorf("file %d: reason %q, want %q", i, ans.Reason, want)
		}
		for _, n := range names {
			if ans.Results[n] != report.GoSymbolNotChecked {
				t.Errorf("file %d: %s %s", i, n, ans.Results[n])
			}
		}
	}
	if sec.Coverage != report.CoveragePartial {
		t.Errorf("coverage %s", sec.Coverage)
	}
}

func TestGoSymbolLimits(t *testing.T) {
	sum := strings.Repeat("0", 64)
	many := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = "p.F" + strings.Repeat("x", i%7)
		}
		return out
	}
	files := func(n, names int) []report.GoSymbolFile {
		out := make([]report.GoSymbolFile, n)
		for i := range out {
			out[i] = report.GoSymbolFile{Path: "/bin/x", SHA256: sum, Names: many(names)}
		}
		return out
	}
	for name, q := range map[string]report.GoSymbolQuery{
		"files":    {Files: files(report.MaxGoSymbolFiles+1, 1)},
		"per file": {Files: files(1, report.MaxGoSymbolNamesPerFile+1)},
		"total":    {Files: files(report.MaxGoSymbolNames/report.MaxGoSymbolNamesPerFile+1, report.MaxGoSymbolNamesPerFile)},
		"long":     {Files: []report.GoSymbolFile{{Path: "/bin/x", SHA256: sum, Names: []string{strings.Repeat("a", report.MaxGoSymbolNameLen+1)}}}},
		"empty":    {Files: []report.GoSymbolFile{{Path: "/bin/x", SHA256: sum, Names: []string{""}}}},
		"relative": {Files: []report.GoSymbolFile{{Path: "bin/x", SHA256: sum, Names: []string{"p.F"}}}},
		"hash":     {Files: []report.GoSymbolFile{{Path: "/bin/x", SHA256: "abc", Names: []string{"p.F"}}}},
	} {
		if _, err := Run(context.Background(), report.Request{Sections: []string{report.SectionGoSymbols}, GoSymbols: &q}, Options{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	ok := report.GoSymbolQuery{Files: files(report.MaxGoSymbolNames/report.MaxGoSymbolNamesPerFile, report.MaxGoSymbolNamesPerFile)}
	if err := ok.Validate(); err != nil {
		t.Errorf("at the limits: %v", err)
	}
	// Naming go_symbols without a query is no request at all.
	if _, err := Run(context.Background(), report.Request{Sections: []string{report.SectionGoSymbols}}, Options{}); err == nil {
		t.Error("go_symbols without a query accepted")
	}
}
