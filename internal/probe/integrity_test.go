// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package probe

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/bomcensus/bomcensus/internal/report"
)

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, c := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRunIntegrity(t *testing.T) {
	root := t.TempDir()
	sum := md5.Sum([]byte("original"))
	writeTree(t, root, map[string]string{
		"var/lib/dpkg/status":            "Package: tool\nStatus: install ok installed\nArchitecture: all\nVersion: 1\n",
		"var/lib/dpkg/info/tool.list":    "/usr/bin/tool\n",
		"var/lib/dpkg/info/tool.md5sums": hex.EncodeToString(sum[:]) + "  usr/bin/tool\n",
		"usr/bin/tool":                   "tampered",
	})
	req := report.Request{
		Sections:  []string{report.SectionIntegrity},
		Policy:    report.DefaultPolicy(),
		Integrity: &report.IntegrityQuery{PassID: "p1", MaxReadMBps: 100},
	}
	rep, err := Run(context.Background(), req, Options{Root: root, Proc: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Host != nil || rep.Packages != nil || rep.Processes != nil {
		t.Error("other sections collected")
	}
	if rep.Cache != nil {
		t.Error("collection cache returned by an integrity run")
	}
	sec := rep.Integrity
	if sec == nil || !sec.PassDone || sec.PassID != "p1" || len(sec.Findings) != 1 || sec.Findings[0].Path != "/usr/bin/tool" {
		t.Fatalf("integrity %+v", sec)
	}
	if len(sec.Cache) == 0 {
		t.Error("integrity cache missing")
	}
}

func TestIntegrityRequestLimits(t *testing.T) {
	for name, req := range map[string]report.Request{
		"no pass id": {Sections: []string{report.SectionIntegrity}, Integrity: &report.IntegrityQuery{}},
		"too long": {Sections: []string{report.SectionIntegrity}, Integrity: &report.IntegrityQuery{PassID: "p"},
			Policy: report.Policy{MaxRuntimeSeconds: report.MaxIntegrityRuntimeSeconds + 1}},
		"relative exclude": {Sections: []string{report.SectionIntegrity},
			Integrity: &report.IntegrityQuery{PassID: "p", ExcludePaths: []string{"usr"}}},
		"no query": {Sections: []string{report.SectionIntegrity}},
	} {
		if _, err := Run(context.Background(), req, Options{Root: t.TempDir()}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
