// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package ingest

import (
	"strings"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

func integrityReport(at time.Time, pass string, done bool, findings ...report.IntegrityFinding) *report.Report {
	return &report.Report{
		SchemaVersion: report.SchemaVersion, CollectedAt: at, Subject: &report.Subject{Kind: report.SubjectSelf},
		Privilege: report.Privilege{Level: report.PrivilegePrivileged},
		Integrity: &report.IntegritySection{SectionMeta: meta(at, report.CoverageFull), PassID: pass,
			PassDone: done, Packages: 3, Checked: 40, UTCOffsetSeconds: 3600, Findings: findings},
	}
}

func TestIntegrityChunkIngest(t *testing.T) {
	f := newFixture(t)
	must(t, f.ingest(t, f.agent, hostReport(t0)))
	agent, err := f.db.GetAgent(f.ctx, f.agent.ID)
	must(t, err)

	good := report.IntegrityFinding{PkgType: "deb", Package: "openssh-server", Version: "1:9.6p1", Path: "/usr/sbin/sshd",
		Status: report.IntegrityModified, Algo: "md5", Expected: strings.Repeat("a", 32), Actual: strings.Repeat("b", 32),
		ActualSHA256: strings.Repeat("C", 64), Size: 9, Mtime: t0}
	badHex := good
	badHex.Path, badHex.Actual = "/usr/bin/x", "zz"
	noSHA := good
	noSHA.Path, noSHA.ActualSHA256 = "/usr/bin/y", ""
	missing := report.IntegrityFinding{PkgType: "rpm", Package: "at", Version: "3", Path: "/usr/bin/at",
		Status: report.IntegrityMissing, Algo: "sha256", Expected: strings.Repeat("d", 64)}
	must(t, f.ingest(t, f.agent, integrityReport(t0.Add(time.Hour), "pass-1", true, good, badHex, noSHA, missing)))

	fs, total, err := f.db.ListIntegrityFindings(f.ctx, store.IntegrityFilter{}, store.Page{})
	must(t, err)
	if total != 2 {
		t.Fatalf("findings %+v", fs)
	}
	for _, x := range fs {
		if x.AssetID != agent.AssetID {
			t.Errorf("finding on asset %s, want %s", x.AssetID, agent.AssetID)
		}
		if x.Path == "/usr/sbin/sshd" && x.ActualSHA256 != strings.Repeat("c", 64) {
			t.Errorf("sha256 not lower-cased: %+v", x)
		}
	}
	p, err := f.db.LastCompletedIntegrityPass(f.ctx, agent.AssetID)
	must(t, err)
	if p.PassKey != "pass-1" || p.Checked != 40 || p.UTCOffset == nil || *p.UTCOffset != 3600 {
		t.Errorf("pass %+v", p)
	}

	// A chunk that checked nothing (package manager busy) is not recorded.
	busy := integrityReport(t0.Add(2*time.Hour), "pass-2", false)
	busy.Integrity.Packages, busy.Integrity.Coverage = 0, report.CoverageNone
	must(t, f.ingest(t, f.agent, busy))
	if last, err := f.db.LastIntegrityPass(f.ctx, agent.AssetID); err != nil || last.PassKey != "pass-1" {
		t.Errorf("busy chunk recorded: %+v %v", last, err)
	}
}
