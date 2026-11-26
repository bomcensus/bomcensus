// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/collect"
	"github.com/bomcensus/bomcensus/internal/detectors"
	"github.com/bomcensus/bomcensus/internal/report"
)

func fakeELF(t *testing.T, p string) {
	t.Helper()
	write(t, p, []byte("\x7fELF\x02\x01\x01\x00not really an executable"))
	if err := os.Chmod(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func softwareByPath(sec *report.ArtifactsSection) map[string]report.Artifact {
	out := map[string]report.Artifact{}
	for _, a := range sec.Artifacts {
		if a.Kind == report.ArtifactSoftware {
			out[a.Path] = a
		}
	}
	return out
}

func TestRequestDetectors(t *testing.T) {
	f := newFixture(t, false)
	r := func(p string) string { return filepath.Join(f.root, p) }
	fakeELF(t, r("/opt/acme/bin/acmed"))
	write(t, r("/opt/acme/VERSION"), []byte("ACME Server 3.1.4 build 77\n"))
	fakeELF(t, r("/usr/sbin/sh"))
	write(t, r("/etc/shadow"), []byte("root:$6$salt$hash:19000:0:99999:7:::\n"))

	table := detectors.Builtin()
	table.Detectors = append(table.Detectors,
		report.DetectorSpec{ID: "acme", Name: "acme-server", Names: []string{"acmed"},
			Static: []report.DetectorStatic{{File: "../VERSION", Rules: []report.DetectorRule{
				{Pattern: `ACME Server (?P<version>\d+\.\d+\.\d+) build (?P<build>\d+)`}}}},
			PURL: "pkg:generic/acme/server@{version}"},
		// Reads the password database next to nothing it recognizes.
		report.DetectorSpec{ID: "shadow", Name: "x", Names: []string{"sh"},
			Static: []report.DetectorStatic{{File: "../../../etc/shadow", Rules: []report.DetectorRule{{Pattern: `root:([^:]+)`}}}}},
		// A shell with -c and a static rule: static only.
		report.DetectorSpec{ID: "shell", Name: "sh", Names: []string{"sh"}, Exec: []string{"-c", "id"},
			Parse:  []report.DetectorRule{{Pattern: `uid=(\d+)`}},
			Static: []report.DetectorStatic{{File: "../../etc/shadow", Rules: []report.DetectorRule{{Pattern: `root:\$6\$([^$]+)`}}}}},
		report.DetectorSpec{ID: "shell2", Name: "sh", Names: []string{"sh"}, Exec: []string{"-c", "id"},
			Parse:  []report.DetectorRule{{Pattern: `uid=(\d+)`}},
			Static: []report.DetectorStatic{{Rules: []report.DetectorRule{{Pattern: `ELF(.)`}}}}},
	)
	digest, _ := detectors.Digest(table)

	// The table travels as JSON, like from an agent.
	raw, err := json.Marshal(report.Request{Sections: []string{report.SectionArtifacts}, Detectors: table})
	if err != nil {
		t.Fatal(err)
	}
	req, err := DecodeRequest(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	rep := f.run(t, req)
	use := rep.Detectors
	if use == nil || use.Source != report.DetectorsRequest || use.Digest != digest || use.Error != "" {
		t.Fatalf("detectors %+v", use)
	}
	var rejected []string
	for _, x := range use.Rejected {
		rejected = append(rejected, x.ID)
	}
	if !slices.Equal(rejected, []string{"shadow", "shell"}) || !slices.Equal(use.StaticOnly, []string{"shell2"}) {
		t.Fatalf("rejected %v static only %v", use.Rejected, use.StaticOnly)
	}
	got := softwareByPath(rep.Artifacts)
	acme := got["/opt/acme/bin/acmed"]
	if acme.Name != "acme-server" || acme.Version != "3.1.4" || acme.Build != "77" || acme.Detector != "acme" ||
		acme.PURL != "pkg:generic/acme/server@3.1.4" || acme.Method != report.MethodStatic {
		t.Fatalf("acme %+v", acme)
	}
	if sh := got["/usr/sbin/sh"]; sh.Detector != "shell2" || sh.Version != "" || sh.VersionOutput != nil {
		t.Fatalf("sh %+v", sh)
	}
	for _, a := range rep.Artifacts.Artifacts {
		if a.Version != "" && (a.Path == "/usr/sbin/sh" || a.Path == "/etc/shadow") {
			t.Errorf("leaked %+v", a)
		}
	}

	// Without a table, and with one that cannot be used, the built-in
	// table is used and reported.
	rep = f.run(t, report.Request{Sections: []string{report.SectionArtifacts}})
	if u := rep.Detectors; u == nil || u.Source != report.DetectorsBuiltin || u.Digest != detectors.BuiltinDigest() || u.Error != "" {
		t.Fatalf("built-in %+v", u)
	}
	if _, ok := softwareByPath(rep.Artifacts)["/opt/acme/bin/acmed"]; ok {
		t.Fatal("custom detector without a table")
	}
	rep = f.run(t, report.Request{Sections: []string{report.SectionArtifacts},
		Detectors: &report.DetectorTable{SchemaVersion: 99}})
	if u := rep.Detectors; u == nil || u.Source != report.DetectorsBuiltin || u.Error == "" {
		t.Fatalf("unusable table %+v", u)
	}
	// Sections that use no detectors do not report a table.
	rep = f.run(t, report.Request{Sections: []string{report.SectionHost}, Detectors: table})
	if rep.Detectors != nil {
		t.Fatalf("host only: %+v", rep.Detectors)
	}
}

// TestImageScanReuseNeedsSameDetectors: a stored image scan made with
// another detector table is not reused.
func TestImageScanReuseNeedsSameDetectors(t *testing.T) {
	f := newFixture(t, false)
	ct1Root := filepath.Join(filepath.Dir(f.root), "ct1-rootfs")
	started := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cache := collect.NewHashCache()
	scan := func(digest string) []report.Artifact {
		t.Helper()
		env := &collect.Env{Root: f.root, Proc: f.proc, Policy: report.DefaultPolicy(), Cache: cache,
			Log: slog.New(slog.DiscardHandler), Privileged: true}
		r := &runner{env: env, log: env.Log, ctx: context.Background(), hardStop: time.Now().Add(time.Minute), limit: time.Minute,
			detectorsDigest: digest}
		sec := &report.ContainersSection{Containers: []report.Container{
			{ID: ct1ID, Name: "app-1", Running: true, InitPID: ct1PID, UpperDir: upperDir, ImageDigest: digestA, StartedAt: started},
		}}
		if r.scanContainers(sec, nil, nil) || len(sec.ImageScopes) != 1 {
			t.Fatalf("scan %+v", sec)
		}
		return sec.ImageScopes[0].Artifacts
	}
	has := func(as []report.Artifact, p string) bool {
		return slices.ContainsFunc(as, func(a report.Artifact) bool { return a.Path == p })
	}
	scan("a")
	write(t, filepath.Join(ct1Root, "app/new.jar"), jarBytes(t, "org.example", "new", "1.0"))
	if has(scan("a"), "/app/new.jar") {
		t.Fatal("same table: not reused")
	}
	if !has(scan("b"), "/app/new.jar") {
		t.Fatal("other table: reused")
	}
}
