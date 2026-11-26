// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package artifact

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/bomcensus/bomcensus/internal/detectors"
	"github.com/bomcensus/bomcensus/internal/report"
)

// comparable is a detector with its patterns as text.
func comparableDetector(d *Detector) any {
	type rule struct{ Pattern, Name, PURL, CPE string }
	conv := func(rs []Rule) []rule {
		var out []rule
		for _, r := range rs {
			out = append(out, rule{r.Pattern.String(), r.Name, r.PURL, r.CPE})
		}
		return out
	}
	type static struct {
		File, Entry, BuildSetting string
		GoMain                    bool
		Rules                     []rule
		Limit                     int64
	}
	var st []static
	for _, s := range d.Static {
		st = append(st, static{s.File, s.Entry, s.BuildSetting, s.GoMain, conv(s.Rules), s.Limit})
	}
	return struct {
		ID, Name       string
		Names, Paths   []string
		Archive        bool
		Exec           []string
		Env            []EnvVar
		Parse          []rule
		AddressSpaceMB int
		Static         []static
		PURL, CPE      string
		Constrained    bool
		CacheTag       string
	}{d.ID, d.Name, d.Names, d.Paths, d.Archive, d.Exec, d.Env, conv(d.Parse), d.AddressSpaceMB, st, d.PURL, d.CPE,
		d.constrained, d.cacheTag}
}

// TestBuiltinTableUnchanged checks that the embedded YAML table is the
// table that was written in Go.
func TestBuiltinTableUnchanged(t *testing.T) {
	if len(Detectors) != len(legacyDetectors) {
		t.Fatalf("%d detectors, the Go table had %d", len(Detectors), len(legacyDetectors))
	}
	for i := range legacyDetectors {
		got, want := comparableDetector(Detectors[i]), comparableDetector(legacyDetectors[i])
		if !reflect.DeepEqual(got, want) {
			g, _ := json.MarshalIndent(got, "", " ")
			w, _ := json.MarshalIndent(want, "", " ")
			t.Errorf("detector %d differs:\n got %s\nwant %s", i, g, w)
		}
	}
}

// TestSuppliedBuiltinTable: the built-in table sent back by a server is
// used exactly like the built-in one.
func TestSuppliedBuiltinTable(t *testing.T) {
	r := detectors.Resolve(detectors.Builtin())
	if r.Use.Source != report.DetectorsRequest || len(r.Use.Rejected) > 0 || len(r.Use.StaticOnly) > 0 {
		t.Fatalf("use %+v", r.Use)
	}
	got := Load(r)
	for i := range got {
		if !reflect.DeepEqual(comparableDetector(got[i]), comparableDetector(Detectors[i])) {
			t.Errorf("detector %s differs", got[i].ID)
		}
	}
}

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, content := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func softwareOf(sec *report.ArtifactsSection) map[string]report.Artifact {
	out := map[string]report.Artifact{}
	for _, a := range sec.Artifacts {
		if a.Kind == report.ArtifactSoftware {
			out[a.Path] = a
		}
	}
	return out
}

func loadOne(t *testing.T, spec report.DetectorSpec) []*Detector {
	t.Helper()
	r := detectors.Resolve(&report.DetectorTable{SchemaVersion: report.DetectorSchemaVersion, Detectors: []report.DetectorSpec{spec}})
	if len(r.Use.Rejected) > 0 {
		t.Fatalf("rejected: %+v", r.Use.Rejected)
	}
	return Load(r)
}

// TestConstrainedSideFiles: side files of a detector that is not built in
// are not followed through symbolic links, not read in denied locations,
// and only version-shaped captures are reported.
func TestConstrainedSideFiles(t *testing.T) {
	root := t.TempDir()
	elf := string(tinyELF(t, "x", "", 0))
	writeTree(t, root, map[string]string{
		"opt/app/bin/appd":      elf,
		"opt/app/VERSION":       "app 4.2.1\n",
		"opt/link/bin/appd":     elf,
		"opt/l2/bin/appd":       elf,
		"opt/elsewhere/VERSION": "app 7.7.7\n",
		"opt/bad/bin/appd":      elf,
		"opt/bad/VERSION":       "app hunter2-password\n",
		"home/u/app/bin/appd":   elf,
		"home/u/app/VERSION":    "app 1.0.0\n",
	})
	// A symbolic link to a version file elsewhere is not followed.
	if err := os.Symlink(filepath.Join(root, "opt/elsewhere/VERSION"), filepath.Join(root, "opt/link/VERSION")); err != nil {
		t.Fatal(err)
	}
	// Nor is a link to a directory on the way.
	if err := os.Symlink("../elsewhere", filepath.Join(root, "opt/l2/conf")); err != nil {
		t.Fatal(err)
	}
	dets := loadOne(t, report.DetectorSpec{
		ID: "custom-app", Name: "app", Names: []string{"appd"},
		Static: []report.DetectorStatic{
			{File: "../VERSION", Rules: []report.DetectorRule{{Pattern: `app (\S+)`}}},
			{File: "../conf/VERSION", Rules: []report.DetectorRule{{Pattern: `app (\S+)`}}},
		},
		PURL: "pkg:generic/app@{version}",
	})
	if !dets[0].constrained || dets[0].cacheTag == "" {
		t.Fatalf("detector %+v", dets[0])
	}
	sec := testCollector(testEnv(root), Inputs{}, "/", dets...).run(context.Background())
	got := softwareOf(sec)
	want := map[string]string{
		"/opt/app/bin/appd":    "4.2.1",
		"/opt/link/bin/appd":   "",
		"/opt/l2/bin/appd":     "",
		"/opt/bad/bin/appd":    "",
		"/home/u/app/bin/appd": "",
	}
	for p, v := range want {
		a, ok := got[p]
		if !ok {
			t.Errorf("%s not reported", p)
			continue
		}
		if a.Version != v {
			t.Errorf("%s: version %q, want %q", p, a.Version, v)
		}
	}

	// Built-in detectors follow the directory link, as they always did.
	builtinLike := *dets[0]
	builtinLike.constrained, builtinLike.cacheTag = false, ""
	sec = testCollector(testEnv(root), Inputs{}, "/", &builtinLike).run(context.Background())
	if v := softwareOf(sec)["/opt/l2/bin/appd"].Version; v != "7.7.7" {
		t.Errorf("built-in side file through a directory link: %q", v)
	}

}

// TestConstrainedGlobLimit: a glob side file of a detector that is not
// built in reads at most detectors.MaxSideFileMatches files.
func TestConstrainedGlobLimit(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{"opt/app/bin/appd": string(tinyELF(t, "x", "", 0))}
	for i := range 20 {
		files[fmt.Sprintf("opt/app/conf/v%02d", i)] = "nothing here\n"
	}
	files["opt/app/conf/v15"] = "app 4.2.1\n"
	writeTree(t, root, files)
	dets := loadOne(t, report.DetectorSpec{ID: "custom-app", Name: "app", Names: []string{"appd"},
		Static: []report.DetectorStatic{{File: "../conf/v*", Rules: []report.DetectorRule{{Pattern: `app (\S+)`}}}}})
	sec := testCollector(testEnv(root), Inputs{}, "/", dets...).run(context.Background())
	if v := softwareOf(sec)["/opt/app/bin/appd"].Version; v != "" {
		t.Fatalf("read past the limit: %q", v)
	}
	builtinLike := *dets[0]
	builtinLike.constrained, builtinLike.cacheTag = false, ""
	sec = testCollector(testEnv(root), Inputs{}, "/", &builtinLike).run(context.Background())
	if v := softwareOf(sec)["/opt/app/bin/appd"].Version; v != "4.2.1" {
		t.Fatalf("built-in glob: %q", v)
	}
}

// TestConstrainedCacheKeys: a changed rule of a detector with the same id
// does not reuse the cached result of the old rule.
func TestConstrainedCacheKeys(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"usr/bin/appd": string(tinyELF(t, "x", "\x00appd/2.0.1\x00appd-legacy 1.0.0\x00", 0))})
	env := testEnv(root)
	spec := report.DetectorSpec{ID: "custom-app", Name: "app", Names: []string{"appd"},
		Static: []report.DetectorStatic{{Rules: []report.DetectorRule{{Pattern: `appd/(\d+\.\d+\.\d+)`}}}}}
	a := testCollector(env, Inputs{}, "/", loadOne(t, spec)...).run(context.Background())
	spec.Static[0].Rules[0].Pattern = `appd-legacy (\d+\.\d+\.\d+)`
	b := testCollector(env, Inputs{}, "/", loadOne(t, spec)...).run(context.Background())
	if va, vb := softwareOf(a)["/usr/bin/appd"].Version, softwareOf(b)["/usr/bin/appd"].Version; va != "2.0.1" || vb != "1.0.0" {
		t.Fatalf("versions %q %q", va, vb)
	}
}

// TestConstrainedCapture: what a rule of a supplied table captures from the
// matched file must look like a version.
func TestConstrainedCapture(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"usr/bin/appd": string(tinyELF(t, "x", "\x00KEY=s3cr3t/value+with$chars\x00", 0))})
	dets := loadOne(t, report.DetectorSpec{ID: "grab", Name: "grab", Names: []string{"appd"},
		Static: []report.DetectorStatic{{Rules: []report.DetectorRule{{Pattern: `KEY=([^\x00]+)`}}}}})
	sec := testCollector(testEnv(root), Inputs{}, "/", dets...).run(context.Background())
	if v := softwareOf(sec)["/usr/bin/appd"].Version; v != "" {
		t.Fatalf("captured %q", v)
	}
	dets = loadOne(t, report.DetectorSpec{ID: "grab", Name: "grab", Names: []string{"appd"},
		Static: []report.DetectorStatic{{Rules: []report.DetectorRule{{Pattern: `KEY=(` + strings.Repeat(`\S`, 1) + `+)`}}}}})
	sec = testCollector(testEnv(root), Inputs{}, "/", dets...).run(context.Background())
	if v := softwareOf(sec)["/usr/bin/appd"].Version; v != "" {
		t.Fatalf("captured %q", v)
	}
}
