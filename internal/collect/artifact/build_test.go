// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package artifact

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bomcensus/bomcensus/internal/report"
)

func TestDetectorBuild(t *testing.T) {
	for _, tc := range []struct {
		tag, name, version, build, cpe string
	}{
		{"NAC-CLOUD-R-117458-5.0.54.0720", "genian-nac", "5.0.54.0720", "117458",
			"cpe:2.3:a:genians:genian_nac:5.0.54.0720:*:*:*:*:*:*:*"},
		{"NAC-CLOUD-R-120001-6.0.15.0101", "genian-ztna", "6.0.15.0101", "120001",
			"cpe:2.3:a:genians:genian_ztna:6.0.15.0101:*:*:*:*:*:*:*"},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "usr/geni"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "usr/geni/centerd"), tinyELF(t, "x", "", 0), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, ".version"), []byte(tc.tag+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			sec := testCollector(testEnv(root), Inputs{}, "/", detectorByID(t, "genian-nac")).run(context.Background())
			var got *report.Artifact
			for i := range sec.Artifacts {
				if sec.Artifacts[i].Kind == report.ArtifactSoftware {
					got = &sec.Artifacts[i]
				}
			}
			if got == nil {
				t.Fatalf("no software artifact in %+v", sec.Artifacts)
			}
			if got.Name != tc.name || got.Version != tc.version || got.Build != tc.build || got.CPE != tc.cpe {
				t.Fatalf("got %s %s build %q cpe %s", got.Name, got.Version, got.Build, got.CPE)
			}
		})
	}
}

func TestRuleWithoutBuildGroup(t *testing.T) {
	m, ok := firstMatch(detectorByID(t, "nginx").Static[0].Rules, []byte("nginx version: nginx/1.27.5"))
	if !ok || m.Version != "1.27.5" || m.Build != "" {
		t.Fatalf("got %+v ok=%v", m, ok)
	}
}
