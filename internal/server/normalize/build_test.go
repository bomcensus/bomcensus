// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package normalize

import (
	"testing"

	"github.com/bomcensus/bomcensus/internal/report"
)

func TestArtifactBuild(t *testing.T) {
	a := report.Artifact{Kind: report.ArtifactSoftware, Name: "genian-nac", Version: "5.0.54.0720", Build: "117458",
		PURL: "pkg:generic/genians/genian-nac@5.0.54.0720", CPE: "cpe:2.3:a:genians:genian_nac:5.0.54.0720:*:*:*:*:*:*:*"}
	cs := Artifact(a)
	if len(cs) != 1 || cs[0].Build != "117458" || cs[0].Version != "5.0.54.0720" || cs[0].CPE != a.CPE {
		t.Fatalf("components %+v", cs)
	}
	a.Build = ""
	if cs := Artifact(a); cs[0].Build != "" {
		t.Fatalf("build without one: %+v", cs)
	}
}
