// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package vulnsvc

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

func TestBuildRequestSendsBuild(t *testing.T) {
	nac := store.Component{ID: "g", Type: "binary", Name: "genian-nac", Version: "5.0.54.0720", Build: "117458",
		CPE: "cpe:2.3:a:genians:genian_nac:5.0.54.0720:*:*:*:*:*:*:*"}
	plain := store.Component{ID: "n", Type: "binary", Name: "nginx", CPE: "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"}
	req := buildRequest([]store.Component{nac, plain})
	cs := req.Targets[0].Components
	if len(cs) != 2 || cs[0].Build != "117458" || cs[1].Build != "" {
		t.Fatalf("components %+v", cs)
	}
	raw, _ := json.Marshal(req)
	if !strings.Contains(string(raw), `"build":"117458"`) || strings.Count(string(raw), `"build"`) != 1 {
		t.Fatalf("request %s", raw)
	}
}

func TestConvertKeepsBuildUnknown(t *testing.T) {
	var res matchResult
	if err := json.Unmarshal([]byte(`{"targets":[{"id":"t0","components":[{"ref":"g","status":"checked","matches":[
		{"vuln_id":"CVE-1","method":"cpe","cpe_match":"range","range_source":"cna_rule","build_unknown":true,"fixed_version":"5.0.54.0720 build 117458"},
		{"vuln_id":"CVE-2","method":"cpe","cpe_match":"range","range_source":"nvd"}]}]}],
		"vulnerabilities":{"CVE-1":{"id":"CVE-1"},"CVE-2":{"id":"CVE-2"}}}`), &res); err != nil {
		t.Fatal(err)
	}
	b, err := convert(&res, []store.Component{{ID: "g"}}, store.MatchEpoch{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	vs := b.Components[0].Vulns
	if len(vs) != 2 || !vs[0].BuildUnknown || vs[0].RangeSource != "cna_rule" || vs[1].BuildUnknown {
		t.Fatalf("vulns %+v", vs)
	}
}
