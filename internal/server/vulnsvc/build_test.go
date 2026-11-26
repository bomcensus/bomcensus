// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package vulnsvc

import (
	"encoding/json"
	"strings"
	"testing"

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
