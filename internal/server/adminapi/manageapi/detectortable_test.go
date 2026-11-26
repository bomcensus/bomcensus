// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package manageapi

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/bomcensus/bomcensus/internal/detectors"
	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/detectorsvc"
	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/server/scope"
)

const customTable = `schema_version: 1
detectors:
  - id: genian-nac
    name: genian-nac
    names: [centerd]
    paths: [usr/geni/centerd]
    static:
      - file: '../../.version'
        rules:
          - pattern: '(?m)^NAC-[A-Z0-9]+-R-(?P<build>\d+)-(?P<version>\d+\.\d+\.\d+(?:\.\d+)?)\s*$'
    cpe: 'cpe:2.3:a:genians:genian_nac:{version}:*:*:*:*:*:*:*'
  - id: shell
    name: sh
    names: [sh]
    exec: ['-c', 'id']
    parse:
      - pattern: 'uid=(\d+)'
    static:
      - rules:
          - pattern: 'GNU bash, version (\d+\.\d+\.\d+)'
`

func TestDetectorTableAPI(t *testing.T) {
	e := newEnv(t, false)
	ctx := scope.System(context.Background())

	// Without the service the operations answer 503.
	e.want(e.do("GET", "/detector-table", nil), 503, "")

	svc, err := detectorsvc.New(detectorsvc.Config{Store: e.db})
	if err != nil {
		t.Fatal(err)
	}
	e.h.detectors = svc

	st := decode[gen.DetectorTableState](t, e.do("GET", "/detector-table", nil))
	if st.Custom || st.Digest != detectors.BuiltinDigest() || st.DefaultDigest != st.Digest || st.BuiltinDigest != st.Digest ||
		st.Revision != nil || len(st.Warnings) != 0 || st.Yaml != string(detectors.BuiltinYAML()) {
		t.Fatalf("initial state %+v", st)
	}
	def := decode[gen.DetectorTableText](t, e.do("GET", "/detector-table/default", nil))
	if def.Source != "built-in" || def.Digest != st.Digest || def.Detectors == 0 {
		t.Fatalf("default %+v", def)
	}

	// Malicious entries are refused with their position.
	for _, bad := range []string{
		strings.Replace(customTable, "'../../.version'", "'../../../etc/shadow'", 1),
		strings.Replace(customTable, `(?P<build>\d+)`, `(?P<build>\d+)\1`, 1),
		strings.Replace(customTable, "    static:\n      - file: '../../.version'", "    static:\n      - file: '../../.version'\n        limit: 999999999", 1),
		"schema_version: 1\ndetectors:\n  - id: x\n    name: x\n    names: [x]\n    run: [sh]\n",
		"schema_version: 2\ndetectors: []\n",
	} {
		r := e.do("PUT", "/detector-table", gen.DetectorTableInput{Yaml: bad})
		e.want(r, 422, "")
		c := decode[gen.DetectorTableCheck](t, r)
		if c.Valid || len(c.Problems) == 0 || c.Problems[0].Severity != gen.DetectorTableProblemSeverityError {
			t.Fatalf("check %+v", c)
		}
		chk := decode[gen.DetectorTableCheck](t, e.do("POST", "/detector-table/check", gen.DetectorTableInput{Yaml: bad}))
		if chk.Valid {
			t.Fatalf("check accepted %q", bad)
		}
	}
	if l := decode[gen.DetectorTableRevisionList](t, e.do("GET", "/detector-table/revisions", nil)); len(l.Items) != 0 {
		t.Fatalf("refused tables stored: %+v", l)
	}

	// A valid table with a version command that will not run: saved with
	// a warning.
	chk := decode[gen.DetectorTableCheck](t, e.do("POST", "/detector-table/check", gen.DetectorTableInput{Yaml: customTable}))
	if !chk.Valid || chk.Digest == nil || deref(chk.Detectors) != 2 || len(chk.Problems) != 1 ||
		chk.Problems[0].Severity != gen.DetectorTableProblemSeverityWarning || deref(chk.Problems[0].Id) != "shell" {
		t.Fatalf("check %+v", chk)
	}
	saved := decode[gen.DetectorTableState](t, e.do("PUT", "/detector-table", gen.DetectorTableInput{Yaml: customTable}))
	if !saved.Custom || saved.Digest != *chk.Digest || saved.Revision == nil || deref(saved.UpdatedBy) != "admin-1" ||
		saved.Detectors != 2 || len(saved.Warnings) != 1 || saved.Yaml != customTable {
		t.Fatalf("saved %+v", saved)
	}
	if got := decode[gen.DetectorTableState](t, e.do("GET", "/detector-table", nil)); got.Digest != saved.Digest {
		t.Fatalf("after save %+v", got)
	}

	// Usage of the agents that polled.
	a, err := e.db.CreateAgent(ctx, store.Agent{Kind: store.AgentKindAgent, IdentityKey: []byte("k1"), State: store.AgentApproved})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.db.UpdateAgentPoll(ctx, a.ID, store.AgentPollStatus{Hostname: "h", ConnectMode: store.ConnectModeConnect,
		TLSMode: store.TLSVerifyPinned, Privilege: store.PrivilegeNonRoot, UpdateState: store.UpdateUpToDate,
		DetectorsDigest: &saved.Digest}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.CreateAgent(ctx, store.Agent{Kind: store.AgentKindAgent, IdentityKey: []byte("k2"), State: store.AgentApproved}); err != nil {
		t.Fatal(err)
	}
	u := decode[gen.DetectorTableUsageList](t, e.do("GET", "/detector-table/usage", nil))
	if len(u.Items) != 2 {
		t.Fatalf("usage %+v", u)
	}
	for _, it := range u.Items {
		if it.Reported != it.Current || it.Count != 1 {
			t.Errorf("usage %+v", it)
		}
	}
	if ag := decode[gen.Agent](t, e.do("GET", "/agents/"+a.ID, nil)); deref(ag.DetectorsDigest) != saved.Digest {
		t.Fatalf("agent digest %v", ag.DetectorsDigest)
	}

	// Reset, history and one revision.
	reset := decode[gen.DetectorTableState](t, e.do("DELETE", "/detector-table", nil))
	if reset.Custom || reset.Digest != detectors.BuiltinDigest() || reset.Revision == nil || *reset.Revision <= *saved.Revision {
		t.Fatalf("reset %+v", reset)
	}
	l := decode[gen.DetectorTableRevisionList](t, e.do("GET", "/detector-table/revisions", nil))
	if len(l.Items) != 2 || !l.Items[0].Reset || l.Items[1].Reset || l.Items[1].Yaml != nil || deref(l.Items[1].Digest) != saved.Digest {
		t.Fatalf("revisions %+v", l)
	}
	rev := decode[gen.DetectorTableRevision](t, e.do("GET", "/detector-table/revisions/"+strconv.FormatInt(*saved.Revision, 10), nil))
	if deref(rev.Yaml) != customTable {
		t.Fatalf("revision %+v", rev)
	}
	e.want(e.do("GET", "/detector-table/revisions/99999", nil), 404, "")
}
