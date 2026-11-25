// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package manageapi

import (
	"context"
	"encoding/json"
	"testing"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/apierr"
	"github.com/bomcensus/bomcensus/internal/server/integritysvc"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

func TestIntegrityModes(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()
	a, err := e.db.CreateAgent(ctx, store.Agent{Kind: store.AgentKindAgent, IdentityKey: []byte("agent-key"), State: store.AgentApproved})
	if err != nil {
		t.Fatal(err)
	}
	sc, err := e.db.CreateAgent(ctx, store.Agent{Kind: store.AgentKindScanner, IdentityKey: []byte("scanner-key"), State: store.AgentApproved})
	if err != nil {
		t.Fatal(err)
	}

	// On by default.
	got := decode[gen.Agent](t, e.do("GET", "/agents/"+a.ID, nil))
	if got.Integrity == nil || *got.Integrity != gen.IntegrityModeInherit || got.IntegrityEnabled == nil || !*got.IntegrityEnabled {
		t.Fatalf("default agent %+v %+v", got.Integrity, got.IntegrityEnabled)
	}
	if s := decode[gen.Agent](t, e.do("GET", "/agents/"+sc.ID, nil)); s.Integrity != nil || s.IntegrityEnabled != nil {
		t.Errorf("scanner carries integrity %+v", s)
	}
	off := gen.IntegrityModeOff
	e.want(e.do("PATCH", "/agents/"+sc.ID, gen.AgentUpdate{Integrity: &off}), 400, apierr.CodeInvalidArgument)
	e.want(e.do("PATCH", "/agents/"+a.ID, map[string]any{"integrity": "sometimes"}), 400, apierr.CodeInvalidArgument)
	got = decode[gen.Agent](t, e.do("PATCH", "/agents/"+a.ID, gen.AgentUpdate{Integrity: &off}))
	if *got.Integrity != off || *got.IntegrityEnabled {
		t.Errorf("after off %+v %+v", *got.Integrity, *got.IntegrityEnabled)
	}

	// The default for scan targets follows the policy.
	p := integritysvc.DefaultPolicy()
	p.SSH = false
	raw, _ := json.Marshal(p)
	if err := e.db.PutSetting(ctx, integritysvc.SettingPolicy, raw); err != nil {
		t.Fatal(err)
	}
	cred := decode[gen.Credential](t, e.do("POST", "/credentials", gen.CredentialCreate{Name: "ssh", Kind: gen.CredentialKindSshPassword, Username: ptr("u"), Password: ptr("p")}))
	tg := decode[gen.ScanTarget](t, e.do("POST", "/scan-targets", gen.ScanTargetCreate{Name: "h", Address: "10.0.0.1", CredentialId: cred.Id}))
	if tg.Integrity != gen.IntegrityModeInherit || tg.IntegrityEnabled {
		t.Errorf("new target %s %v", tg.Integrity, tg.IntegrityEnabled)
	}
	up := decode[gen.ScanTarget](t, e.do("PATCH", "/scan-targets/"+tg.Id, map[string]any{"integrity": "on"}))
	if up.Integrity != gen.IntegrityModeOn || !up.IntegrityEnabled {
		t.Errorf("after on %s %v", up.Integrity, up.IntegrityEnabled)
	}
	up = decode[gen.ScanTarget](t, e.do("PATCH", "/scan-targets/"+tg.Id, map[string]any{"name": "h2"}))
	if up.Integrity != gen.IntegrityModeOn {
		t.Errorf("mode lost on rename: %s", up.Integrity)
	}
	e.want(e.do("POST", "/scan-targets", map[string]any{"name": "x", "address": "10.0.0.2", "credentialId": cred.Id, "integrity": "x"}), 400, apierr.CodeInvalidArgument)
}
