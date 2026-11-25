// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package manageapi

import (
	"context"
	"slices"
	"testing"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/apierr"
	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/server/scope"
)

func TestDetectDirs(t *testing.T) {
	e := newEnv(t, true)
	ctx := scope.System(context.Background())

	for _, bad := range []string{"opt", "/opt/*", "/opt/a\x01", ""} {
		e.want(e.do("POST", "/detect-dirs", gen.DetectDirCreate{Path: bad}), 400, apierr.CodeInvalidArgument)
	}
	opt := decode[gen.DetectDir](t, e.do("POST", "/detect-dirs", gen.DetectDirCreate{Path: " /opt/app/../ ", Description: ptr("apps")}))
	if opt.Path != "/opt" || deref(opt.Description) != "apps" || opt.Agents != 0 {
		t.Fatalf("created %+v", opt)
	}
	e.want(e.do("POST", "/detect-dirs", gen.DetectDirCreate{Path: "/opt/"}), 409, "")
	srv := decode[gen.DetectDir](t, e.do("POST", "/detect-dirs", gen.DetectDirCreate{Path: "/srv"}))

	// Agents take directories; scanners do not.
	a, err := e.db.CreateAgent(ctx, store.Agent{Kind: store.AgentKindAgent, IdentityKey: []byte("agent-key"), State: store.AgentApproved})
	if err != nil {
		t.Fatal(err)
	}
	sc, err := e.db.CreateAgent(ctx, store.Agent{Kind: store.AgentKindScanner, IdentityKey: []byte("scanner-key"), State: store.AgentApproved})
	if err != nil {
		t.Fatal(err)
	}
	if got := decode[gen.Agent](t, e.do("GET", "/agents/"+a.ID, nil)); got.DetectDirIds == nil || len(got.DetectDirIds) != 0 {
		t.Fatalf("new agent dirs %v", got.DetectDirIds)
	}
	e.want(e.do("PATCH", "/agents/"+sc.ID, gen.AgentUpdate{DetectDirIds: &[]string{opt.Id}}), 400, apierr.CodeInvalidArgument)
	e.want(e.do("PATCH", "/agents/"+a.ID, gen.AgentUpdate{DetectDirIds: &[]string{"00000000-0000-0000-0000-000000000000"}}), 400, apierr.CodeInvalidArgument)
	got := decode[gen.Agent](t, e.do("PATCH", "/agents/"+a.ID, gen.AgentUpdate{DetectDirIds: &[]string{srv.Id, opt.Id}}))
	if !slices.Equal(got.DetectDirIds, []string{opt.Id, srv.Id}) {
		t.Fatalf("agent dirs %v", got.DetectDirIds)
	}
	// A description change keeps the directories.
	got = decode[gen.Agent](t, e.do("PATCH", "/agents/"+a.ID, gen.AgentUpdate{Description: ptr("web")}))
	if len(got.DetectDirIds) != 2 {
		t.Fatalf("dirs after description change %v", got.DetectDirIds)
	}

	// Scan targets take directories on create and update.
	cred := decode[gen.Credential](t, e.do("POST", "/credentials", gen.CredentialCreate{Name: "ssh", Kind: gen.CredentialKindSshPassword, Username: ptr("u"), Password: ptr("p")}))
	e.want(e.do("POST", "/scan-targets", gen.ScanTargetCreate{Name: "h", Address: "10.0.0.1", CredentialId: cred.Id,
		DetectDirIds: &[]string{"00000000-0000-0000-0000-000000000000"}}), 400, apierr.CodeInvalidArgument)
	if l := decode[gen.ScanTargetList](t, e.do("GET", "/scan-targets", nil)); l.Total != 0 {
		t.Fatalf("a refused create stored a target: %+v", l)
	}
	tg := decode[gen.ScanTarget](t, e.do("POST", "/scan-targets", gen.ScanTargetCreate{Name: "h", Address: "10.0.0.1",
		CredentialId: cred.Id, DetectDirIds: &[]string{srv.Id}}))
	if !slices.Equal(tg.DetectDirIds, []string{srv.Id}) {
		t.Fatalf("target dirs %v", tg.DetectDirIds)
	}
	up := decode[gen.ScanTarget](t, e.do("PATCH", "/scan-targets/"+tg.Id, map[string]any{"name": "h2"}))
	if !slices.Equal(up.DetectDirIds, []string{srv.Id}) {
		t.Fatalf("dirs after rename %v", up.DetectDirIds)
	}
	up = decode[gen.ScanTarget](t, e.do("PATCH", "/scan-targets/"+tg.Id, map[string]any{"detectDirIds": []string{}}))
	if up.DetectDirIds == nil || len(up.DetectDirIds) != 0 {
		t.Fatalf("cleared dirs %v", up.DetectDirIds)
	}
	decode[gen.ScanTarget](t, e.do("PATCH", "/scan-targets/"+tg.Id, map[string]any{"detectDirIds": []string{opt.Id}}))

	// The list counts assignments.
	l := decode[gen.DetectDirList](t, e.do("GET", "/detect-dirs", nil))
	if l.Total != 2 || l.Items[0].Path != "/opt" || l.Items[0].Agents != 1 || l.Items[0].ScanTargets != 1 ||
		l.Items[1].Agents != 1 || l.Items[1].ScanTargets != 0 {
		t.Fatalf("list %+v", l)
	}

	// Update: path cleaned, conflict refused, empty description removes it.
	e.want(e.do("PATCH", "/detect-dirs/"+srv.Id, gen.DetectDirUpdate{Path: ptr("/opt")}), 409, "")
	e.want(e.do("PATCH", "/detect-dirs/"+srv.Id, gen.DetectDirUpdate{Path: ptr("srv")}), 400, apierr.CodeInvalidArgument)
	e.want(e.do("PATCH", "/detect-dirs/00000000-0000-0000-0000-000000000000", gen.DetectDirUpdate{Path: ptr("/x")}), 404, "")
	ud := decode[gen.DetectDir](t, e.do("PATCH", "/detect-dirs/"+opt.Id, gen.DetectDirUpdate{Path: ptr("/opt/apps/"), Description: ptr("")}))
	if ud.Path != "/opt/apps" || ud.Description != nil {
		t.Fatalf("updated %+v", ud)
	}

	// Delete removes the assignments.
	e.want(e.do("DELETE", "/detect-dirs/"+opt.Id, nil), 204, "")
	e.want(e.do("DELETE", "/detect-dirs/"+opt.Id, nil), 404, "")
	if got := decode[gen.Agent](t, e.do("GET", "/agents/"+a.ID, nil)); !slices.Equal(got.DetectDirIds, []string{srv.Id}) {
		t.Fatalf("agent dirs after delete %v", got.DetectDirIds)
	}
	if l := decode[gen.ScanTargetList](t, e.do("GET", "/scan-targets", nil)); l.Total != 1 || len(l.Items[0].DetectDirIds) != 0 {
		t.Fatalf("targets after delete %+v", l)
	}
}
