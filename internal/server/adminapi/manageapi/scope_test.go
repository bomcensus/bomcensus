// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package manageapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/apierr"
)

// doIn is do with the data scope ids (comma-separated) of the request.
func (e *env) doIn(scopes, method, path string, body any) resp {
	e.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			e.t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, e.srv.URL+"/api/v1"+path, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(testScopeHeader, scopes)
	return e.send(req)
}

func TestDataScopes(t *testing.T) {
	e := newEnv(t, false)
	pw := "secret"

	// Records of scope b.
	key := decode[gen.RegisterKeyCreated](t, e.doIn("b", "POST", "/register-keys",
		gen.RegisterKeyCreate{Name: "k", Target: gen.AgentKindAgent, Approval: gen.RegisterKeyApprovalAuto}))
	if key.Key.ScopeId == nil || *key.Key.ScopeId != "b" {
		t.Fatalf("key scope %v", key.Key.ScopeId)
	}
	cred := decode[gen.Credential](t, e.doIn("b", "POST", "/credentials",
		gen.CredentialCreate{Name: "c", Kind: gen.CredentialKindSshPassword, Username: ptr("u"), Password: &pw}))
	if cred.ScopeId != "b" {
		t.Fatalf("credential scope %q", cred.ScopeId)
	}
	target := decode[gen.ScanTarget](t, e.doIn("b", "POST", "/scan-targets",
		gen.ScanTargetCreate{Name: "t", Address: "10.0.0.1", CredentialId: cred.Id}))
	if target.ScopeId != "b" {
		t.Fatalf("target scope %q", target.ScopeId)
	}

	// Creating in a scope outside the request is forbidden.
	for _, c := range []struct {
		path string
		body any
	}{
		{"/register-keys", gen.RegisterKeyCreate{Name: "k", Target: gen.AgentKindAgent, Approval: gen.RegisterKeyApprovalAuto, ScopeId: ptr("b")}},
		{"/register-keys", gen.RegisterKeyCreate{Name: "s", Target: gen.AgentKindScanner, Approval: gen.RegisterKeyApprovalAuto}},
		{"/credentials", gen.CredentialCreate{Name: "c", Kind: gen.CredentialKindSshPassword, Username: ptr("u"), Password: &pw, ScopeId: ptr("b")}},
		{"/scan-targets", gen.ScanTargetCreate{Name: "t", Address: "10.0.0.2", CredentialId: cred.Id, ScopeId: ptr("b")}},
		{"/listen-targets", gen.ListenTargetCreate{Address: "a.example:7000", ScopeId: ptr("b")}},
	} {
		e.want(e.doIn("a", "POST", c.path, c.body), 403, apierr.CodeForbidden)
	}
	// A request with several scopes must name one.
	e.want(e.doIn("a,b", "POST", "/credentials",
		gen.CredentialCreate{Name: "c2", Kind: gen.CredentialKindSshPassword, Username: ptr("u"), Password: &pw}), 403, apierr.CodeForbidden)
	e.want(e.doIn("a", "POST", "/credentials",
		gen.CredentialCreate{Name: "c3", Kind: gen.CredentialKindSshPassword, Username: ptr("u"), Password: &pw, ScopeId: ptr("bad scope")}),
		400, apierr.CodeInvalidArgument)

	// The records of b do not exist for a.
	e.want(e.doIn("a", "GET", "/register-keys/"+key.Key.Id, nil), 404, apierr.CodeNotFound)
	e.want(e.doIn("b", "GET", "/register-keys/"+key.Key.Id, nil), 200, "")
	e.want(e.doIn("a", "PATCH", "/scan-targets/"+target.Id, gen.ScanTargetUpdate{Name: ptr("x")}), 404, apierr.CodeNotFound)
	e.want(e.doIn("b", "PATCH", "/scan-targets/"+target.Id, gen.ScanTargetUpdate{Name: ptr("x")}), 200, "")
	e.want(e.doIn("a", "POST", "/register-keys/"+key.Key.Id+"/revoke", nil), 404, apierr.CodeNotFound)
	e.want(e.doIn("a", "DELETE", "/credentials/"+cred.Id, nil), 404, apierr.CodeNotFound)
	e.want(e.doIn("a", "DELETE", "/scan-targets/"+target.Id, nil), 404, apierr.CodeNotFound)
	if l := decode[gen.CredentialList](t, e.doIn("a", "GET", "/credentials", nil)); l.Total != 0 {
		t.Fatalf("a lists %d credentials", l.Total)
	}
	if l := decode[gen.ScanTargetList](t, e.doIn("a,b", "GET", "/scan-targets?scopeId=a", nil)); l.Total != 0 {
		t.Fatalf("filter by scope a lists %d targets", l.Total)
	}

	// A target of a cannot use the credential of b, even for a request that
	// sees both.
	e.want(e.doIn("a,b", "POST", "/scan-targets",
		gen.ScanTargetCreate{Name: "t", Address: "10.0.0.3", CredentialId: cred.Id, ScopeId: ptr("a")}), 403, apierr.CodeForbidden)
	// For a it does not exist.
	e.want(e.doIn("a", "POST", "/scan-targets",
		gen.ScanTargetCreate{Name: "t", Address: "10.0.0.3", CredentialId: cred.Id}), 400, apierr.CodeInvalidArgument)
	// Names are unique per scope.
	e.want(e.doIn("a", "POST", "/credentials",
		gen.CredentialCreate{Name: "c", Kind: gen.CredentialKindSshPassword, Username: ptr("u"), Password: &pw}), 201, "")

	// Scanner keys are shared: every scope sees them, only All changes them.
	scanner := decode[gen.RegisterKeyCreated](t, e.do("POST", "/register-keys",
		gen.RegisterKeyCreate{Name: "s", Target: gen.AgentKindScanner, Approval: gen.RegisterKeyApprovalAuto}))
	if scanner.Key.ScopeId != nil {
		t.Fatalf("scanner key scope %v", *scanner.Key.ScopeId)
	}
	e.want(e.doIn("a", "GET", "/register-keys/"+scanner.Key.Id, nil), 200, "")
	e.want(e.doIn("a", "POST", "/register-keys/"+scanner.Key.Id+"/revoke", nil), 403, apierr.CodeForbidden)
	e.want(e.do("POST", "/register-keys/"+scanner.Key.Id+"/revoke", nil), 200, "")
}
