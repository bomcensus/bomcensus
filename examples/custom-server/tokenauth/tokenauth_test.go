// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package tokenauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/bomcensus/bomcensus/server/auth"
	"github.com/bomcensus/bomcensus/server/authz"
)

func TestMiddleware(t *testing.T) {
	tokens, err := ParseTokens("t1=alice:admin:*, t2=bob:viewer:team-a|team-b")
	if err != nil {
		t.Fatal(err)
	}
	var got auth.Principal
	h := Middleware(tokens)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = auth.FromContext(r.Context())
	}))
	for _, c := range []struct {
		header string
		status int
		id     string
	}{
		{"", http.StatusOK, ""},
		{"Bearer t2", http.StatusOK, "token:bob"},
		{"Bearer nope", http.StatusUnauthorized, ""},
		{"Basic x", http.StatusUnauthorized, ""},
	} {
		got = nil
		r := httptest.NewRequest(http.MethodGet, "/api/v1/assets", nil)
		if c.header != "" {
			r.Header.Set("Authorization", c.header)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		id := ""
		if got != nil {
			id = got.ID()
		}
		if w.Code != c.status || id != c.id {
			t.Errorf("%q: %d %q", c.header, w.Code, id)
		}
	}
	if _, err := ParseTokens("t=x:root:*"); err == nil {
		t.Fatal("unknown role accepted")
	}
}

func TestAuthorizer(t *testing.T) {
	ctx := context.Background()
	viewer := User{UserID: "bob", Role: RoleViewer, Tenants: []string{"team-a"}}
	operator := User{UserID: "carol", Role: RoleOperator, Tenants: []string{"team-a", "team-b"}}
	admin := User{UserID: "alice", Role: RoleAdmin, Tenants: []string{"*"}}
	a := Authorizer{}

	d, err := a.Authorize(ctx, viewer, authz.Request{Operation: authz.OpListAssets})
	if err != nil || !slices.Equal(d.Scope.IDs(), []string{"team-a"}) {
		t.Fatalf("viewer list: %+v %v", d, err)
	}
	if _, err := a.Authorize(ctx, viewer, authz.Request{Operation: authz.OpCreateScanTarget}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("viewer create: %v", err)
	}
	if _, err := a.Authorize(ctx, operator, authz.Request{Operation: authz.OpCreateScanTarget}); err != nil {
		t.Fatalf("operator create: %v", err)
	}
	if _, err := a.Authorize(ctx, operator, authz.Request{Operation: authz.OpUploadRelease}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("operator release upload: %v", err)
	}
	if d, err := a.Authorize(ctx, admin, authz.Request{Operation: authz.OpUploadRelease}); err != nil || !d.Scope.IsAll() {
		t.Fatalf("admin: %+v %v", d, err)
	}
	if _, err := a.Authorize(ctx, auth.User{UserID: "x"}, authz.Request{Operation: authz.OpListAssets}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("foreign principal: %v", err)
	}
}
