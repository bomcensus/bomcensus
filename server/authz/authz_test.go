// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package authz

import (
	"context"
	"reflect"
	"slices"
	"testing"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/server/auth"
)

// TestOperationsMatchServer keeps operations.go in step with admin.yaml:
// regenerate with go run ./tools/authzops.
func TestOperationsMatchServer(t *testing.T) {
	typ := reflect.TypeFor[gen.StrictServerInterface]()
	var want []string
	for i := range typ.NumMethod() {
		want = append(want, typ.Method(i).Name)
	}
	slices.Sort(want)
	if got := Operations(); !slices.Equal(got, want) {
		t.Fatalf("operations.go is out of date (go run ./tools/authzops)\n got %v\nwant %v", got, want)
	}
	if !IsPublic(OpLogin) || IsPublic(OpListAssets) {
		t.Fatal("public operations")
	}
}

func TestAllowAll(t *testing.T) {
	d, err := AllowAll.Authorize(context.Background(), auth.User{UserID: "u"}, Request{Operation: OpListAssets})
	if err != nil || !d.Scope.IsAll() {
		t.Fatalf("AllowAll = %v, %v", d, err)
	}
	if !(Decision{}).Scope.IsEmpty() {
		t.Fatal("zero decision must have the empty scope")
	}
}
