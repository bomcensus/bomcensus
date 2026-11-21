// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package authz

import (
	"context"
	"errors"
	"testing"

	"github.com/bomcensus/bomcensus/internal/server/auth"
)

func TestCheck(t *testing.T) {
	if err := Check(context.Background(), "GetAsset", "/api/v1/assets/x"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("no principal: %v", err)
	}
	ctx := auth.WithPrincipal(context.Background(), auth.Principal{ID: "env:admin", Name: "admin"})
	if err := Check(ctx, "DeleteK8sCluster", "/api/v1/k8s/clusters/x"); err != nil {
		t.Fatalf("principal: %v", err)
	}
}
