// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package container

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/bomcensus/bomcensus/internal/collect"
)

// TestLive prints the inventory of the machine it runs on. It is meant for
// checking the collector against a real runtime:
//
//	CGO_ENABLED=0 go test -c -o container.test ./internal/collect/container
//	BOMCENSUS_CONTAINER_LIVE=1 ./container.test -test.run TestLive -test.v
func TestLive(t *testing.T) {
	if os.Getenv("BOMCENSUS_CONTAINER_LIVE") == "" {
		t.Skip("set BOMCENSUS_CONTAINER_LIVE=1 to inventory this machine")
	}
	sec := Collect(context.Background(), collect.NewEnv())
	out, err := json.MarshalIndent(sec, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(out))
}
