// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package probe

import (
	"os"
	"testing"

	"github.com/bomcensus/bomcensus/internal/sandbox"
)

func TestMain(m *testing.M) {
	// CheckSandbox runs the test binary as the check program.
	sandbox.MaybeRunCheck()
	os.Exit(m.Run())
}
