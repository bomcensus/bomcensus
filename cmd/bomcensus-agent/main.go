// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Command bomcensus-agent is the host agent. See internal/agent.
package main

import (
	"os"

	"github.com/bomcensus/bomcensus/internal/agent"
)

func main() {
	os.Exit(agent.Main(os.Args[1:], os.Stdout, os.Stderr))
}
