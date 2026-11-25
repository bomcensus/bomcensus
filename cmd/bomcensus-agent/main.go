// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Command bomcensus-agent is the host agent. See package agent for the
// commands and for building an agent of your own.
package main

import "github.com/bomcensus/bomcensus/agent"

func main() {
	agent.Main(agent.Options{})
}
