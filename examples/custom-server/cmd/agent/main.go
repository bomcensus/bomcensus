// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Command agent is bomcensus-agent with the frame channel:
//
//	agent enroll --channel frame --server server.example:9443 \
//		--server-name bomcensus.example.com --token bc1....
//
// It must be built with the trust of your own release keys and signed with
// them (docs/EXTENDING.md); without that it refuses to run.
package main

import (
	"github.com/bomcensus/bomcensus/agent"
	"github.com/bomcensus/bomcensus/agentproto"
	"github.com/bomcensus/bomcensus/examples/custom-server/framechannel"
)

func main() {
	agent.Main(agent.Options{Channels: map[string]agentproto.ChannelFactory{
		framechannel.Name: framechannel.Factory(),
	}})
}
