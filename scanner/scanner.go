// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package scanner runs bomcensus-scanner from a program of your own, with
// channels of your own, like package agent for the agent. A build with its
// own channels must be signed with its own release keys
// (docs/EXTENDING.md).
package scanner

import (
	"os"

	"github.com/bomcensus/bomcensus/agentproto"
	"github.com/bomcensus/bomcensus/internal/platform/winsvc"
	"github.com/bomcensus/bomcensus/internal/scanner/cli"
)

// Options extend the scanner.
type Options struct {
	// Channels are channels by name besides the built-in "connect" HTTP
	// channel, chosen at enrollment with --channel.
	Channels map[string]agentproto.ChannelFactory
}

// Main runs the bomcensus-scanner command line with opts and exits. Started
// by the Windows service control manager it runs as the bomcensus-scanner
// service.
func Main(opts Options) {
	ext := cli.Extensions{Channels: opts.Channels}
	if winsvc.IsService() {
		os.Exit(cli.Service(ext))
	}
	os.Exit(cli.Main(os.Args[1:], os.Stdout, os.Stderr, ext))
}
