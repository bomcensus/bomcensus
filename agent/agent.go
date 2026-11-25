// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package agent runs bomcensus-agent from a program of your own, with
// channels of your own.
//
//	func main() {
//		agent.Main(agent.Options{Channels: map[string]agentproto.ChannelFactory{"grpc": grpcChannel}})
//	}
//
// The agent then enrolls with "bomcensus-agent enroll --channel grpc
// --channel-setting key=value ..." and keeps that channel. A build with
// its own channels must be signed with its own release keys: it refuses to
// run when it was built without release trust or with the official keys
// (docs/EXTENDING.md).
//
// Started by the Windows service control manager it runs as the
// bomcensus-agent service: the service command line holds the "run" command
// and its flags, a stop request ends it, and logs go to the Application
// event log.
package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"

	"github.com/bomcensus/bomcensus/agentproto"
	internal "github.com/bomcensus/bomcensus/internal/agent"
	"github.com/bomcensus/bomcensus/internal/agent/update"
	"github.com/bomcensus/bomcensus/internal/platform/paths"
	"github.com/bomcensus/bomcensus/internal/platform/winsvc"
)

// Options extend the agent.
type Options struct {
	// Channels are channels by name besides the built-in "connect" and
	// "listen" HTTP channels, chosen at enrollment with --channel.
	Channels map[string]agentproto.ChannelFactory
}

// Main runs the bomcensus-agent command line with opts and exits.
func Main(opts Options) {
	ext := internal.Extensions{Channels: opts.Channels}
	if winsvc.IsService() {
		os.Exit(service(ext))
	}
	os.Exit(internal.MainWith(os.Args[1:], os.Stdout, os.Stderr, ext))
}

func service(ext internal.Extensions) int {
	name := paths.AgentService
	var logw io.Writer = os.Stderr
	if el, err := winsvc.EventLog(name); err == nil {
		defer el.Close()
		logw = el
	}
	err := winsvc.Run(name, nil, func(ctx context.Context) error {
		return internal.RunServiceWith(ctx, os.Args[1:], logw, ext)
	})
	log := slog.New(slog.NewTextHandler(logw, nil))
	var re *update.ReexecError
	switch {
	case errors.As(err, &re):
		// The service stopped with a failure status: its recovery action
		// starts it again through the current junction. The updater
		// service normally restarts it first.
		log.Info("exiting so that the service manager starts the current version", "version", re.Version)
		return 1
	case err != nil:
		log.Error("service stopped", "error", err)
		return 1
	}
	return 0
}
