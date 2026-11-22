// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Command bomcensus-agent is the host agent. See internal/agent.
//
// Started by the Windows service control manager it runs as the
// bomcensus-agent service: the service command line holds the "run" command
// and its flags, a stop request ends it, and logs go to the Application
// event log.
package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"

	"github.com/bomcensus/bomcensus/internal/agent"
	"github.com/bomcensus/bomcensus/internal/agent/update"
	"github.com/bomcensus/bomcensus/internal/platform/paths"
	"github.com/bomcensus/bomcensus/internal/platform/winsvc"
)

const serviceName = paths.AgentService

func main() {
	if winsvc.IsService() {
		os.Exit(service())
	}
	os.Exit(agent.Main(os.Args[1:], os.Stdout, os.Stderr))
}

func service() int {
	var logw io.Writer = os.Stderr
	if el, err := winsvc.EventLog(serviceName); err == nil {
		defer el.Close()
		logw = el
	}
	err := winsvc.Run(serviceName, nil, func(ctx context.Context) error {
		return agent.RunService(ctx, os.Args[1:], logw)
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
