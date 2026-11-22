// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/bomcensus/bomcensus/internal/platform/paths"
	"github.com/bomcensus/bomcensus/internal/platform/winsvc"
)

const serviceName = paths.ScannerService

// service runs the scanner as the Windows service bomcensus-scanner. The
// service command line holds the "run" command and its flags; logs go to
// the Application event log.
func service() int {
	var logw io.Writer = os.Stderr
	if el, err := winsvc.EventLog(serviceName); err == nil {
		defer el.Close()
		logw = el
	}
	err := winsvc.Run(serviceName, nil, func(ctx context.Context) error {
		args := os.Args[1:]
		if len(args) == 0 || args[0] != "run" {
			return fmt.Errorf("%w: a service runs the \"run\" command, got %q", errUsage, args)
		}
		return cmdRun(ctx, args[1:], logw)
	})
	if err != nil {
		slog.New(slog.NewTextHandler(logw, nil)).Error("service stopped", "error", err)
		return 1
	}
	return 0
}
