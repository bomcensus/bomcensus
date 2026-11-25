// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package agent

import (
	"context"
	"fmt"
	"io"
)

// RunService runs the "run" command under a service manager that controls
// the process: ctx ends on a stop request. args are the command line
// arguments without the program name and must start with "run". Unlike
// Main it does not replace the process after an update: the
// *update.ReexecError is returned, and the caller exits with a failure
// status so that the service manager starts the executable of the current
// version.
func RunService(ctx context.Context, args []string, stderr io.Writer) error {
	return RunServiceWith(ctx, args, stderr, Extensions{})
}

// RunServiceWith is RunService with extensions.
func RunServiceWith(ctx context.Context, args []string, stderr io.Writer, ext Extensions) error {
	if len(args) == 0 || args[0] != "run" {
		return fmt.Errorf("%w: a service runs the \"run\" command, got %q", errUsage, args)
	}
	if err := ext.check(); err != nil {
		return err
	}
	return cmdRun(ctx, args[1:], stderr, ext)
}
