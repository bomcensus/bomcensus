// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build !windows

package main

import (
	"fmt"
	"io"
)

func runService(_ serviceConfig, stderr io.Writer) error {
	fmt.Fprintln(stderr, "bomcensus-updater: the service command is available on Windows only; use the systemd units")
	return errUsage
}
