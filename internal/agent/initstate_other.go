// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build !linux

package agent

import "errors"

// InitStateDir is a container init step of the Linux node agent.
func InitStateDir(string, int, int) error {
	return errors.New("init-state: only available on Linux")
}
