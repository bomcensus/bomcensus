// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package main

import "github.com/bomcensus/bomcensus/internal/sandbox"

// maybeRunExecHelper runs the check program of the version command sandbox
// (self-test runs the probe as one). Version commands are not run on
// Windows yet.
func maybeRunExecHelper() { sandbox.MaybeRunCheck() }
