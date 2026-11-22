// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package main

import "github.com/bomcensus/bomcensus/internal/collect/artifact"

// maybeRunExecHelper turns the process into the exec helper of version
// commands when it was started as one, and then never returns.
func maybeRunExecHelper() { artifact.MaybeRunExecHelper() }
