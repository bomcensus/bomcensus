// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package probe

import (
	"log/slog"
	"runtime"
	"runtime/debug"

	"github.com/bomcensus/bomcensus/internal/report"
)

const (
	maxProcs  = 2
	gcPercent = 25
)

// applyProcessLimits bounds the memory, CPU parallelism and scheduling
// priority of the probe. Everything is best effort.
func applyProcessLimits(p report.Policy, log *slog.Logger) {
	mb := p.MemoryLimitMB
	if mb <= 0 {
		mb = DefaultMemoryLimitMB
	}
	debug.SetMemoryLimit(int64(mb) << 20)
	debug.SetGCPercent(gcPercent)
	if runtime.GOMAXPROCS(0) > maxProcs {
		runtime.GOMAXPROCS(maxProcs)
	}
	niced, failed := lowerPriority()
	log.Debug("process limits", "memory_limit_mb", mb, "gomaxprocs", runtime.GOMAXPROCS(0),
		"threads_lowered", niced, "threads_failed", failed)
}
