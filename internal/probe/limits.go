// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package probe

import (
	"log/slog"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/bomcensus/bomcensus/internal/report"
)

const (
	maxProcs  = 2
	gcPercent = 25
	// lowestNice is the nice value the probe runs at.
	lowestNice = 19
	// I/O priority: class idle (3) in bits 13 and up.
	ioprioWhoProcess = 1
	ioprioClassIdle  = 3 << 13
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

// lowerPriority sets the lowest CPU and I/O priority on every thread of the
// process. Both are per thread on Linux; threads created later inherit them
// from the thread that creates them.
func lowerPriority() (ok, failed int) {
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		tasks = nil
	}
	tids := []int{0}
	for _, t := range tasks {
		if tid, err := strconv.Atoi(t.Name()); err == nil {
			tids = append(tids, tid)
		}
	}
	for _, tid := range tids {
		err1 := unix.Setpriority(unix.PRIO_PROCESS, tid, lowestNice)
		_, _, e2 := unix.Syscall(unix.SYS_IOPRIO_SET, ioprioWhoProcess, uintptr(tid), ioprioClassIdle)
		if err1 != nil || e2 != 0 {
			failed++
		} else {
			ok++
		}
	}
	return ok, failed
}
