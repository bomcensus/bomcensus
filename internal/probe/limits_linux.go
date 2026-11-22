// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package probe

import (
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

const (
	// lowestNice is the nice value the probe runs at.
	lowestNice = 19
	// I/O priority: class idle (3) in bits 13 and up.
	ioprioWhoProcess = 1
	ioprioClassIdle  = 3 << 13
)

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
