// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package probe

import "golang.org/x/sys/windows"

// processModeBackgroundBegin is PROCESS_MODE_BACKGROUND_BEGIN: lowest I/O
// and memory priority for the calling process.
const processModeBackgroundBegin = 0x00100000

// lowerPriority puts the process in the idle priority class and in
// background mode. Priority classes apply to the whole process, so it
// reports one unit of work.
func lowerPriority() (ok, failed int) {
	p := windows.CurrentProcess()
	err1 := windows.SetPriorityClass(p, windows.IDLE_PRIORITY_CLASS)
	err2 := windows.SetPriorityClass(p, processModeBackgroundBegin)
	if err1 != nil || err2 != nil {
		return 0, 1
	}
	return 1, 0
}
