// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package probe

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/bomcensus/bomcensus/internal/report"
)

// maxPrivilegeProbe bounds the processes looked at to find one other than
// the probe when the probe is pid 1.
const maxPrivilegeProbe = 4096

// DetectPrivilege reports what the current process may read, after the
// sandbox was applied. The level is privileged when the probe can read
// other processes and other users' files: the executable link of a process
// other than its own can be read (pid 1, or the first other process when
// pid 1 is the probe), and CAP_DAC_READ_SEARCH or CAP_DAC_OVERRIDE is
// effective. The link is tried also for a process of the probe's own uid,
// because the kernel requires the reader's permitted capabilities to cover
// the target's.
func DetectPrivilege(procDir string) report.Privilege {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	p := report.Privilege{Level: report.PrivilegeNonRoot, UID: os.Geteuid()}
	caps, err := currentCaps()
	if err == nil {
		p.Capabilities = caps.effective.names()
	}
	files := caps.effective.has(unix.CAP_DAC_READ_SEARCH) || caps.effective.has(unix.CAP_DAC_OVERRIDE)
	if files && canReadOtherProcess(procDir, caps) {
		p.Level = report.PrivilegePrivileged
	}
	return p
}

func canReadOtherProcess(procDir string, caps capState) bool {
	self := os.Getpid()
	if self != 1 && hasExe(procDir, 1) {
		return readableExe(procDir, 1)
	}
	if entries, err := os.ReadDir(procDir); err == nil {
		for i, e := range entries {
			if i == maxPrivilegeProbe {
				break
			}
			pid, err := strconv.Atoi(e.Name())
			if err != nil || pid == self || !hasExe(procDir, pid) {
				continue
			}
			return readableExe(procDir, pid)
		}
	}
	// No other process is visible.
	return caps.effective.has(unix.CAP_SYS_PTRACE)
}

func procOwner(procDir string, pid int) (int, bool) {
	var st syscall.Stat_t
	if err := syscall.Stat(filepath.Join(procDir, strconv.Itoa(pid)), &st); err != nil {
		return 0, false
	}
	return int(st.Uid), true
}

func readableExe(procDir string, pid int) bool {
	_, err := os.Readlink(filepath.Join(procDir, strconv.Itoa(pid), "exe"))
	return err == nil
}

// hasExe tells user processes from kernel threads, which have no
// executable: their cmdline is empty.
func hasExe(procDir string, pid int) bool {
	b, err := readSmall(filepath.Join(procDir, strconv.Itoa(pid), "cmdline"), 1)
	return err == nil && len(b) > 0
}
