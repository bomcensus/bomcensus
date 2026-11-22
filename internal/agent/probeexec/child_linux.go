// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package probeexec

import (
	"log/slog"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

const defaultSocket = "/run/bomcensus/probe.sock"

func statSocket(path string) (os.FileInfo, error) { return os.Stat(path) }

func defaultEnv() []string {
	return []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
}

type child struct{ cmd *exec.Cmd }

// prepareChild starts the probe in its own process group and makes
// cancellation kill the whole group.
func prepareChild(cmd *exec.Cmd) *child {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		// The probe runs in its own process group; kill all of it.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	return &child{cmd}
}

// started lowers the priority of the started probe. The returned function
// is called after the probe has exited.
func (c *child) started(log *slog.Logger) func() {
	lowerPriority(c.cmd.Process.Pid, log)
	return func() {}
}

// lowerPriority applies nice 10 and the idle I/O class, best effort. The
// child may already have started work; its later threads inherit nothing,
// but the process-wide settings apply from here on.
func lowerPriority(pid int, log *slog.Logger) {
	if err := unix.Setpriority(unix.PRIO_PROCESS, pid, 10); err != nil {
		log.Debug("set probe CPU priority", "error", err)
	}
	const (
		ioprioWhoProcess = 1
		ioprioClassIdle  = 3
		ioprioClassShift = 13
	)
	if _, _, e := unix.Syscall(unix.SYS_IOPRIO_SET, ioprioWhoProcess, uintptr(pid), ioprioClassIdle<<ioprioClassShift); e != 0 {
		log.Debug("set probe I/O priority", "error", e)
	}
}
