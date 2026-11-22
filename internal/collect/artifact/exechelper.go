// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package artifact

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"
)

// helperArg is the hidden first argument that turns the current binary into
// the exec helper. The helper only removes privileges before it executes,
// so invoking it directly grants nothing.
const helperArg = "__bomcensus_exec_helper"

// File descriptors the helper inherits.
const (
	helperExeFD    = 3 // the file to execute
	helperStatusFD = 4 // error message if the exec fails
)

// Linux constants not in package syscall on every architecture.
const (
	rlimitNPROC          = 6
	prSetNoNewPrivs      = 38
	prCapAmbient         = 47
	prCapAmbientClearAll = 4
	prCapbsetDrop        = 24
	capVersion3          = 0x20080522
	lastCap              = 63
)

// MaybeRunExecHelper turns the process into the exec helper when it was
// started as one, and never returns in that case. Binaries that collect
// artifacts must call it first thing in main, before anything else runs;
// tests call it from TestMain.
func MaybeRunExecHelper() {
	if len(os.Args) < 2 || os.Args[1] != helperArg {
		return
	}
	// prctl and capset act on the calling thread, which must be the one
	// that executes the target.
	runtime.LockOSThread()
	err := execHelper(os.Args[2:])
	status := os.NewFile(helperStatusFD, "status")
	if status != nil {
		_, _ = status.WriteString(err.Error())
	}
	os.Exit(127)
}

// execHelper takes: cpu-seconds address-space nofile nproc -- argv...
func execHelper(args []string) error {
	if len(args) < 6 || args[4] != "--" {
		return errors.New("bad helper arguments")
	}
	var lim [4]uint64
	for i := range lim {
		v, err := strconv.ParseUint(args[i], 10, 64)
		if err != nil {
			return fmt.Errorf("bad helper limit %q", args[i])
		}
		lim[i] = v
	}
	cpu, as, nofile, nproc := lim[0], lim[1], lim[2], lim[3]
	argv := args[5:]
	syscall.CloseOnExec(helperStatusFD)

	for _, l := range []struct {
		res int
		val uint64
	}{
		{syscall.RLIMIT_CORE, 0},
		{syscall.RLIMIT_CPU, cpu},
		{syscall.RLIMIT_FSIZE, 0},
		{syscall.RLIMIT_NOFILE, nofile},
		{rlimitNPROC, nproc},
	} {
		if err := syscall.Setrlimit(l.res, &syscall.Rlimit{Cur: l.val, Max: l.val}); err != nil {
			return fmt.Errorf("setrlimit %d: %w", l.res, err)
		}
	}
	if err := prctl(prSetNoNewPrivs, 1); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	// Kernels before 4.3 have no ambient capabilities.
	if err := prctl(prCapAmbient, prCapAmbientClearAll); err != nil && !errors.Is(err, syscall.EINVAL) {
		return fmt.Errorf("clear ambient capabilities: %w", err)
	}
	// Only possible with CAP_SETPCAP; without it there is nothing to drop
	// that no_new_privs does not already neutralize.
	for c := 0; c <= lastCap; c++ {
		_ = prctl(prCapbsetDrop, uintptr(c))
	}
	if err := dropCapabilities(); err != nil {
		return fmt.Errorf("drop capabilities: %w", err)
	}
	// Last: the Go runtime of the helper has already reserved its memory.
	if err := syscall.Setrlimit(syscall.RLIMIT_AS, &syscall.Rlimit{Cur: as, Max: as}); err != nil {
		return fmt.Errorf("setrlimit address space: %w", err)
	}
	err := syscall.Exec("/proc/self/fd/"+strconv.Itoa(helperExeFD), argv, os.Environ())
	return fmt.Errorf("exec: %w", err)
}

func prctl(option int, arg uintptr) error {
	if _, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, uintptr(option), arg, 0, 0, 0, 0); e != 0 {
		return e
	}
	return nil
}

// dropCapabilities clears the effective, permitted and inheritable sets.
func dropCapabilities() error {
	hdr := struct {
		version uint32
		pid     int32
	}{version: capVersion3}
	var data [2]struct{ effective, permitted, inheritable uint32 }
	if _, _, e := syscall.RawSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); e != 0 {
		return e
	}
	return nil
}
