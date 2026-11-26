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

	"golang.org/x/sys/unix"

	"github.com/bomcensus/bomcensus/internal/sandbox"
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
// started as one, or into the sandbox check program (versionexec_check.go)
// when it was started as a version command for that, and never returns in
// these cases. Binaries that collect artifacts must call it first thing in
// main, before anything else runs; tests call it from TestMain.
func MaybeRunExecHelper() {
	if len(os.Args) < 2 {
		return
	}
	switch os.Args[1] {
	case helperArg:
	case checkArg:
		os.Exit(runCommandChecks())
	default:
		return
	}
	// prctl, capset, Landlock and seccomp act on the calling thread, which
	// must be the one that executes the target.
	runtime.LockOSThread()
	err := execHelper(os.Args[2:])
	msg := []byte(err.Error())
	_, _ = unix.Write(helperStatusFD, msg)
	os.Exit(127)
}

// execHelper takes: cpu-seconds address-space nofile nproc -- argv...
//
// In this order it: marks every descriptor but 0 to 2 close-on-exec, sets
// umask 077 and the rlimits (never above the current hard limits),
// no_new_privs, clears the ambient, bounding and all other capability
// sets, refuses to continue as uid 0, puts the thread into a Landlock
// domain (where the kernel has Landlock), installs the command's seccomp
// filter and executes the target from its descriptor.
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

	// Descriptors the probe inherited without close-on-exec would reach
	// the target otherwise. The descriptor of the target itself is
	// close-on-exec too: the kernel opens /proc/self/fd/3 before it closes
	// it, and only ELF files are executed, which need no path to it.
	if err := cloexecFrom(helperExeFD); err != nil {
		return fmt.Errorf("close descriptors: %w", err)
	}
	syscall.Umask(0o077)

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
		if err := setrlimitAtMost(l.res, l.val); err != nil {
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
	// The probe starts the helper as uid 65534 when it is root itself; a
	// helper that is still root got here some other way.
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		return errors.New("refusing to run a version command as root")
	}
	// Last: the Go runtime of the helper has already reserved its memory.
	if err := setrlimitAtMost(syscall.RLIMIT_AS, as); err != nil {
		return fmt.Errorf("setrlimit address space: %w", err)
	}
	if _, err := sandbox.RestrictCommand("/"); err != nil {
		return err
	}
	prog, err := sandbox.CommandFilter(os.Getpid())
	if err != nil {
		return err
	}
	if err := sandbox.Install(prog, false); err != nil {
		return err
	}
	err = syscall.Exec("/proc/self/fd/"+strconv.Itoa(helperExeFD), argv, os.Environ())
	return fmt.Errorf("exec: %w", err)
}

// cloexecFrom marks every descriptor from first on close-on-exec.
func cloexecFrom(first int) error {
	if unix.CloseRange(uint(first), ^uint(0), unix.CLOSE_RANGE_CLOEXEC) == nil {
		return nil
	}
	// Kernels before 5.11, or close_range denied by a container runtime's
	// seccomp profile.
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return err
	}
	for _, e := range ents {
		fd, err := strconv.Atoi(e.Name())
		if err != nil || fd < first {
			continue
		}
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil && !errors.Is(err, unix.EBADF) {
			return err
		}
	}
	return nil
}

// setrlimitAtMost sets the soft and hard limit of res to val, or to the
// current hard limit when that is lower: raising it needs a capability,
// and a lower limit is only stricter.
func setrlimitAtMost(res int, val uint64) error {
	var cur syscall.Rlimit
	if err := syscall.Getrlimit(res, &cur); err == nil && cur.Max < val {
		val = cur.Max
	}
	return syscall.Setrlimit(res, &syscall.Rlimit{Cur: val, Max: val})
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
