// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package sandbox

// Landlock is applied to version commands only, never to the probe: a
// process inside a Landlock domain may not access processes outside it
// (ptrace, and /proc/<pid>/{mem,environ,exe,maps,fd,root}), which is what
// the probe must read and exactly what a version command must not.

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// LandlockABI returns the Landlock ABI version of the kernel, 0 when
// Landlock is not available.
func LandlockABI() int {
	v, _, e := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if e != 0 || int(v) < 0 {
		return 0
	}
	return int(v)
}

// landlockRulesetAttr is struct landlock_ruleset_attr up to ABI 6. Passing
// a size larger than the kernel's is accepted while the extra fields are
// zero.
type landlockRulesetAttr struct {
	handledFS, handledNet, scoped uint64
}

// landlockFSAccess returns the file system rights the kernel of the given
// ABI knows.
func landlockFSAccess(abi int) uint64 {
	fs := uint64(unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM)
	if abi >= 2 {
		fs |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		fs |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	if abi >= 5 {
		fs |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
	return fs
}

// LandlockCommand describes what RestrictCommand handles at ABI abi.
func LandlockCommand(abi int) string {
	switch {
	case abi <= 0:
		return "not available"
	case abi < 4:
		return fmt.Sprintf("ABI %d: read and execute only, no access to other processes", abi)
	case abi < 6:
		return fmt.Sprintf("ABI %d: read and execute only, no TCP, no access to other processes", abi)
	}
	return fmt.Sprintf("ABI %d: read and execute only, no TCP, no access to, signals to or abstract sockets of other processes", abi)
}

// RestrictCommand puts the calling thread into a new Landlock domain that
// keeps it to reading, listing and executing files beneath root. Every
// other file system right the kernel can control is denied; from ABI 4
// TCP bind and connect, from ABI 6 signals to and abstract Unix sockets of
// processes outside the domain. Being in a domain also denies ptrace
// access to processes outside it, on every ABI. The domain is kept across
// execve. The caller must have set no_new_privs.
//
// It returns the ABI applied, or 0 when Landlock is not available: not
// built into the kernel (ENOSYS), disabled at boot (EOPNOTSUPP), or denied
// by a seccomp filter of a container runtime (usually EPERM). An error
// after the ABI is known is returned.
func RestrictCommand(root string) (int, error) {
	abi := LandlockABI()
	if abi <= 0 {
		return 0, nil
	}
	attr := landlockRulesetAttr{handledFS: landlockFSAccess(abi)}
	if abi >= 4 {
		attr.handledNet = unix.LANDLOCK_ACCESS_NET_BIND_TCP | unix.LANDLOCK_ACCESS_NET_CONNECT_TCP
	}
	if abi >= 6 {
		attr.scoped = unix.LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | unix.LANDLOCK_SCOPE_SIGNAL
	}
	rfd, _, e := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if e != 0 {
		return 0, fmt.Errorf("landlock create ruleset: %w", e)
	}
	defer unix.Close(int(rfd))

	dir, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, fmt.Errorf("landlock: open %s: %w", root, err)
	}
	defer unix.Close(dir)
	// struct landlock_path_beneath_attr is packed: 8 bytes of rights and
	// the 4-byte descriptor.
	beneath := unix.LandlockPathBeneathAttr{
		Allowed_access: unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR,
		Parent_fd:      int32(dir),
	}
	if _, _, e := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, rfd, unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&beneath)), 0, 0, 0); e != 0 {
		return 0, fmt.Errorf("landlock add rule: %w", e)
	}
	if _, _, e := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, rfd, 0, 0); e != 0 {
		return 0, fmt.Errorf("landlock restrict: %w", e)
	}
	return abi, nil
}
