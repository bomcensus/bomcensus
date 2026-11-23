// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux && (amd64 || arm64)

package probe

// The seccomp filter is a deny list: everything not named here is allowed,
// so that the collectors, the exec helper (execve, clone, prctl, capset,
// setrlimit, waitid, kill) and arbitrary runtimes run by version commands
// keep working. Denied calls fail with an errno instead of killing the
// process. Calls of a foreign architecture (i386, x32) kill the process.
//
// Denied with EPERM:
//   - tampering with other processes: ptrace, process_vm_readv/writev,
//     pidfd_getfd, process_madvise
//   - kernel attack surface: perf_event_open, bpf, userfaultfd, io_uring_*
//     (which would also bypass the socket rule), user namespaces through
//     clone, unshare and setns with any flags
//   - system changes: kexec_*, module loading, mount and the new mount API,
//     chroot, reboot, swapon/swapoff, acct, setting the clock (settimeofday,
//     clock_settime, adjtimex and clock_adjtime, which cannot be told apart
//     from their read-only use), sethostname, setdomainname, quotactl,
//     iopl/ioperm, and syslog actions other than reading
//
// The exec helper still works: it needs setuid, setgid, setgroups, capset,
// prctl, setrlimit, clone and execve, none of which is restricted beyond
// CLONE_NEWUSER. kill and tgkill cannot be limited to the probe's own
// children by seccomp and stay allowed.
//   - sockets of any family but AF_UNIX and AF_NETLINK
//   - open_by_handle_at, which with CAP_DAC_READ_SEARCH opens files by
//     handle around path checks
//
// Denied with EACCES, so that "no write" also holds where Landlock is not
// available: opening with write access, O_CREAT or O_TRUNC; creat;
// truncate; creating, removing, renaming and linking names; changing
// modes, owners, extended attributes and timestamps by path or by
// descriptor (a root probe could otherwise change them through a
// descriptor opened read-only). Writing to
// descriptors that are already open (stdout, pipes, memfds) is unaffected.
//
// Denied with ENOSYS, because their flags sit in memory the filter cannot
// inspect: clone3 and openat2. C libraries fall back to clone and openat.

import (
	"fmt"
	"slices"
	"unsafe"

	"golang.org/x/sys/unix"
)

// BPF opcodes and seccomp return values.
const (
	bpfLdAbsW     = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
	bpfJeqK       = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
	bpfJgeK       = unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K
	bpfJsetK      = unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K
	bpfRetK       = unix.BPF_RET | unix.BPF_K
	retAllow      = unix.SECCOMP_RET_ALLOW
	retKill       = unix.SECCOMP_RET_KILL_PROCESS
	retErrno      = unix.SECCOMP_RET_ERRNO
	offNr         = 0
	offArch       = 4
	offArgsLow    = 16 // args[i] low 32 bits on little-endian: 16 + 8*i
	x32SyscallBit = 0x40000000
)

func errnoRet(e unix.Errno) uint32 { return retErrno | uint32(e)&unix.SECCOMP_RET_DATA }

// rule denies one system call, optionally only when an argument matches.
type rule struct {
	nr  uintptr
	ret uint32
	// arg >= 0 selects an argument check: deny when the low 32 bits of
	// args[arg] have any bit of mask set (mask != 0), or when they equal
	// none of allow (allow != nil).
	arg   int
	mask  uint32
	allow []uint32
}

func deny(ret uint32, nrs ...uintptr) []rule {
	out := make([]rule, 0, len(nrs))
	for _, nr := range nrs {
		out = append(out, rule{nr: nr, ret: ret, arg: -1})
	}
	return out
}

// syslogReadActions are the syslog(2) actions that only read the kernel
// log: READ, READ_ALL, SIZE_UNREAD and SIZE_BUFFER.
var syslogReadActions = []uint32{2, 3, 9, 10}

// openWriteFlags are the open flags that write to or create a file.
const openWriteFlags = unix.O_WRONLY | unix.O_RDWR | unix.O_CREAT | unix.O_TRUNC

func seccompRules() []rule {
	eperm := errnoRet(unix.EPERM)
	eacces := errnoRet(unix.EACCES)
	enosys := errnoRet(unix.ENOSYS)

	rules := deny(eperm,
		unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV,
		unix.SYS_PIDFD_GETFD, unix.SYS_PROCESS_MADVISE,
		unix.SYS_PERF_EVENT_OPEN, unix.SYS_BPF, unix.SYS_USERFAULTFD,
		unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER,
		unix.SYS_KEXEC_LOAD, unix.SYS_KEXEC_FILE_LOAD,
		unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE,
		unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_MOVE_MOUNT,
		unix.SYS_OPEN_TREE, unix.SYS_OPEN_TREE_ATTR, unix.SYS_FSOPEN, unix.SYS_FSCONFIG,
		unix.SYS_FSMOUNT, unix.SYS_FSPICK, unix.SYS_MOUNT_SETATTR,
		unix.SYS_REBOOT, unix.SYS_SWAPON, unix.SYS_SWAPOFF,
		unix.SYS_OPEN_BY_HANDLE_AT,
		unix.SYS_CHROOT, unix.SYS_SETNS, unix.SYS_UNSHARE, unix.SYS_ACCT,
		unix.SYS_SETTIMEOFDAY, unix.SYS_CLOCK_SETTIME, unix.SYS_ADJTIMEX, unix.SYS_CLOCK_ADJTIME,
		unix.SYS_SETHOSTNAME, unix.SYS_SETDOMAINNAME, unix.SYS_QUOTACTL, unix.SYS_QUOTACTL_FD,
	)
	rules = append(rules,
		rule{nr: unix.SYS_SOCKET, ret: eperm, arg: 0, allow: []uint32{unix.AF_UNIX, unix.AF_NETLINK}},
		rule{nr: unix.SYS_CLONE, ret: eperm, arg: 0, mask: unix.CLONE_NEWUSER},
		rule{nr: unix.SYS_SYSLOG, ret: eperm, arg: 0, allow: syslogReadActions},
		rule{nr: unix.SYS_OPENAT, ret: eacces, arg: 2, mask: openWriteFlags},
	)
	rules = append(rules, deny(enosys, unix.SYS_CLONE3, unix.SYS_OPENAT2)...)
	rules = append(rules, deny(eacces,
		unix.SYS_TRUNCATE,
		unix.SYS_MKDIRAT, unix.SYS_MKNODAT, unix.SYS_UNLINKAT, unix.SYS_RENAMEAT, unix.SYS_RENAMEAT2,
		unix.SYS_LINKAT, unix.SYS_SYMLINKAT,
		unix.SYS_FCHMODAT, unix.SYS_FCHMODAT2, unix.SYS_FCHOWNAT, unix.SYS_UTIMENSAT,
		unix.SYS_SETXATTR, unix.SYS_LSETXATTR, unix.SYS_REMOVEXATTR, unix.SYS_LREMOVEXATTR,
		unix.SYS_SETXATTRAT, unix.SYS_REMOVEXATTRAT,
		// These act on descriptors, which may be open read-only.
		unix.SYS_FCHMOD, unix.SYS_FCHOWN, unix.SYS_FSETXATTR, unix.SYS_FREMOVEXATTR,
	)...)
	return append(rules, archRules(eacces)...)
}

// buildFilter assembles the filter program.
func buildFilter(rules []rule) ([]unix.SockFilter, error) {
	stmt := func(code uint16, k uint32) unix.SockFilter { return unix.SockFilter{Code: code, K: k} }
	jump := func(code uint16, k uint32, jt, jf int) unix.SockFilter {
		return unix.SockFilter{Code: code, K: k, Jt: uint8(jt), Jf: uint8(jf)}
	}
	prog := []unix.SockFilter{
		stmt(bpfLdAbsW, offArch),
		jump(bpfJeqK, auditArch, 1, 0),
		stmt(bpfRetK, retKill),
		stmt(bpfLdAbsW, offNr),
	}
	if checkX32 {
		prog = append(prog, jump(bpfJgeK, x32SyscallBit, 0, 1), stmt(bpfRetK, retKill))
	}
	for _, r := range rules {
		if r.arg < 0 {
			prog = append(prog, jump(bpfJeqK, uint32(r.nr), 0, 1), stmt(bpfRetK, r.ret))
			continue
		}
		// The block returns on every path, so the syscall number need not
		// be reloaded after it.
		var block []unix.SockFilter
		block = append(block, stmt(bpfLdAbsW, uint32(offArgsLow+8*r.arg)))
		if r.allow != nil {
			n := len(r.allow)
			for i, v := range r.allow {
				// Jump over the remaining comparisons and the deny return.
				block = append(block, jump(bpfJeqK, v, n-i, 0))
			}
			block = append(block, stmt(bpfRetK, r.ret), stmt(bpfRetK, retAllow))
		} else {
			block = append(block, jump(bpfJsetK, r.mask, 0, 1), stmt(bpfRetK, r.ret), stmt(bpfRetK, retAllow))
		}
		prog = append(prog, jump(bpfJeqK, uint32(r.nr), 0, len(block)))
		prog = append(prog, block...)
	}
	prog = append(prog, stmt(bpfRetK, retAllow))
	if len(prog) > unix.BPF_MAXINSNS {
		return nil, fmt.Errorf("seccomp filter too long: %d instructions", len(prog))
	}
	for _, in := range prog {
		if int(in.Jt) > 255 || int(in.Jf) > 255 {
			return nil, fmt.Errorf("seccomp filter jump out of range")
		}
	}
	return prog, nil
}

// listenerSeccompRules are the rules of the serve listener: those of the
// probe without the chroot denial. Every collect child inherits the
// listener's filter and, in host root mode, still has to change its root
// before it installs the full filter itself.
func listenerSeccompRules() []rule {
	return slices.DeleteFunc(seccompRules(), func(r rule) bool { return r.nr == unix.SYS_CHROOT })
}

func applySeccomp() SandboxStep { return applySeccompRules(seccompRules()) }

func applySeccompRules(rules []rule) SandboxStep {
	step := SandboxStep{Name: "seccomp"}
	prog, err := buildFilter(rules)
	if err != nil {
		step.Status = StepFailed
		step.Detail = err.Error()
		return step
	}
	if err := installFilter(prog); err != nil {
		step.Status = StepFailed
		step.Detail = err.Error()
		return step
	}
	step.Status = StepApplied
	step.Detail = fmt.Sprintf("%d system calls restricted (%d instructions), all threads", len(rules), len(prog))
	return step
}

// installFilter loads the program on every thread of the process. The
// caller must have set no_new_privs.
func installFilter(prog []unix.SockFilter) error {
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	r, _, e := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&fprog)))
	switch {
	case e != 0:
		return fmt.Errorf("seccomp: %w", e)
	case r != 0:
		return fmt.Errorf("seccomp: thread %d could not be synchronized", r)
	}
	return nil
}
