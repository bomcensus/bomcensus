// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux && (amd64 || arm64)

package sandbox

// The probe filter is a deny list: everything not named here is allowed,
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
	"slices"

	"golang.org/x/sys/unix"
)

// syslogReadActions are the syslog(2) actions that only read the kernel
// log: READ, READ_ALL, SIZE_UNREAD and SIZE_BUFFER.
var syslogReadActions = []uint32{2, 3, 9, 10}

// openWriteFlags are the open flags that write to or create a file.
const openWriteFlags = unix.O_WRONLY | unix.O_RDWR | unix.O_CREAT | unix.O_TRUNC

// ProbeRules are the rules of the probe's own filter.
func ProbeRules() []Rule {
	eperm := Errno(unix.EPERM)
	eacces := Errno(unix.EACCES)
	enosys := Errno(unix.ENOSYS)

	rules := Deny(eperm,
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
		Rule{Nr: unix.SYS_SOCKET, Ret: eperm, Conds: []Cond{{Arg: 0, Op: NotIn, Values: []uint32{unix.AF_UNIX, unix.AF_NETLINK}}}},
		Rule{Nr: unix.SYS_CLONE, Ret: eperm, Conds: []Cond{{Arg: 0, Op: AnyBits, K: unix.CLONE_NEWUSER}}},
		Rule{Nr: unix.SYS_SYSLOG, Ret: eperm, Conds: []Cond{{Arg: 0, Op: NotIn, Values: syslogReadActions}}},
		Rule{Nr: unix.SYS_OPENAT, Ret: eacces, Conds: []Cond{{Arg: 2, Op: AnyBits, K: openWriteFlags}}},
	)
	rules = append(rules, Deny(enosys, unix.SYS_CLONE3, unix.SYS_OPENAT2)...)
	rules = append(rules, Deny(eacces,
		unix.SYS_TRUNCATE,
		unix.SYS_MKDIRAT, unix.SYS_MKNODAT, unix.SYS_UNLINKAT, unix.SYS_RENAMEAT, unix.SYS_RENAMEAT2,
		unix.SYS_LINKAT, unix.SYS_SYMLINKAT,
		unix.SYS_FCHMODAT, unix.SYS_FCHMODAT2, unix.SYS_FCHOWNAT, unix.SYS_UTIMENSAT,
		unix.SYS_SETXATTR, unix.SYS_LSETXATTR, unix.SYS_REMOVEXATTR, unix.SYS_LREMOVEXATTR,
		unix.SYS_SETXATTRAT, unix.SYS_REMOVEXATTRAT,
		// These act on descriptors, which may be open read-only.
		unix.SYS_FCHMOD, unix.SYS_FCHOWN, unix.SYS_FSETXATTR, unix.SYS_FREMOVEXATTR,
	)...)
	return append(rules, archProbeRules(eacces)...)
}

// ListenerRules are the rules of the serve listener: those of the probe
// without the chroot denial. Every collect child inherits the listener's
// filter and, in host root mode, still has to change its root before it
// installs the full filter itself.
func ListenerRules() []Rule {
	return slices.DeleteFunc(ProbeRules(), func(r Rule) bool { return r.Nr == unix.SYS_CHROOT })
}

// namespaceFlags are the clone flags that create namespaces.
const namespaceFlags = unix.CLONE_NEWNS | unix.CLONE_NEWCGROUP | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC |
	unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWNET

// Personality values a version command may set: PER_LINUX, PER_LINUX32
// and the query 0xffffffff.
var allowedPersonalities = []uint32{0, 8, 0xffffffff}

// CommandRules are the rules of a version command's own filter. They are
// the probe's rules, so that the command is confined even where the
// probe's filter is missing, tightened for a single untrusted program
// that is pid self (the exec helper, which then executes the command):
//
//   - no new processes: fork, vfork and clone without CLONE_THREAD fail,
//     as do clone with namespace flags, setsid and setpgid. The command
//     therefore stays a single process in the process group and session
//     the helper created, and nothing outlives it.
//   - signals only to itself: kill only for pid 0, self and -self;
//     tgkill, rt_sigqueueinfo and rt_tgsigqueueinfo only for thread group
//     self; tkill, pidfd_open and pidfd_send_signal not at all. Other
//     processes of the same user (uid 65534 is shared with other services,
//     and the probe itself runs as it) cannot be signalled.
//   - no changes to other processes that the same uid would otherwise
//     permit: prlimit64, setpriority, ioprio_set, sched_setaffinity,
//     sched_setscheduler, sched_setparam, sched_setattr, migrate_pages
//     and move_pages only for itself; kcmp and process_mrelease not at all.
//   - no sockets of any family (a command could otherwise reach abstract
//     Unix sockets of the host's network namespace, or path sockets its
//     groups may write, such as a container runtime's). socketpair works.
//   - no kernel keyrings (add_key, keyctl, request_key), which are shared
//     by every process of a user; no System V IPC and no POSIX message
//     queues, which are shared within the IPC namespace.
//   - personality only PER_LINUX, PER_LINUX32 or the query; no TIOCSTI
//     and TIOCLINUX ioctls; on amd64 no modify_ldt and uselib.
func CommandRules(self int) []Rule {
	eperm := Errno(unix.EPERM)
	eacces := Errno(unix.EACCES)
	me, neg := uint32(int32(self)), uint32(int32(-self))
	selfOnly := func(nr uintptr, arg int, also ...uint32) Rule {
		return Rule{Nr: nr, Ret: eperm, Conds: []Cond{{Arg: arg, Op: NotIn, Values: append([]uint32{me}, also...)}}}
	}

	own := []Rule{
		{Nr: unix.SYS_SOCKET, Ret: eperm},
		{Nr: unix.SYS_CLONE, Ret: eperm, Conds: []Cond{
			{Arg: 0, Op: AnyBits, K: namespaceFlags},
			{Arg: 0, Op: MissingBits, K: unix.CLONE_THREAD},
		}},
		selfOnly(unix.SYS_KILL, 0, 0, neg),
		selfOnly(unix.SYS_TGKILL, 0),
		selfOnly(unix.SYS_RT_SIGQUEUEINFO, 0),
		selfOnly(unix.SYS_RT_TGSIGQUEUEINFO, 0),
		selfOnly(unix.SYS_PRLIMIT64, 0, 0),
		selfOnly(unix.SYS_SCHED_SETAFFINITY, 0, 0),
		selfOnly(unix.SYS_SCHED_SETSCHEDULER, 0, 0),
		selfOnly(unix.SYS_SCHED_SETPARAM, 0, 0),
		selfOnly(unix.SYS_SCHED_SETATTR, 0, 0),
		selfOnly(unix.SYS_MIGRATE_PAGES, 0, 0),
		selfOnly(unix.SYS_MOVE_PAGES, 0, 0),
		{Nr: unix.SYS_SETPRIORITY, Ret: eperm, Conds: []Cond{
			{Arg: 0, Op: NotIn, Values: []uint32{unix.PRIO_PROCESS}},
			{Arg: 1, Op: NotIn, Values: []uint32{0, me}},
		}},
		{Nr: unix.SYS_IOPRIO_SET, Ret: eperm, Conds: []Cond{
			{Arg: 0, Op: NotIn, Values: []uint32{1}}, // IOPRIO_WHO_PROCESS
			{Arg: 1, Op: NotIn, Values: []uint32{0, me}},
		}},
		{Nr: unix.SYS_PERSONALITY, Ret: eperm, Conds: []Cond{{Arg: 0, Op: NotIn, Values: allowedPersonalities}}},
		{Nr: unix.SYS_IOCTL, Ret: eperm, Conds: []Cond{{Arg: 1, Op: In, Values: []uint32{unix.TIOCSTI, unix.TIOCLINUX}}}},
		{Nr: unix.SYS_MQ_OPEN, Ret: eacces},
	}
	own = append(own, Deny(eperm,
		unix.SYS_SETSID, unix.SYS_SETPGID,
		unix.SYS_TKILL, unix.SYS_PIDFD_OPEN, unix.SYS_PIDFD_SEND_SIGNAL,
		unix.SYS_KCMP, unix.SYS_PROCESS_MRELEASE,
		unix.SYS_ADD_KEY, unix.SYS_KEYCTL, unix.SYS_REQUEST_KEY,
		unix.SYS_SHMGET, unix.SYS_SHMAT, unix.SYS_SHMCTL,
		unix.SYS_MSGGET, unix.SYS_MSGSND, unix.SYS_MSGRCV, unix.SYS_MSGCTL,
		unix.SYS_SEMGET, unix.SYS_SEMOP, unix.SYS_SEMTIMEDOP, unix.SYS_SEMCTL,
	)...)
	own = append(own, archCommandRules(eperm)...)

	replaced := map[uintptr]bool{}
	for _, r := range own {
		replaced[r.Nr] = true
	}
	rules := slices.DeleteFunc(ProbeRules(), func(r Rule) bool { return replaced[r.Nr] })
	return append(rules, own...)
}

// CommandFilter builds the filter of CommandRules.
func CommandFilter(self int) ([]unix.SockFilter, error) { return Build(CommandRules(self)) }
