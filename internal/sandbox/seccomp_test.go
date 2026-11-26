// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux && (amd64 || arm64)

package sandbox

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

// evalFilter runs a classic BPF seccomp program over one seccomp_data.
func evalFilter(t *testing.T, prog []unix.SockFilter, arch uint32, nr int, args ...uint64) uint32 {
	t.Helper()
	data := make([]byte, 64)
	binary.LittleEndian.PutUint32(data[0:], uint32(nr))
	binary.LittleEndian.PutUint32(data[4:], arch)
	for i, a := range args {
		binary.LittleEndian.PutUint64(data[16+8*i:], a)
	}
	var acc uint32
	for pc := 0; pc < len(prog); {
		in := prog[pc]
		switch in.Code {
		case bpfLdAbsW:
			acc = binary.LittleEndian.Uint32(data[in.K:])
			pc++
		case bpfAndK:
			acc &= in.K
			pc++
		case bpfJa:
			pc += 1 + int(in.K)
		case bpfJeqK, bpfJgeK, bpfJsetK:
			var cond bool
			switch in.Code {
			case bpfJeqK:
				cond = acc == in.K
			case bpfJgeK:
				cond = acc >= in.K
			default:
				cond = acc&in.K != 0
			}
			if cond {
				pc += 1 + int(in.Jt)
			} else {
				pc += 1 + int(in.Jf)
			}
		case bpfRetK:
			return in.K
		default:
			t.Fatalf("unexpected instruction %#x at %d", in.Code, pc)
		}
	}
	t.Fatal("program fell off the end")
	return 0
}

type filterCase struct {
	name string
	nr   int
	args []uint64
	want uint32
}

func checkCases(t *testing.T, prog []unix.SockFilter, cases []filterCase) {
	t.Helper()
	for _, c := range cases {
		if got := evalFilter(t, prog, AuditArch, c.nr, c.args...); got != c.want {
			t.Errorf("%s: %#x, want %#x", c.name, got, c.want)
		}
	}
	if got := evalFilter(t, prog, 0x40000003 /* i386 */, unix.SYS_READ); got != RetKill {
		t.Errorf("foreign architecture: %#x", got)
	}
	if checkX32 {
		if got := evalFilter(t, prog, AuditArch, x32SyscallBit|unix.SYS_READ); got != RetKill {
			t.Errorf("x32 call: %#x", got)
		}
	}
}

var (
	eperm  = Errno(unix.EPERM)
	eacces = Errno(unix.EACCES)
	enosys = Errno(unix.ENOSYS)
)

// probeCases hold for the probe filter and, unless commandCases says
// otherwise, for the command filter.
var probeCases = []filterCase{
	{"read", unix.SYS_READ, nil, RetAllow},
	{"write", unix.SYS_WRITE, nil, RetAllow},
	{"execve", unix.SYS_EXECVE, nil, RetAllow},
	{"memfd_create", unix.SYS_MEMFD_CREATE, nil, RetAllow},
	{"capset", unix.SYS_CAPSET, nil, RetAllow},
	{"waitid", unix.SYS_WAITID, nil, RetAllow},
	{"ptrace", unix.SYS_PTRACE, nil, eperm},
	{"process_vm_readv", unix.SYS_PROCESS_VM_READV, nil, eperm},
	{"bpf", unix.SYS_BPF, nil, eperm},
	{"mount", unix.SYS_MOUNT, nil, eperm},
	{"io_uring_setup", unix.SYS_IO_URING_SETUP, nil, eperm},
	{"socket inet", unix.SYS_SOCKET, []uint64{unix.AF_INET}, eperm},
	{"socket inet6", unix.SYS_SOCKET, []uint64{unix.AF_INET6}, eperm},
	{"socket packet", unix.SYS_SOCKET, []uint64{unix.AF_PACKET}, eperm},
	{"openat read", unix.SYS_OPENAT, []uint64{0, 0, unix.O_RDONLY | unix.O_CLOEXEC | unix.O_DIRECTORY}, RetAllow},
	{"openat write", unix.SYS_OPENAT, []uint64{0, 0, unix.O_WRONLY}, eacces},
	{"openat rdwr", unix.SYS_OPENAT, []uint64{0, 0, unix.O_RDWR}, eacces},
	{"openat create", unix.SYS_OPENAT, []uint64{0, 0, unix.O_RDONLY | unix.O_CREAT}, eacces},
	{"openat trunc", unix.SYS_OPENAT, []uint64{0, 0, unix.O_RDONLY | unix.O_TRUNC}, eacces},
	{"openat2", unix.SYS_OPENAT2, nil, enosys},
	{"clone thread", unix.SYS_CLONE, []uint64{unix.CLONE_VM | unix.CLONE_THREAD}, RetAllow},
	{"clone newuser", unix.SYS_CLONE, []uint64{unix.CLONE_NEWUSER}, eperm},
	{"clone3", unix.SYS_CLONE3, nil, enosys},
	{"unshare newuser", unix.SYS_UNSHARE, []uint64{unix.CLONE_NEWUSER | unix.CLONE_NEWNS}, eperm},
	{"unshare newnet", unix.SYS_UNSHARE, []uint64{unix.CLONE_NEWNET}, eperm},
	{"setns", unix.SYS_SETNS, nil, eperm},
	{"chroot", unix.SYS_CHROOT, nil, eperm},
	{"settimeofday", unix.SYS_SETTIMEOFDAY, nil, eperm},
	{"sethostname", unix.SYS_SETHOSTNAME, nil, eperm},
	{"syslog read all", unix.SYS_SYSLOG, []uint64{3}, RetAllow},
	{"syslog clear", unix.SYS_SYSLOG, []uint64{5}, eperm},
	{"syslog console level", unix.SYS_SYSLOG, []uint64{8}, eperm},
	{"fchmod", unix.SYS_FCHMOD, nil, eacces},
	{"fchown", unix.SYS_FCHOWN, nil, eacces},
	{"setuid", unix.SYS_SETUID, nil, RetAllow},
	{"setgroups", unix.SYS_SETGROUPS, nil, RetAllow},
	{"prctl", unix.SYS_PRCTL, nil, RetAllow},
	{"unlinkat", unix.SYS_UNLINKAT, nil, eacces},
	{"renameat2", unix.SYS_RENAMEAT2, nil, eacces},
	{"truncate", unix.SYS_TRUNCATE, nil, eacces},
}

func TestProbeFilter(t *testing.T) {
	prog, err := Build(ProbeRules())
	if err != nil {
		t.Fatal(err)
	}
	checkCases(t, prog, probeCases)
	checkCases(t, prog, []filterCase{
		{"socket unix", unix.SYS_SOCKET, []uint64{unix.AF_UNIX}, RetAllow},
		{"socket netlink", unix.SYS_SOCKET, []uint64{unix.AF_NETLINK}, RetAllow},
		{"clone newnet", unix.SYS_CLONE, []uint64{unix.CLONE_NEWNET}, RetAllow},
		{"clone process", unix.SYS_CLONE, []uint64{uint64(unix.SIGCHLD)}, RetAllow},
		{"kill", unix.SYS_KILL, []uint64{1234, 9}, RetAllow},
		{"setsid", unix.SYS_SETSID, nil, RetAllow},
		{"keyctl", unix.SYS_KEYCTL, nil, RetAllow},
	})
}

func TestListenerFilter(t *testing.T) {
	full, lst := ProbeRules(), ListenerRules()
	if len(lst) != len(full)-1 {
		t.Fatalf("listener rules: %d, full: %d", len(lst), len(full))
	}
	prog, err := Build(lst)
	if err != nil {
		t.Fatal(err)
	}
	if r := evalFilter(t, prog, AuditArch, unix.SYS_CHROOT); r != RetAllow {
		t.Errorf("chroot under the listener filter: %#x", r)
	}
	for _, nr := range []int{unix.SYS_PTRACE, unix.SYS_SETNS, unix.SYS_MOUNT} {
		if r := evalFilter(t, prog, AuditArch, nr); r == RetAllow {
			t.Errorf("syscall %d allowed under the listener filter", nr)
		}
	}
	if r := evalFilter(t, prog, AuditArch, unix.SYS_SOCKET, unix.AF_INET); r == RetAllow {
		t.Error("AF_INET socket allowed under the listener filter")
	}
}

func TestCommandFilter(t *testing.T) {
	const self = 4242
	prog, err := CommandFilter(self)
	if err != nil {
		t.Fatal(err)
	}
	neg := func(pid int) uint64 { return uint64(uint32(int32(-pid))) }
	minus1 := uint64(0xffffffff)
	commandCases := []filterCase{
		{"socket unix", unix.SYS_SOCKET, []uint64{unix.AF_UNIX}, eperm},
		{"socket netlink", unix.SYS_SOCKET, []uint64{unix.AF_NETLINK}, eperm},
		{"socketpair", unix.SYS_SOCKETPAIR, []uint64{unix.AF_UNIX}, RetAllow},
		{"clone process", unix.SYS_CLONE, []uint64{uint64(unix.SIGCHLD)}, eperm},
		{"clone vfork", unix.SYS_CLONE, []uint64{unix.CLONE_VM | unix.CLONE_VFORK | uint64(unix.SIGCHLD)}, eperm},
		{"clone thread newnet", unix.SYS_CLONE, []uint64{unix.CLONE_VM | unix.CLONE_THREAD | unix.CLONE_NEWNET}, eperm},
		{"clone newpid", unix.SYS_CLONE, []uint64{unix.CLONE_NEWPID}, eperm},
		{"clone thread, high bits", unix.SYS_CLONE, []uint64{1<<40 | unix.CLONE_VM | unix.CLONE_THREAD | unix.CLONE_SIGHAND}, RetAllow},
		{"setsid", unix.SYS_SETSID, nil, eperm},
		{"setpgid", unix.SYS_SETPGID, []uint64{0, 0}, eperm},
		{"kill self", unix.SYS_KILL, []uint64{self, 9}, RetAllow},
		{"kill own group", unix.SYS_KILL, []uint64{0, 9}, RetAllow},
		{"kill own group by id", unix.SYS_KILL, []uint64{neg(self), 9}, RetAllow},
		{"kill other", unix.SYS_KILL, []uint64{self + 1, 9}, eperm},
		{"kill all", unix.SYS_KILL, []uint64{minus1, 9}, eperm},
		{"kill other group", unix.SYS_KILL, []uint64{neg(77), 9}, eperm},
		{"kill other, self in high bits", unix.SYS_KILL, []uint64{1<<32 | 77, 9}, eperm},
		{"tgkill self", unix.SYS_TGKILL, []uint64{self, self + 3, 23}, RetAllow},
		{"tgkill other", unix.SYS_TGKILL, []uint64{77, 77, 9}, eperm},
		{"tkill", unix.SYS_TKILL, []uint64{self, 9}, eperm},
		{"rt_sigqueueinfo other", unix.SYS_RT_SIGQUEUEINFO, []uint64{77, 9}, eperm},
		{"rt_tgsigqueueinfo self", unix.SYS_RT_TGSIGQUEUEINFO, []uint64{self, self, 9}, RetAllow},
		{"pidfd_open", unix.SYS_PIDFD_OPEN, []uint64{self}, eperm},
		{"pidfd_send_signal", unix.SYS_PIDFD_SEND_SIGNAL, nil, eperm},
		{"prlimit64 self", unix.SYS_PRLIMIT64, []uint64{0, unix.RLIMIT_NOFILE}, RetAllow},
		{"prlimit64 other", unix.SYS_PRLIMIT64, []uint64{77, unix.RLIMIT_NOFILE}, eperm},
		{"setpriority self", unix.SYS_SETPRIORITY, []uint64{unix.PRIO_PROCESS, 0, 19}, RetAllow},
		{"setpriority thread", unix.SYS_SETPRIORITY, []uint64{unix.PRIO_PROCESS, self, 19}, RetAllow},
		{"setpriority other", unix.SYS_SETPRIORITY, []uint64{unix.PRIO_PROCESS, 77, 19}, eperm},
		{"setpriority user", unix.SYS_SETPRIORITY, []uint64{unix.PRIO_USER, 0, 19}, eperm},
		{"ioprio_set user", unix.SYS_IOPRIO_SET, []uint64{3, 0, 0}, eperm},
		{"ioprio_set self", unix.SYS_IOPRIO_SET, []uint64{1, 0, 0}, RetAllow},
		{"sched_setaffinity other", unix.SYS_SCHED_SETAFFINITY, []uint64{77}, eperm},
		{"sched_setaffinity self", unix.SYS_SCHED_SETAFFINITY, []uint64{0}, RetAllow},
		{"move_pages other", unix.SYS_MOVE_PAGES, []uint64{77}, eperm},
		{"kcmp", unix.SYS_KCMP, nil, eperm},
		{"keyctl", unix.SYS_KEYCTL, nil, eperm},
		{"add_key", unix.SYS_ADD_KEY, nil, eperm},
		{"request_key", unix.SYS_REQUEST_KEY, nil, eperm},
		{"shmget", unix.SYS_SHMGET, nil, eperm},
		{"semop", unix.SYS_SEMOP, nil, eperm},
		{"msgget", unix.SYS_MSGGET, nil, eperm},
		{"mq_open", unix.SYS_MQ_OPEN, nil, eacces},
		{"personality query", unix.SYS_PERSONALITY, []uint64{0xffffffff}, RetAllow},
		{"personality linux", unix.SYS_PERSONALITY, []uint64{0}, RetAllow},
		{"personality no aslr", unix.SYS_PERSONALITY, []uint64{0x0040000}, eperm},
		{"ioctl tiocsti", unix.SYS_IOCTL, []uint64{0, unix.TIOCSTI}, eperm},
		{"ioctl tioclinux", unix.SYS_IOCTL, []uint64{0, unix.TIOCLINUX}, eperm},
		{"ioctl tcgets", unix.SYS_IOCTL, []uint64{0, unix.TCGETS}, RetAllow},
		{"sigaltstack", unix.SYS_SIGALTSTACK, nil, RetAllow},
		{"mmap", unix.SYS_MMAP, nil, RetAllow},
	}
	// Every probe case holds except those the command rules replace.
	replaced := map[int]bool{unix.SYS_SOCKET: true, unix.SYS_CLONE: true}
	var inherited []filterCase
	for _, c := range probeCases {
		if !replaced[c.nr] {
			inherited = append(inherited, c)
		}
	}
	checkCases(t, prog, inherited)
	checkCases(t, prog, commandCases)
	checkCases(t, prog, archCommandCases())
}

func TestBuildRejectsDuplicates(t *testing.T) {
	rules := append(Deny(eperm, unix.SYS_KILL), Deny(eacces, unix.SYS_KILL)...)
	if _, err := Build(rules); err == nil {
		t.Fatal("two rules for one system call accepted")
	}
}
