// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package probe

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

func TestSeccompFilter(t *testing.T) {
	prog, err := buildFilter(seccompRules())
	if err != nil {
		t.Fatal(err)
	}
	eperm, eacces, enosys := errnoRet(unix.EPERM), errnoRet(unix.EACCES), errnoRet(unix.ENOSYS)
	cases := []struct {
		name string
		nr   int
		args []uint64
		want uint32
	}{
		{"read", unix.SYS_READ, nil, retAllow},
		{"write", unix.SYS_WRITE, nil, retAllow},
		{"execve", unix.SYS_EXECVE, nil, retAllow},
		{"memfd_create", unix.SYS_MEMFD_CREATE, nil, retAllow},
		{"capset", unix.SYS_CAPSET, nil, retAllow},
		{"waitid", unix.SYS_WAITID, nil, retAllow},
		{"ptrace", unix.SYS_PTRACE, nil, eperm},
		{"process_vm_readv", unix.SYS_PROCESS_VM_READV, nil, eperm},
		{"bpf", unix.SYS_BPF, nil, eperm},
		{"mount", unix.SYS_MOUNT, nil, eperm},
		{"io_uring_setup", unix.SYS_IO_URING_SETUP, nil, eperm},
		{"socket inet", unix.SYS_SOCKET, []uint64{unix.AF_INET}, eperm},
		{"socket inet6", unix.SYS_SOCKET, []uint64{unix.AF_INET6}, eperm},
		{"socket packet", unix.SYS_SOCKET, []uint64{unix.AF_PACKET}, eperm},
		{"socket unix", unix.SYS_SOCKET, []uint64{unix.AF_UNIX}, retAllow},
		{"socket netlink", unix.SYS_SOCKET, []uint64{unix.AF_NETLINK}, retAllow},
		{"openat read", unix.SYS_OPENAT, []uint64{0, 0, unix.O_RDONLY | unix.O_CLOEXEC | unix.O_DIRECTORY}, retAllow},
		{"openat write", unix.SYS_OPENAT, []uint64{0, 0, unix.O_WRONLY}, eacces},
		{"openat rdwr", unix.SYS_OPENAT, []uint64{0, 0, unix.O_RDWR}, eacces},
		{"openat create", unix.SYS_OPENAT, []uint64{0, 0, unix.O_RDONLY | unix.O_CREAT}, eacces},
		{"openat trunc", unix.SYS_OPENAT, []uint64{0, 0, unix.O_RDONLY | unix.O_TRUNC}, eacces},
		{"openat2", unix.SYS_OPENAT2, nil, enosys},
		{"clone thread", unix.SYS_CLONE, []uint64{unix.CLONE_VM | unix.CLONE_THREAD}, retAllow},
		{"clone newuser", unix.SYS_CLONE, []uint64{unix.CLONE_NEWUSER}, eperm},
		{"clone3", unix.SYS_CLONE3, nil, enosys},
		{"unshare newuser", unix.SYS_UNSHARE, []uint64{unix.CLONE_NEWUSER | unix.CLONE_NEWNS}, eperm},
		{"unshare newnet", unix.SYS_UNSHARE, []uint64{unix.CLONE_NEWNET}, eperm},
		{"clone newnet", unix.SYS_CLONE, []uint64{unix.CLONE_NEWNET}, retAllow},
		{"setns", unix.SYS_SETNS, nil, eperm},
		{"chroot", unix.SYS_CHROOT, nil, eperm},
		{"settimeofday", unix.SYS_SETTIMEOFDAY, nil, eperm},
		{"sethostname", unix.SYS_SETHOSTNAME, nil, eperm},
		{"syslog read all", unix.SYS_SYSLOG, []uint64{3}, retAllow},
		{"syslog clear", unix.SYS_SYSLOG, []uint64{5}, eperm},
		{"syslog console level", unix.SYS_SYSLOG, []uint64{8}, eperm},
		{"fchmod", unix.SYS_FCHMOD, nil, eacces},
		{"fchown", unix.SYS_FCHOWN, nil, eacces},
		{"setuid", unix.SYS_SETUID, nil, retAllow},
		{"setgroups", unix.SYS_SETGROUPS, nil, retAllow},
		{"prctl", unix.SYS_PRCTL, nil, retAllow},
		{"kill", unix.SYS_KILL, nil, retAllow},
		{"unlinkat", unix.SYS_UNLINKAT, nil, eacces},
		{"renameat2", unix.SYS_RENAMEAT2, nil, eacces},
		{"truncate", unix.SYS_TRUNCATE, nil, eacces},
	}
	for _, c := range cases {
		if got := evalFilter(t, prog, auditArch, c.nr, c.args...); got != c.want {
			t.Errorf("%s: %#x, want %#x", c.name, got, c.want)
		}
	}
	if got := evalFilter(t, prog, 0x40000003 /* i386 */, unix.SYS_READ); got != retKill {
		t.Errorf("foreign architecture: %#x", got)
	}
	if checkX32 {
		if got := evalFilter(t, prog, auditArch, x32SyscallBit|unix.SYS_READ); got != retKill {
			t.Errorf("x32 call: %#x", got)
		}
	}
}
