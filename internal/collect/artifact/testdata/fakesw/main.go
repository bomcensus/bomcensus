// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Command fakesw is run as a version command by the tests of package
// artifact. Its first argument selects what it does: print a version,
// sleep, flood its output, print its environment or process state, or try
// what the sandbox must deny (fork, daemon, attack, net).
//
// The runtime must not keep the cgroup file cpu.max open, which the
// descriptor check would report.
//
//go:debug containermaxprocs=0
//go:debug updatemaxprocs=0
package main

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func report(name string, err error) {
	if err == nil {
		fmt.Printf("%s=allowed\n", name)
	} else {
		fmt.Printf("%s=denied: %v\n", name, err)
	}
}

func errno(e syscall.Errno) error {
	if e == 0 {
		return nil
	}
	return e
}

func main() {
	switch os.Args[1] {
	case "version":
		fmt.Println("fakesw version 1.2.3")
		fmt.Fprintln(os.Stderr, "some warning")
		os.Exit(3)
	case "sleep":
		time.Sleep(time.Minute)
	case "big":
		os.Stdout.WriteString(strings.Repeat("o", 200<<10))
		os.Stderr.WriteString(strings.Repeat("e", 100<<10))
	case "flood":
		chunk := []byte(strings.Repeat("f", 4096))
		for {
			os.Stdout.Write(chunk)
		}
	case "env":
		for _, e := range os.Environ() {
			fmt.Println(e)
		}
	case "status":
		b, _ := os.ReadFile("/proc/self/status")
		os.Stdout.Write(b)
		l, _ := os.ReadFile("/proc/self/limits")
		os.Stdout.Write(l)
		in, _ := os.Readlink("/proc/self/fd/0")
		fmt.Printf("stdin=%s\n", in)
		ns, _ := os.Readlink("/proc/self/ns/net")
		fmt.Printf("netns:\t%s\n", ns)
		sid, _, _ := syscall.RawSyscall(syscall.SYS_GETSID, 0, 0, 0)
		fmt.Printf("sid:\t%d\n", sid)
		wd, _ := os.Getwd()
		fmt.Printf("cwd:\t%s\n", wd)
		d, _ := os.Open("/proc/self/fd")
		names, _ := d.Readdirnames(-1)
		var fds []string
		for _, n := range names {
			// The Go runtime's own epoll and event descriptors are
			// anonymous inodes.
			l, _ := os.Readlink("/proc/self/fd/" + n)
			if n != strconv.Itoa(int(d.Fd())) && !strings.HasPrefix(l, "anon_inode:") {
				fds = append(fds, n)
			}
		}
		sort.Strings(fds)
		fmt.Printf("fds:\t%s\n", strings.Join(fds, ","))
		if len(os.Args) > 2 {
			f, err := os.Create(os.Args[2])
			if err == nil {
				_, err = f.Write([]byte("x"))
				f.Close()
			}
			fmt.Printf("write=%v\n", err)
		}
	case "fork":
		// A child that would outlive the command.
		cmd := exec.Command(os.Args[0], "sleep")
		cmd.Stdout = os.Stdout
		err := cmd.Start()
		if err == nil {
			fmt.Printf("child=%d\n", cmd.Process.Pid)
		}
		report("fork", err)
	case "forkbomb":
		n := 0
		var last error
		for range 200 {
			pid, err := syscall.ForkExec(os.Args[0], []string{os.Args[0], "sleep"}, &syscall.ProcAttr{})
			if err != nil {
				last = err
				continue
			}
			n++
			fmt.Printf("child=%d\n", pid)
		}
		fmt.Printf("forks=%d\n", n)
		report("forkbomb", last)
	case "daemon":
		// Leave the process group and session, then fork a child that
		// would survive the group kill.
		_, _, e := syscall.RawSyscall(syscall.SYS_SETSID, 0, 0, 0)
		report("setsid", errno(e))
		report("setpgid", syscall.Setpgid(0, 0))
		cmd := exec.Command(os.Args[0], "sleep")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		err := cmd.Start()
		if err == nil {
			fmt.Printf("child=%d\n", cmd.Process.Pid)
		}
		report("daemon", err)
	case "attack":
		// Try to reach the process with pid os.Args[2] (another process
		// of the same user, or the caller).
		pid, _ := strconv.Atoi(os.Args[2])
		report("kill0", syscall.Kill(pid, 0))
		report("kill", syscall.Kill(pid, syscall.SIGKILL))
		report("killgroup", syscall.Kill(-pid, syscall.SIGKILL))
		report("killall", syscall.Kill(-1, 0))
		_, _, e := syscall.RawSyscall(syscall.SYS_TGKILL, uintptr(pid), uintptr(pid), uintptr(syscall.SIGSTOP))
		report("tgkill", errno(e))
		report("ptrace", syscall.PtraceAttach(pid))
		_, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
		report("environ", err)
		f, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
		if err == nil {
			f.Close()
		}
		report("mem", err)
		var lim [2]uint64
		_, _, e = syscall.RawSyscall6(syscall.SYS_PRLIMIT64, uintptr(pid), uintptr(syscall.RLIMIT_NOFILE), 0, uintptr(unsafe.Pointer(&lim[0])), 0, 0)
		report("prlimit", errno(e))
		report("setpriority", syscall.Setpriority(syscall.PRIO_PROCESS, pid, 19))
		report("setpriority_user", syscall.Setpriority(2 /* PRIO_USER */, 0, 19))
	case "net":
		for _, s := range []struct {
			name     string
			fam, typ int
		}{{"tcp", syscall.AF_INET, syscall.SOCK_STREAM}, {"udp6", syscall.AF_INET6, syscall.SOCK_DGRAM},
			{"unix", syscall.AF_UNIX, syscall.SOCK_STREAM}, {"netlink", syscall.AF_NETLINK, syscall.SOCK_RAW}} {
			fd, err := syscall.Socket(s.fam, s.typ, 0)
			if err == nil {
				syscall.Close(fd)
			}
			report(s.name, err)
		}
		_, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
		report("socketpair", err)
	}
}
