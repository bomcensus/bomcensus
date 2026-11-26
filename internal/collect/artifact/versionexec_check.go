// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package artifact

// The sandbox check: the current binary run as a version command, through
// the exec helper, tries what the sandbox of version commands must deny and
// prints the outcome. It is part of bomcensus-probe self-test and of the
// tests.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/bomcensus/bomcensus/internal/report"
)

// checkArg is the hidden first argument of the check program.
const checkArg = "__bomcensus_exec_check"

// CommandCheck is the outcome of one attempt inside a version command.
type CommandCheck struct {
	Name string `json:"name"`
	// OK is true when the outcome is the intended one.
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// RunCommand runs exe as a version command with argv and env, under the
// limits and the sandbox the collector uses, without its checks of the
// file and without its cache. addressSpaceMB overrides the address space
// limit when positive. It fails only when the command could not be run.
func RunCommand(ctx context.Context, exe *os.File, argv, env []string, addressSpaceMB int) (*report.VersionOutput, error) {
	lim := defaultExecLimits
	if addressSpaceMB > 0 {
		lim.AddressSpace = uint64(addressSpaceMB) << 20
	}
	res := runVersion(ctx, exe, argv, env, lim)
	if !res.Ran {
		return nil, errors.New(res.Err)
	}
	return res.Output, nil
}

// CheckCommandSandbox runs the check program: the binary exe (normally
// /proc/self/exe, which must call MaybeRunExecHelper first in main) as a
// version command.
func CheckCommandSandbox(ctx context.Context, exe *os.File) ([]CommandCheck, error) {
	// The Go runtime of the check program would otherwise keep the cgroup
	// file cpu.max open, which the descriptor check would report.
	env := []string{"GODEBUG=containermaxprocs=0,updatemaxprocs=0"}
	out, err := RunCommand(ctx, exe, []string{"bomcensus-exec-check", checkArg, strconv.Itoa(os.Getpid())}, env, 0)
	if err != nil {
		return nil, err
	}
	var checks []CommandCheck
	if err := json.Unmarshal([]byte(out.Stdout), &checks); err != nil {
		return nil, fmt.Errorf("check output: %v (exit %d, stderr %q)", err, out.ExitCode, out.Stderr)
	}
	return checks, nil
}

// runCommandChecks is the check program. Its first argument is the pid of
// a process outside the sandbox (the caller) to try to reach.
func runCommandChecks() int {
	other := os.Getppid()
	if len(os.Args) > 2 {
		if n, err := strconv.Atoi(os.Args[2]); err == nil {
			other = n
		}
	}
	var out []CommandCheck
	works := func(name string, ok bool, detail string) {
		out = append(out, CommandCheck{Name: name, OK: ok, Detail: detail})
	}
	denied := func(name string, err error) {
		c := CommandCheck{Name: name, OK: err != nil, Detail: "allowed"}
		if err != nil {
			c.Detail = "denied: " + err.Error()
		}
		out = append(out, c)
	}

	status, _ := os.ReadFile("/proc/self/status")
	field := func(k string) string { return procField(string(status), k) }
	uid := strings.Fields(field("Uid"))
	works("not root", len(uid) == 4 && !slices.Contains(uid, "0"), "uid "+strings.Join(uid, "/"))
	caps := field("CapInh") + field("CapPrm") + field("CapEff") + field("CapAmb")
	works("no capabilities", caps == strings.Repeat("0", 64), "inh/prm/eff/amb "+caps)
	works("no_new_privs", field("NoNewPrivs") == "1", "NoNewPrivs "+field("NoNewPrivs"))
	works("seccomp", field("Seccomp") == "2", "Seccomp "+field("Seccomp")+", filters "+field("Seccomp_filters"))
	fds := openFDs()
	works("only standard descriptors", fds == "0,1,2", "open: "+fds)
	in, _ := os.Readlink("/proc/self/fd/0")
	works("stdin is /dev/null", in == "/dev/null", in)
	cwd, _ := os.Getwd()
	works("cwd is /", cwd == "/", cwd)
	sid, _ := unix.Getsid(0)
	works("own session", sid == os.Getpid() && syscall.Getpgrp() == os.Getpid(), fmt.Sprintf("sid %d pgid %d pid %d", sid, syscall.Getpgrp(), os.Getpid()))

	denied("create file", func() error {
		f, err := os.OpenFile(filepath.Join(os.TempDir(), fmt.Sprintf(".bomcensus-exec-check-%d", os.Getpid())), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			os.Remove(f.Name())
			f.Close()
		}
		return err
	}())
	denied("tcp socket", trySocket(unix.AF_INET, unix.SOCK_STREAM))
	denied("unix socket", trySocket(unix.AF_UNIX, unix.SOCK_STREAM))
	denied("netlink socket", trySocket(unix.AF_NETLINK, unix.SOCK_RAW))
	denied("new process", func() error {
		pid, err := syscall.ForkExec("/proc/self/exe", []string{"true"}, &syscall.ProcAttr{})
		if err == nil {
			var ws syscall.WaitStatus
			syscall.Wait4(pid, &ws, 0, nil)
		}
		return err
	}())
	denied("new session", func() error { _, err := unix.Setsid(); return err }())
	denied("signal another process", unix.Kill(other, 0))
	denied("signal every process", unix.Kill(-1, 0))
	denied("read another process's environment", func() error {
		_, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", other))
		return err
	}())
	denied("read another process's memory", func() error {
		f, err := os.Open(fmt.Sprintf("/proc/%d/mem", other))
		if err == nil {
			f.Close()
		}
		return err
	}())
	denied("ptrace another process", func() error {
		_, _, e := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_ATTACH, uintptr(other), 0, 0, 0, 0)
		if e == 0 {
			unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_DETACH, uintptr(other), 0, 0, 0, 0)
			return nil
		}
		return e
	}())
	denied("change another process's limits", func() error {
		var old unix.Rlimit
		_, _, e := unix.RawSyscall6(unix.SYS_PRLIMIT64, uintptr(other), unix.RLIMIT_NOFILE, 0, uintptr(unsafe.Pointer(&old)), 0, 0)
		if e != 0 {
			return e
		}
		return nil
	}())
	denied("kernel keyring", func() error {
		_, err := unix.KeyctlInt(unix.KEYCTL_GET_KEYRING_ID, unix.KEY_SPEC_USER_KEYRING, 0, 0, 0)
		return err
	}())
	denied("io_uring", func() error {
		var params [120]byte
		fd, _, e := unix.Syscall(unix.SYS_IO_URING_SETUP, 1, uintptr(unsafe.Pointer(&params[0])), 0)
		if e != 0 {
			return e
		}
		unix.Close(int(fd))
		return nil
	}())

	b, _ := json.Marshal(out)
	os.Stdout.Write(b)
	return 0
}

func trySocket(family, typ int) error {
	fd, err := unix.Socket(family, typ|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	unix.Close(fd)
	return nil
}

// openFDs lists the open descriptors, without the one used to list them
// and without anonymous inodes, which the Go runtime opens for itself.
func openFDs() string {
	d, err := os.Open("/proc/self/fd")
	if err != nil {
		return err.Error()
	}
	defer d.Close()
	names, _ := d.Readdirnames(-1)
	var fds []int
	for _, n := range names {
		fd, err := strconv.Atoi(n)
		if err != nil || fd == int(d.Fd()) {
			continue
		}
		// The Go runtime's own epoll and event descriptors.
		if l, _ := os.Readlink("/proc/self/fd/" + n); strings.HasPrefix(l, "anon_inode:") {
			continue
		}
		fds = append(fds, fd)
	}
	slices.Sort(fds)
	var b strings.Builder
	for i, fd := range fds {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(fd))
	}
	return b.String()
}

// procField returns a field of /proc/<pid>/status.
func procField(status, key string) string {
	sc := bufio.NewScanner(bytes.NewReader([]byte(status)))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), key+":"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
