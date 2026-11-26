// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package probe

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"github.com/bomcensus/bomcensus/internal/collect/artifact"
	"github.com/bomcensus/bomcensus/internal/sandbox"
)

// SandboxCheck is the result of trying one operation after the sandbox was
// applied.
type SandboxCheck struct {
	Name string `json:"name"`
	// OK is true when the outcome is the intended one: denied for the
	// operations the sandbox forbids, working for the others.
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// CheckSandbox tries operations the sandbox must deny and operations the
// collectors need. It is meant for the self-test; it leaves nothing behind.
// The own binary is run once as a child with selfArgs and must exit 0 and
// print something.
func CheckSandbox(selfArgs ...string) []SandboxCheck {
	var out []SandboxCheck
	denied := func(name string, err error) {
		c := SandboxCheck{Name: name, OK: err != nil}
		if err != nil {
			c.Detail = "denied: " + err.Error()
		} else {
			c.Detail = "allowed"
		}
		out = append(out, c)
	}
	works := func(name string, err error) {
		c := SandboxCheck{Name: name, OK: err == nil}
		if err != nil {
			c.Detail = err.Error()
		}
		out = append(out, c)
	}

	tmp := filepath.Join(os.TempDir(), fmt.Sprintf(".bomcensus-probe-check-%d", os.Getpid()))
	err := createFile(tmp)
	if err == nil {
		os.Remove(tmp)
	}
	denied("create file", err)
	denied("mkdir", func() error {
		err := os.Mkdir(tmp, 0o700)
		if err == nil {
			os.Remove(tmp)
		}
		return err
	}())
	denied("open /proc/1/mem rw", func() error {
		f, err := os.OpenFile("/proc/1/mem", os.O_RDWR, 0)
		if err == nil {
			f.Close()
		}
		return err
	}())
	denied("tcp socket", socketErr(unix.AF_INET, unix.SOCK_STREAM))
	denied("udp socket", socketErr(unix.AF_INET6, unix.SOCK_DGRAM))
	denied("ptrace", ptraceErr())
	works("unix socket", socketErr(unix.AF_UNIX, unix.SOCK_STREAM))
	works("read file", func() error {
		_, err := os.ReadFile("/proc/self/status")
		return err
	}())
	// Only meaningful when the parent's link is readable at all: same
	// user, or CAP_SYS_PTRACE.
	caps, _ := currentCaps()
	if ppid := os.Getppid(); ppid > 0 {
		if owner, ok := procOwner("/proc", ppid); ok && (owner == os.Geteuid() || caps.effective.has(unix.CAP_SYS_PTRACE)) {
			_, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", ppid))
			works("read parent exe link", err)
		}
	}
	works("memfd", func() error {
		fd, err := unix.MemfdCreate("bomcensus-check", unix.MFD_CLOEXEC)
		if err == nil {
			_, err = unix.Write(fd, []byte("x"))
			unix.Close(fd)
		}
		return err
	}())
	works("run child process", runSelf(selfArgs))
	return append(out, checkCommands(caps)...)
}

// checkCommands runs the own binary as a version command, through the
// exec helper, and reports what it could do from inside (see
// artifact.CheckCommandSandbox). A root probe that cannot switch users
// must not run version commands at all.
func checkCommands(caps capState) []SandboxCheck {
	const name = "version command"
	self, err := os.Open("/proc/self/exe")
	if err != nil {
		return []SandboxCheck{{Name: name, Detail: err.Error()}}
	}
	defer self.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	checks, err := artifact.CheckCommandSandbox(ctx, self)
	if err != nil {
		if os.Geteuid() == 0 && (!caps.effective.has(unix.CAP_SETUID) || !caps.effective.has(unix.CAP_SETGID)) {
			return []SandboxCheck{{Name: name, OK: true, Detail: "not run (root without CAP_SETUID/CAP_SETGID): " + err.Error()}}
		}
		return []SandboxCheck{{Name: name, Detail: err.Error()}}
	}
	out := []SandboxCheck{{Name: name, OK: true, Detail: "ran; landlock " + sandbox.LandlockCommand(sandbox.LandlockABI())}}
	for _, c := range checks {
		out = append(out, SandboxCheck{Name: "command: " + c.Name, OK: c.OK, Detail: c.Detail})
	}
	return out
}

// createFile tries to create a new file; it is used by the self-test and
// the tests.
func createFile(name string) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}

func socketErr(family, typ int) error {
	fd, err := unix.Socket(family, typ|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	unix.Close(fd)
	return nil
}

// ptraceErr asks for data of a process that is not traced. Without the
// filter the kernel answers ESRCH; the filter answers EPERM first.
func ptraceErr() error {
	_, _, e := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_PEEKDATA, uintptr(os.Getppid()), 0, 0, 0, 0)
	if e == unix.EPERM {
		return e
	}
	return nil
}

// runSelf runs the own binary as a child, as the exec helper does.
func runSelf(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/proc/self/exe", args...)
	cmd.Env = []string{}
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return fmt.Errorf("%w: %s", err, ee.Stderr)
		}
		return err
	}
	if len(out) == 0 {
		return errors.New("no output")
	}
	return nil
}
