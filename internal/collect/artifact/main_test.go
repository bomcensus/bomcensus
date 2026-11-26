// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package artifact

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/bomcensus/bomcensus/internal/collect"
	"github.com/bomcensus/bomcensus/internal/report"
)

func TestMain(m *testing.M) {
	MaybeRunExecHelper()
	widenTestProcessMargin()
	os.Exit(m.Run())
}

// testProcessMargin replaces defaultExecLimits.NProcMargin in tests that
// do not run as root.
const testProcessMargin = 4096

// widenTestProcessMargin keeps the process limit from failing commands
// for reasons outside the test. Without root the commands run as the test
// user, and RLIMIT_NPROC counts every task of that user: under go test
// ./... the other test binaries start threads between the count and the
// command's start, often more than the production margin of 64, and the Go
// runtime of the helper program then fails to create a thread. As root
// the commands run as nobody, whose count is stable, and the production
// margin is kept. The margin stays within the hard limit, which the
// helper cannot raise.
func widenTestProcessMargin() {
	if os.Geteuid() == 0 {
		return
	}
	margin := uint64(testProcessMargin)
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(rlimitNPROC, &rl); err == nil {
		if used := countTasks("/proc", os.Getuid()); used < rl.Max && rl.Max-used < 2*margin {
			margin = (rl.Max - used) / 2
		}
	}
	defaultExecLimits.NProcMargin = max(margin, defaultExecLimits.NProcMargin)
}

// helperSource is a small program used as a version command.
const helperSource = `package main

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
			name      string
			fam, typ  int
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
`

var (
	helperOnce sync.Once
	helperPath string
	helperErr  error
)

// testHelperBinary builds helperSource once.
func testHelperBinary(t *testing.T) string {
	t.Helper()
	helperOnce.Do(func() {
		// A prebuilt helper lets the tests run where no Go toolchain is
		// installed, for example as root inside a container.
		if p := os.Getenv("BOMCENSUS_TEST_HELPER"); p != "" {
			helperPath = p
			return
		}
		dir, err := os.MkdirTemp("", "artifact-helper-")
		if err != nil {
			helperErr = err
			return
		}
		helperPath, helperErr = goBuild(dir, map[string]string{"main.go": helperSource, "go.mod": "module helper\n\ngo 1.22\n"}, "fakesw")
	})
	if helperErr != nil {
		t.Fatalf("build helper: %v", helperErr)
	}
	return helperPath
}

// goBuild writes files into dir and builds the module there.
func goBuild(dir string, files map[string]string, out string) (string, error) {
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			return "", err
		}
	}
	bin := filepath.Join(dir, out)
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOWORK=off", "GOFLAGS=-mod=mod", "GOPROXY=off")
	if b, err := cmd.CombinedOutput(); err != nil {
		return "", &buildError{out: string(b), err: err}
	}
	return bin, nil
}

type buildError struct {
	out string
	err error
}

func (e *buildError) Error() string { return e.err.Error() + ": " + e.out }

// tinyELF returns a static executable for the current architecture that
// writes msg to stdout and exits 0. tail is appended after the code and is
// not executed. machine overrides e_machine when non-zero.
func tinyELF(t *testing.T, msg, tail string, machine uint16) []byte {
	t.Helper()
	const base = 0x400000
	const hdrs = 64 + 56
	var code []byte
	var em uint16
	switch runtime.GOARCH {
	case "amd64":
		em = 0x3e
		code = []byte{
			0xb8, 1, 0, 0, 0, // mov eax, 1 (write)
			0xbf, 1, 0, 0, 0, // mov edi, 1
			0x48, 0x8d, 0x35, 16, 0, 0, 0, // lea rsi, [rip+16]
			0xba, byte(len(msg)), 0, 0, 0, // mov edx, len
			0x0f, 0x05, // syscall
			0xb8, 60, 0, 0, 0, // mov eax, 60 (exit)
			0x31, 0xff, // xor edi, edi
			0x0f, 0x05, // syscall
		}
	case "arm64":
		em = 0xb7
		for _, ins := range []uint32{
			0xd2800020,                       // mov x0, #1
			0x100000e1,                       // adr x1, +28
			0xd2800002 | uint32(len(msg))<<5, // mov x2, #len
			0xd2800808,                       // mov x8, #64 (write)
			0xd4000001,                       // svc #0
			0xd2800000,                       // mov x0, #0
			0xd2800ba8,                       // mov x8, #93 (exit)
			0xd4000001,                       // svc #0
		} {
			code = binary.LittleEndian.AppendUint32(code, ins)
		}
	default:
		t.Skip("no tiny ELF for " + runtime.GOARCH)
	}
	if machine != 0 {
		em = machine
	}
	body := append(append(code, msg...), tail...)
	total := uint64(hdrs + len(body))

	var b bytes.Buffer
	le := binary.LittleEndian
	b.Write([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	binary.Write(&b, le, uint16(2))         // ET_EXEC
	binary.Write(&b, le, em)                // e_machine
	binary.Write(&b, le, uint32(1))         // e_version
	binary.Write(&b, le, uint64(base+hdrs)) // e_entry
	binary.Write(&b, le, uint64(64))        // e_phoff
	binary.Write(&b, le, uint64(0))         // e_shoff
	binary.Write(&b, le, uint32(0))         // e_flags
	binary.Write(&b, le, uint16(64))        // e_ehsize
	binary.Write(&b, le, uint16(56))        // e_phentsize
	binary.Write(&b, le, uint16(1))         // e_phnum
	binary.Write(&b, le, [3]uint16{})       // e_shentsize, e_shnum, e_shstrndx
	binary.Write(&b, le, uint32(1))         // PT_LOAD
	binary.Write(&b, le, uint32(5))         // PF_R|PF_X
	binary.Write(&b, le, uint64(0))         // p_offset
	binary.Write(&b, le, [2]uint64{base, base})
	binary.Write(&b, le, [2]uint64{total, total})
	binary.Write(&b, le, uint64(0x1000))
	b.Write(body)
	return b.Bytes()
}

// testEnv returns an environment rooted at root with a fresh cache.
func testEnv(root string) *collect.Env {
	env := collect.NewEnv()
	env.Root = root
	env.Policy = report.DefaultPolicy()
	return env
}

// testCollector returns a collector that walks only dir.
func testCollector(env *collect.Env, in Inputs, dir string, dets ...*Detector) *collector {
	in.WalkPaths = []string{dir}
	c := newCollector(env, in)
	c.detectors = dets
	return c
}

// statusField returns a field of /proc/<pid>/status style output.
func statusField(out, key string) string {
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), key+":"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
