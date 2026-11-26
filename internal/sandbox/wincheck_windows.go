// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package sandbox

// The sandbox check: a binary run as a version command tries what the
// sandbox must deny and prints one line per attempt. Every attempt is
// harmless when it succeeds: what it creates it removes, handles it gets
// it closes without using them, and the COM checks only connect. It is
// part of bomcensus-probe self-test and of the tests.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// CheckArg is the hidden first argument of the check program. A binary
// that may be checked calls MaybeRunCheck first in main.
const CheckArg = "__bomcensus_sandbox_check"

// Check is the outcome of one attempt.
type Check struct {
	Name string `json:"name"`
	// OK is true when the attempt was denied, or for the other checks
	// when the command saw what the sandbox promises.
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// MaybeRunCheck runs the check program and exits when os.Args asks for it.
func MaybeRunCheck() {
	if len(os.Args) > 1 && os.Args[1] == CheckArg {
		os.Exit(runCheckProgram(os.Args[2:]))
	}
}

// CheckTargets are more things for the check program to try.
type CheckTargets struct {
	// PIDs of processes outside the sandbox, besides the caller.
	PIDs []int
	// WriteDirs are directories where no file may be created.
	WriteDirs []string
	// ReadFiles must not be readable.
	ReadFiles []string
	// WindowClass is the class of a window outside the sandbox.
	WindowClass string
	// MemoryMB is committed by the program; the job must refuse it.
	MemoryMB int
}

// The environment the check program gets.
const checkEnv = "BOMCENSUS_SANDBOX_CHECK=1"

// CheckCommand runs exe (a binary that calls MaybeRunCheck) as a version
// command with a memory limit of memoryMB and reports each attempt. It
// sets up a TCP and a UDP listener on loopback, a named pipe, an
// inheritable handle, a file only the caller may read and write targets,
// and removes them afterwards.
func CheckCommand(ctx context.Context, exe string, memoryMB int, extra CheckTargets) ([]Check, error) {
	return checkCommand(exe, extra, func(args []string) (*Result, error) {
		return Run(ctx, Command{Path: exe, Args: args, Env: []string{checkEnv}, MemoryMB: memoryMB, Timeout: 60 * time.Second})
	})
}

// checkCommand sets up the targets and runs the check program with run.
func checkCommand(exe string, extra CheckTargets, run func(args []string) (*Result, error)) ([]Check, error) {
	var nb [6]byte
	if _, err := rand.Read(nb[:]); err != nil {
		return nil, err
	}
	tag := "bomcensus-sbx-" + hex.EncodeToString(nb[:])
	args := []string{CheckArg, "tag=" + tag, "pid=" + strconv.Itoa(os.Getpid())}
	for _, p := range extra.PIDs {
		args = append(args, "pid="+strconv.Itoa(p))
	}

	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer tcp.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			c.Close()
			select {
			case accepted <- struct{}{}:
			default:
			}
		}
	}()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer udp.Close()
	received := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 64)
		if _, _, err := udp.ReadFrom(buf); err == nil {
			received <- struct{}{}
		}
	}()
	args = append(args, "tcp="+tcp.Addr().String(), "udp="+udp.LocalAddr().String())

	pipeName := `\\.\pipe\` + tag
	pn, err := windows.UTF16PtrFromString(pipeName)
	if err != nil {
		return nil, err
	}
	pipe, err := windows.CreateNamedPipe(pn, windows.PIPE_ACCESS_DUPLEX, windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT,
		windows.PIPE_UNLIMITED_INSTANCES, 512, 512, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("named pipe: %w", err)
	}
	defer windows.CloseHandle(pipe)
	args = append(args, "pipe="+pipeName)

	// A handle that is inheritable while the command starts: the handle
	// list must keep it out.
	marker := filepath.Join(os.TempDir(), tag+".handle")
	mf, err := os.Create(marker)
	if err != nil {
		return nil, err
	}
	defer os.Remove(marker)
	defer mf.Close()
	if err := windows.SetHandleInformation(windows.Handle(mf.Fd()), windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
		return nil, err
	}
	// Used in a run of its own: with strict handle checks, using an
	// invalid handle terminates the command.
	handleArgs := []string{CheckArg, "tag=" + tag, fmt.Sprintf("handle=%d", mf.Fd())}

	// A file the caller can read and the command must not.
	secret := filepath.Join(os.TempDir(), tag+".secret")
	if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
		return nil, err
	}
	defer os.Remove(secret)
	for _, f := range append([]string{secret}, extra.ReadFiles...) {
		args = append(args, "read="+f)
	}
	dirs := []string{os.TempDir(), filepath.Dir(exe)}
	if pd := os.Getenv("ProgramData"); pd != "" {
		dirs = append(dirs, pd)
	}
	if pub := os.Getenv("PUBLIC"); pub != "" {
		dirs = append(dirs, pub)
	}
	for _, d := range append(dirs, extra.WriteDirs...) {
		args = append(args, "write="+d)
	}
	if extra.WindowClass != "" {
		args = append(args, "window="+extra.WindowClass)
	}
	if extra.MemoryMB > 0 {
		args = append(args, "memory="+strconv.Itoa(extra.MemoryMB))
	}

	res, err := run(args)
	if err != nil {
		return nil, err
	}
	checks := parseChecks(string(res.Stdout))
	if len(checks) == 0 || res.ExitCode != 0 || res.TimedOut {
		return checks, fmt.Errorf("check program: exit 0x%x, timed out %v, stderr %q", res.ExitCode, res.TimedOut,
			strings.TrimSpace(string(res.Stderr)))
	}
	if res, err := run(handleArgs); err == nil && (res.ExitCode == statusInvalidHandle ||
		bytes.HasPrefix(res.Stderr, []byte("Exception 0xc0000008"))) {
		// A Go program reports the exception and exits 2.
		checks = append(checks, Check{Name: "inherited_handle", OK: true,
			Detail: "the handle is not inherited: strict handle checks terminated the command"})
	} else if err != nil {
		checks = append(checks, Check{Name: "inherited_handle", OK: false, Detail: err.Error()})
	} else if hc := parseChecks(string(res.Stdout)); len(hc) == 1 && hc[0].Name == "inherited_handle" {
		checks = append(checks, hc[0])
	} else {
		checks = append(checks, Check{Name: "inherited_handle", OK: false,
			Detail: fmt.Sprintf("exit 0x%x, stdout %q, stderr %.200q", res.ExitCode, res.Stdout, res.Stderr)})
	}
	checks = append(checks, Check{Name: "container", OK: true, Detail: res.Container},
		Check{Name: "window_station", OK: true, Detail: res.WindowStation})
	// What the listeners saw.
	select {
	case <-accepted:
		checks = append(checks, Check{Name: "net_tcp_loopback_accepted", OK: false, Detail: "the listener accepted a connection"})
	default:
		checks = append(checks, Check{Name: "net_tcp_loopback_accepted", OK: true, Detail: "no connection"})
	}
	select {
	case <-received:
		checks = append(checks, Check{Name: "net_udp_loopback_received", OK: false, Detail: "the listener got a datagram"})
	case <-time.After(200 * time.Millisecond):
		checks = append(checks, Check{Name: "net_udp_loopback_received", OK: true, Detail: "nothing received"})
	}
	return checks, nil
}

// statusInvalidHandle is the exception that strict handle checks raise.
const statusInvalidHandle = 0xC0000008

// parseChecks reads the "name ok|FAIL detail" lines of the check program.
func parseChecks(out string) []Check {
	var checks []Check
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		f := strings.SplitN(sc.Text(), "\t", 3)
		if len(f) < 2 {
			continue
		}
		c := Check{Name: f[0], OK: f[1] == "ok"}
		if len(f) == 3 {
			c.Detail = f[2]
		}
		checks = append(checks, c)
	}
	return checks
}

// runCheckProgram is the check program.
func runCheckProgram(args []string) int {
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	report := func(name string, ok bool, detail string) {
		fmt.Fprintf(out, "%s\t%s\t%s\n", name, map[bool]string{true: "ok", false: "FAIL"}[ok], strings.ReplaceAll(detail, "\n", " "))
	}
	// denied reports an attempt: ok when err is not nil.
	denied := func(name string, err error, what string) {
		if err != nil {
			report(name, true, "denied: "+err.Error())
		} else {
			report(name, false, what)
		}
	}
	var tag string
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, "tag="); ok {
			tag = v
		}
	}
	if len(args) == 2 && strings.HasPrefix(args[1], "handle=") {
		h, _ := strconv.ParseUint(strings.TrimPrefix(args[1], "handle="), 10, 64)
		out.Flush()
		denied("inherited_handle", tryHandle(windows.Handle(h), tag), "the handle of the caller's file is open")
		return 0
	}

	tokenChecks(report)
	envCheck(report)

	sys32, _ := windows.GetSystemDirectory()
	denied("process_create", tryCreateProcess(filepath.Join(sys32, "cmd.exe")), "cmd.exe was started")
	denied("com_wmi_connect", tryWMI(), "connected to WMI root\\cimv2")
	denied("com_task_scheduler_connect", tryTaskScheduler(), "connected to the task scheduler")
	denied("winsta0_open", tryOpenWinSta0(), "opened WinSta0")
	denied("input_desktop_open", tryOpenInputDesktop(), "opened the input desktop")
	denied("reg_hkcu_write", tryRegistryWrite(registry.CURRENT_USER, `Software\`+tag), "created a key in HKCU")
	denied("reg_hklm_write", tryRegistryWrite(registry.LOCAL_MACHINE, `Software\`+tag), "created a key in HKLM")

	for _, a := range args {
		k, v, _ := strings.Cut(a, "=")
		switch k {
		case "pid":
			pid, _ := strconv.Atoi(v)
			denied("open_process_"+v, tryOpenProcess(pid), "opened the process for reading memory or terminating")
		case "tcp":
			denied("net_tcp_loopback", tryTCP(v), "connected to "+v)
		case "udp":
			// A send may report no error and still be dropped: the
			// caller's listener decides (net_udp_loopback_received).
			err := tryUDP(v)
			report("net_udp_loopback_send", true, fmt.Sprintf("send to %s: %v", v, err))
		case "pipe":
			denied("named_pipe", tryPipe(v), "opened "+v)
		case "read":
			denied("file_read "+v, tryRead(v), "read "+v)
		case "write":
			denied("file_write "+v, tryWrite(v, tag), "created a file in "+v)
		case "window":
			denied("window_find", tryFindWindow(v), "found the caller's window")
		case "memory":
			mb, _ := strconv.Atoi(v)
			denied("memory_commit", tryCommit(mb), fmt.Sprintf("committed %d MB", mb))
		}
	}
	return 0
}

func tokenChecks(report func(string, bool, string)) {
	tok := windows.GetCurrentProcessToken()
	var ac uint32
	var n uint32
	if err := windows.GetTokenInformation(tok, tokenIsAppContainer, (*byte)(unsafe.Pointer(&ac)), 4, &n); err != nil {
		report("token_appcontainer", false, err.Error())
	} else {
		report("token_appcontainer", ac != 0, fmt.Sprintf("TokenIsAppContainer=%d", ac))
	}
	var il uint32
	if b, err := tokenInfo(tok, windows.TokenIntegrityLevel); err != nil {
		report("token_integrity", false, err.Error())
	} else {
		label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&b[0]))
		sa := label.Label.Sid.SubAuthority(uint32(label.Label.Sid.SubAuthorityCount()) - 1)
		il = sa
		report("token_integrity", il <= securityMandatoryLowRID, fmt.Sprintf("0x%x", il))
	}
	if b, err := tokenInfo(tok, windows.TokenPrivileges); err != nil {
		report("token_privileges", false, err.Error())
	} else {
		p := (*windows.Tokenprivileges)(unsafe.Pointer(&b[0]))
		var names []string
		only := true
		for _, l := range p.AllPrivileges() {
			names = append(names, privilegeName(l.Luid))
			only = only && l.Luid.HighPart == 0 && l.Luid.LowPart == seChangeNotifyPrivilege
		}
		sort.Strings(names)
		report("token_privileges", only && len(names) == 1, strings.Join(names, ","))
	}
	if b, err := tokenInfo(tok, windows.TokenRestrictedSids); err != nil {
		report("token_restricted", false, err.Error())
	} else {
		g := (*windows.Tokengroups)(unsafe.Pointer(&b[0]))
		var sids []string
		for _, s := range g.AllGroups() {
			sids = append(sids, s.Sid.String())
		}
		report("token_restricted", len(sids) > 0, strings.Join(sids, ","))
	}
}

func tokenInfo(tok windows.Token, class uint32) ([]byte, error) {
	n := uint32(256)
	for {
		b := make([]byte, n)
		err := windows.GetTokenInformation(tok, class, &b[0], n, &n)
		if err == nil {
			return b, nil
		}
		if err != windows.ERROR_INSUFFICIENT_BUFFER {
			return nil, err
		}
	}
}

// seChangeNotifyPrivilege is SE_CHANGE_NOTIFY_PRIVILEGE, the LUID of
// SeChangeNotifyPrivilege (the sandbox cannot look names up).
const seChangeNotifyPrivilege = 23

func privilegeName(l windows.LUID) string {
	n := uint32(64)
	buf := make([]uint16, n)
	if err := lookupPrivilegeName(&l, &buf[0], &n); err != nil {
		return fmt.Sprintf("luid-%d", l.LowPart)
	}
	return windows.UTF16ToString(buf[:n])
}

func envCheck(report func(string, bool, string)) {
	var names []string
	for _, e := range os.Environ() {
		k, _, _ := strings.Cut(e, "=")
		if k != "" {
			names = append(names, strings.ToUpper(k))
		}
	}
	sort.Strings(names)
	// LOCALAPPDATA, TEMP and TMP are the AppContainer's folder.
	want := []string{"BOMCENSUS_SANDBOX_CHECK", "LOCALAPPDATA", "SYSTEMROOT", "TEMP", "TMP"}
	report("environment", strings.Join(names, ",") == strings.Join(want, ","), strings.Join(names, ","))
	report("temp_dir", strings.Contains(strings.ToLower(os.Getenv("TEMP")), `\packages\`), os.Getenv("TEMP"))
}

func tryCreateProcess(exe string) error {
	app, _ := windows.UTF16PtrFromString(exe)
	cmd, _ := windows.UTF16PtrFromString(`"` + exe + `" /c exit 0`)
	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	if err := windows.CreateProcess(app, cmd, nil, nil, false, windows.CREATE_NO_WINDOW, nil, nil, &si, &pi); err != nil {
		return err
	}
	windows.WaitForSingleObject(pi.Process, 5000)
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	return nil
}

func tryOpenProcess(pid int) error {
	h, err := windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_TERMINATE|windows.PROCESS_DUP_HANDLE, false, uint32(pid))
	if err != nil {
		return err
	}
	windows.CloseHandle(h)
	return nil
}

func tryTCP(addr string) error {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return err
	}
	return c.Close()
}

func tryUDP(addr string) error {
	c, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write([]byte("x"))
	return err
}

func tryPipe(name string) error {
	p, _ := windows.UTF16PtrFromString(name)
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return err
	}
	return windows.CloseHandle(h)
}

// tryHandle reports an error unless h is the caller's marker file.
func tryHandle(h windows.Handle, tag string) error {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), 0)
	if err != nil {
		return err
	}
	if p := windows.UTF16ToString(buf[:n]); !strings.Contains(p, tag) {
		return fmt.Errorf("handle %d is %s, not the caller's file", h, p)
	}
	return nil
}

func tryRead(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	_ = b
	return nil
}

func tryWrite(dir, tag string) error {
	p := filepath.Join(dir, tag+".written")
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	f.Close()
	os.Remove(p)
	return nil
}

func tryRegistryWrite(root registry.Key, path string) error {
	k, _, err := registry.CreateKey(root, path, registry.WRITE)
	if err != nil {
		return err
	}
	k.Close()
	registry.DeleteKey(root, path)
	return nil
}

func tryCommit(mb int) error {
	p, err := windows.VirtualAlloc(0, uintptr(mb)<<20, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return err
	}
	return windows.VirtualFree(p, 0, windows.MEM_RELEASE)
}
