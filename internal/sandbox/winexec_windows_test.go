// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Modes of the test binary run as a command.
const (
	modeEcho  = "__sbx_echo"
	modeSleep = "__sbx_sleep"
	modeSpin  = "__sbx_spin"
	modeFlood = "__sbx_flood"
)

func TestMain(m *testing.M) {
	MaybeRunCheck()
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case modeEcho:
			for _, a := range os.Args[2:] {
				fmt.Println(a)
			}
			fmt.Fprintln(os.Stderr, "to stderr")
			os.Exit(3)
		case modeSleep:
			time.Sleep(time.Hour)
			os.Exit(0)
		case modeSpin:
			for {
			}
		case "__sbx_user32":
			u := windows.NewLazySystemDLL("user32.dll")
			if err := u.Load(); err != nil {
				fmt.Println("user32:", err)
				os.Exit(1)
			}
			fmt.Println("user32 loaded")
			os.Exit(0)
		case modeFlood:
			b := bytes.Repeat([]byte("x"), 1<<20)
			os.Stdout.Write(b)
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

// aclDir creates a directory with a protected DACL given in SDDL (the
// caller always has full access).
func aclDir(t *testing.T, aces string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "d")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	me, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + me + ")" + aces)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	return dir
}

// Read and execute for everyone and for AppContainers (LPAC included).
const readExecACEs = "(A;OICI;0x1200a9;;;WD)(A;OICI;0x1200a9;;;AC)(A;OICI;0x1200a9;;;S-1-15-2-2)"

// fixture copies the test binary into a directory commands can read.
func fixture(t *testing.T) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(aclDir(t, readExecACEs), "target.exe")
	in, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.Create(exe)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	return exe
}

func run(t *testing.T, c Command) *Result {
	t.Helper()
	res, err := Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestRunOutputAndExitCode(t *testing.T) {
	exe := fixture(t)
	res := run(t, Command{Path: exe, Args: []string{modeEcho, "a b", `q"uote`, `back\`}})
	if got, want := string(res.Stdout), "a b\nq\"uote\nback\\\n"; got != want {
		t.Errorf("stdout %q, want %q", got, want)
	}
	if string(res.Stderr) != "to stderr\n" || res.ExitCode != 3 || res.TimedOut || res.Truncated {
		t.Errorf("result %+v", res)
	}
	if res.Container == "" || res.FileID == "" {
		t.Errorf("container %q, file id %q", res.Container, res.FileID)
	}
	t.Logf("container %s", res.Container)
}

func TestRunTimeout(t *testing.T) {
	exe := fixture(t)
	start := time.Now()
	res := run(t, Command{Path: exe, Args: []string{modeSleep}, Timeout: time.Second})
	if !res.TimedOut || time.Since(start) > 10*time.Second {
		t.Errorf("timed out %v after %v", res.TimedOut, time.Since(start))
	}
}

func TestRunCPULimit(t *testing.T) {
	exe := fixture(t)
	start := time.Now()
	// The job checks the user time limit now and then, not at once.
	res := run(t, Command{Path: exe, Args: []string{modeSpin}, CPUTime: time.Second, Timeout: time.Minute})
	if res.TimedOut || res.ExitCode == 0 {
		t.Errorf("result %+v after %v", res, time.Since(start))
	}
}

func TestRunOutputLimit(t *testing.T) {
	exe := fixture(t)
	res := run(t, Command{Path: exe, Args: []string{modeFlood}, OutputLimit: 1000})
	if len(res.Stdout) != 1000 || !res.Truncated || res.ExitCode != 0 {
		t.Errorf("stdout %d bytes, result %+v", len(res.Stdout), res)
	}
}

func TestRunRefuses(t *testing.T) {
	sys32, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	win, _ := windows.GetSystemWindowsDirectory()
	script := filepath.Join(t.TempDir(), "x.cmd")
	if err := os.WriteFile(script, []byte("@echo hi\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"script": script,
		"dll":    filepath.Join(sys32, "kernel32.dll"),
		"gui":    filepath.Join(sys32, "notepad.exe"),
	}
	if runtime.GOARCH == "amd64" {
		cases["x86"] = filepath.Join(win, "SysWOW64", "cmd.exe")
	}
	for name, p := range cases {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if _, err := Run(context.Background(), Command{Path: p}); !errors.Is(err, ErrNotNativePE) {
			t.Errorf("%s: %v, want ErrNotNativePE", name, err)
		}
	}
	if _, err := Run(context.Background(), Command{Path: "cmd.exe"}); err == nil {
		t.Error("relative path accepted")
	}
}

// A file open for writing is not run, and the file cannot be written,
// renamed or deleted while it runs.
func TestRunLocksFile(t *testing.T) {
	exe := fixture(t)
	w, err := os.OpenFile(exe, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), Command{Path: exe, Args: []string{modeEcho}}); !errors.Is(err, ErrFileBusy) {
		t.Errorf("open for writing: %v, want ErrFileBusy", err)
	}
	w.Close()

	done := make(chan *Result)
	go func() {
		res, _ := Run(context.Background(), Command{Path: exe, Args: []string{modeSleep}, Timeout: 3 * time.Second})
		done <- res
	}()
	time.Sleep(time.Second)
	if f, err := os.OpenFile(exe, os.O_WRONLY, 0); err == nil {
		f.Close()
		t.Error("opened for writing while running")
	}
	if err := os.Rename(exe, exe+".moved"); err == nil {
		t.Error("renamed while running")
	}
	if res := <-done; res == nil || !res.TimedOut {
		t.Errorf("result %+v", res)
	}
}

// testWindow creates a hidden top-level window of a new class on a locked
// thread and returns the class, or "" when there is no desktop for it.
func testWindow(t *testing.T) string {
	t.Helper()
	class := fmt.Sprintf("bomcensus-sbx-test-%d", time.Now().UnixNano())
	ready := make(chan string)
	quit := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		user32 := windows.NewLazySystemDLL("user32.dll")
		cls, _ := windows.UTF16PtrFromString(class)
		type wndClassEx struct {
			Size, Style                        uint32
			WndProc                            uintptr
			ClsExtra, WndExtra                 int32
			Instance, Icon, Cursor, Background windows.Handle
			MenuName, ClassName                *uint16
			IconSm                             windows.Handle
		}
		wc := wndClassEx{WndProc: user32.NewProc("DefWindowProcW").Addr(), ClassName: cls}
		wc.Size = uint32(unsafe.Sizeof(wc))
		if r, _, _ := user32.NewProc("RegisterClassExW").Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
			ready <- ""
			return
		}
		hwnd, _, _ := user32.NewProc("CreateWindowExW").Call(0, uintptr(unsafe.Pointer(cls)), 0, 0, 0, 0, 10, 10, 0, 0, 0, 0)
		if hwnd == 0 {
			ready <- ""
			return
		}
		ready <- class
		<-quit
		user32.NewProc("DestroyWindow").Call(hwnd)
	}()
	t.Cleanup(func() { close(quit) })
	return <-ready
}

// targets are the CheckTargets of the tests: a sibling process, a window,
// and directories that grant writing to everyone or to AppContainers.
func targets(t *testing.T, exe string) CheckTargets {
	t.Helper()
	sib := exec.Command(exe, modeSleep)
	if err := sib.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sib.Process.Kill(); sib.Wait() })
	tg := CheckTargets{
		PIDs:        []int{sib.Process.Pid},
		WriteDirs:   []string{aclDir(t, "(A;OICI;0x1301bf;;;WD)"), aclDir(t, "(A;OICI;0x1301bf;;;AC)(A;OICI;0x1301bf;;;S-1-15-2-2)")},
		WindowClass: testWindow(t),
		MemoryMB:    1024,
	}
	if tg.WindowClass == "" {
		t.Log("no window: window_find is not checked")
	}
	return tg
}

func TestCheckCommand(t *testing.T) {
	for _, tc := range []struct {
		name  string
		order []bool
		want  string
	}{{"lpac", []bool{true}, "lpac"}, {"appcontainer", []bool{false}, "appcontainer"}} {
		t.Run(tc.name, func(t *testing.T) {
			old := containerOrder
			containerOrder = tc.order
			defer func() { containerOrder = old }()
			checkCommandTest(t, tc.want)
		})
	}
}

func checkCommandTest(t *testing.T, container string) {
	exe := fixture(t)
	checks, err := CheckCommand(context.Background(), exe, 512, targets(t, exe))
	for _, c := range checks {
		t.Logf("%-40s %-5v %s", c.Name, c.OK, c.Detail)
		if !c.OK {
			t.Errorf("%s: %s", c.Name, c.Detail)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range checks {
		if c.Name == "container" && c.Detail != container {
			t.Errorf("container %s, want %s", c.Detail, container)
		}
	}
	for _, want := range []string{"process_create", "com_wmi_connect", "net_tcp_loopback", "named_pipe", "inherited_handle", "environment"} {
		found := false
		for _, c := range checks {
			found = found || c.Name == want
		}
		if !found {
			t.Errorf("no %s check", want)
		}
	}
}

// The control: the check program run without the sandbox must succeed in
// the attempts, or the checks prove nothing.
func TestCheckProgramControl(t *testing.T) {
	exe := fixture(t)
	tg := targets(t, exe)
	tg.MemoryMB = 0
	checks, err := checkCommand(exe, tg, func(args []string) (*Result, error) {
		cmd := exec.Command(exe, args...)
		cmd.Env = append(os.Environ(), checkEnv)
		var out, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &stderr
		err := cmd.Run()
		code := uint32(0)
		if cmd.ProcessState != nil {
			code = uint32(cmd.ProcessState.ExitCode())
		}
		return &Result{Stdout: out.Bytes(), Stderr: stderr.Bytes(), ExitCode: code}, err
	})
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{}
	for _, c := range checks {
		t.Logf("%-40s %-5v %s", c.Name, c.OK, c.Detail)
		allowed[c.Name] = !c.OK
	}
	must := []string{"process_create", "com_wmi_connect", "com_task_scheduler_connect", "net_tcp_loopback", "input_desktop_open",
		"net_tcp_loopback_accepted", "net_udp_loopback_received", "named_pipe", "reg_hkcu_write",
		fmt.Sprintf("open_process_%d", tg.PIDs[0]), "file_write " + tg.WriteDirs[0], "file_read " + os.TempDir()}
	if tg.WindowClass != "" {
		must = append(must, "window_find")
	}
	for _, name := range must {
		if strings.HasPrefix(name, "file_read ") {
			// The secret's name is random: any file_read of the temp
			// directory.
			ok := false
			for n, a := range allowed {
				ok = ok || (strings.HasPrefix(n, name) && a)
			}
			if !ok {
				t.Errorf("control: no allowed %s*", name)
			}
			continue
		}
		if !allowed[name] {
			t.Errorf("control: %s was not allowed without the sandbox", name)
		}
	}
}

// The optional mitigations do not keep a program that needs neither user32
// nor dynamic code from running.
func TestRunOptionalMitigations(t *testing.T) {
	exe := fixture(t)
	res := run(t, Command{Path: exe, Args: []string{modeEcho, "x"}, Win32kLockdown: true, ProhibitDynamicCode: true})
	if string(res.Stdout) != "x\n" || res.ExitCode != 3 {
		t.Errorf("result %+v", res)
	}
}

// Runtimes named in BOMCENSUS_TEST_RUNTIMES ("path|arg|arg;path|arg") are
// run as version commands and the test logs how each fared, with and
// without the optional mitigations: which runtimes the sandbox can run is
// measured, not required (scripts/windows-sandbox-matrix.ps1 sets it).
func TestRunRuntimes(t *testing.T) {
	spec := os.Getenv("BOMCENSUS_TEST_RUNTIMES")
	if spec == "" {
		t.Skip("BOMCENSUS_TEST_RUNTIMES is not set")
	}
	for _, entry := range strings.Split(spec, ";") {
		f := strings.Split(entry, "|")
		if f[0] == "" {
			continue
		}
		for _, m := range []struct {
			name          string
			win32k, noJIT bool
		}{{"default", false, false}, {"win32k", true, false}, {"no-dynamic-code", false, true}} {
			res, err := Run(context.Background(), Command{Path: f[0], Args: f[1:], Win32kLockdown: m.win32k, ProhibitDynamicCode: m.noJIT})
			if err != nil {
				t.Logf("%s %s: %v", f[0], m.name, err)
				continue
			}
			out := strings.TrimSpace(string(res.Stdout) + " " + string(res.Stderr))
			if len(out) > 120 {
				out = out[:120]
			}
			t.Logf("%s %s: container %s, window station %s, exit 0x%x: %s", f[0], m.name, res.Container, res.WindowStation, res.ExitCode, out)
		}
	}
}
