// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package sandbox_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/bomcensus/bomcensus/internal/sandbox"
	"github.com/bomcensus/bomcensus/internal/sandbox/sandboxtest"
)

// The Landlock domain cannot be left, so it is applied in a child: the test
// binary started again with landlockChildEnv set. Like a version command,
// the child holds no capabilities and runs as uid 65534 when the test runs
// as root (capabilities such as CAP_SYS_ADMIN let a process in a domain
// read other processes' environment). It tries to reach a sibling of the
// same uid without capabilities.
//
//	landlock  drop all capabilities, set no_new_privs, call RestrictCommand
//	          and execute the binary again as "check": the domain applies
//	          to every thread of the new image, as it does to a version
//	          command
//	none      the same without RestrictCommand (the control)
//	check     try the operations of landlockChecks and print the result
//	sibling   drop all capabilities and execute the binary again as "sleep"
//	abi       print the kernel's Landlock ABI (scripts/sandbox-matrix.sh
//	          reads it outside the containers)
const (
	landlockChildEnv = "BOMCENSUS_SANDBOX_TEST_CHILD"
	envLandlockDir   = "BOMCENSUS_SANDBOX_TEST_DIR"
	envLandlockTCP   = "BOMCENSUS_SANDBOX_TEST_TCP"
	envLandlockUnix  = "BOMCENSUS_SANDBOX_TEST_UNIX"
	envLandlockPeer  = "BOMCENSUS_SANDBOX_TEST_SIBLING"
	envLandlockABI   = "BOMCENSUS_SANDBOX_TEST_APPLIED"
	// envLandlockAs makes the child apply the ruleset of this older ABI.
	envLandlockAs = "BOMCENSUS_SANDBOX_TEST_AS_ABI"
)

func TestMain(m *testing.M) {
	if mode := os.Getenv(landlockChildEnv); mode != "" {
		os.Exit(landlockChild(mode))
	}
	os.Exit(m.Run())
}

// landlockCheck is one operation and the ABI from which RestrictCommand
// must deny it (0: never denied).
type landlockCheck struct {
	name string
	abi  int
}

// Every operation works without the domain (the control run checks that),
// so a denial in the restricted run comes from Landlock.
var landlockChecks = []landlockCheck{
	{"read file", 0},
	{"create file", 1},
	{"write file", 1},
	{"read environ of the sibling", 1}, // ptrace restriction, every ABI
	{"truncate", 3},
	{"tcp connect", 4},
	{"tcp bind", 4},
	{"signal the sibling", 6},
	{"connect abstract unix socket", 6},
}

type landlockChildResult struct {
	Applied int               `json:"applied"`
	Err     string            `json:"err,omitempty"`
	Results map[string]string `json:"results"` // "" when allowed
}

func landlockChild(mode string) int {
	switch mode {
	case "sleep":
		time.Sleep(time.Minute)
		return 0
	case "sibling":
		runtime.LockOSThread()
		if err := dropCapabilities(); err != nil {
			return childFail(err)
		}
		return childFail(unix.Exec("/proc/self/exe", []string{os.Args[0], sleepArg}, childEnv("sleep")))
	case "landlock", "none":
		runtime.LockOSThread()
		if err := dropCapabilities(); err != nil {
			return childFail(err)
		}
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			return childFail(err)
		}
		applied := 0
		if mode == "landlock" {
			var abi int
			var err error
			if as := os.Getenv(envLandlockAs); as != "" {
				n, _ := strconv.Atoi(as)
				abi, err = sandbox.RestrictCommandABI("/", n)
			} else {
				abi, err = sandbox.RestrictCommand("/")
			}
			if err != nil {
				return childFail(err)
			}
			applied = abi
		}
		env := append(childEnv("check"), envLandlockABI+"="+strconv.Itoa(applied))
		return childFail(unix.Exec("/proc/self/exe", os.Args[:1], env))
	case "abi":
		fmt.Println(sandbox.LandlockABI())
		return 0
	case "check":
		applied, _ := strconv.Atoi(os.Getenv(envLandlockABI))
		json.NewEncoder(os.Stdout).Encode(landlockChildResult{Applied: applied, Results: runLandlockChecks()})
		return 0
	}
	return childFail(fmt.Errorf("unknown mode %q", mode))
}

// childEnv is the environment with the child mode replaced.
func childEnv(mode string) []string {
	var env []string
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, landlockChildEnv+"=") {
			env = append(env, e)
		}
	}
	return append(env, landlockChildEnv+"="+mode)
}

// dropCapabilities clears the ambient set and every capability of the
// calling thread, which then executes.
func dropCapabilities() error {
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil && err != unix.EINVAL {
		return err
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	return unix.Capset(&hdr, &data[0])
}

// asCommand makes cmd run as uid 65534 when the test runs as root that can
// switch users. Root without CAP_SETUID runs no version commands; the
// child then stays uid 0, without capabilities.
func asCommand(cmd *exec.Cmd) {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	canSwitch := unix.Capget(&hdr, &data[0]) == nil &&
		data[0].Effective&(1<<unix.CAP_SETUID) != 0 && data[0].Effective&(1<<unix.CAP_SETGID) != 0
	if os.Geteuid() == 0 && canSwitch {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
	}
}

// sleepArg marks the sibling's command line once it has executed again.
const sleepArg = "-sandbox-test-sleep"

func childFail(err error) int {
	json.NewEncoder(os.Stdout).Encode(landlockChildResult{Err: err.Error()})
	return 1
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func runLandlockChecks() map[string]string {
	dir := os.Getenv(envLandlockDir)
	peer, _ := strconv.Atoi(os.Getenv(envLandlockPeer))
	r := map[string]string{}
	_, err := os.ReadFile(filepath.Join(dir, "existing"))
	r["read file"] = errString(err)
	r["create file"] = errString(func() error {
		f, err := os.OpenFile(filepath.Join(dir, fmt.Sprintf("new-%d", os.Getpid())), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			f.Close()
		}
		return err
	}())
	r["write file"] = errString(func() error {
		f, err := os.OpenFile(filepath.Join(dir, "existing"), os.O_WRONLY|os.O_APPEND, 0)
		if err == nil {
			f.Close()
		}
		return err
	}())
	_, err = os.ReadFile(fmt.Sprintf("/proc/%d/environ", peer))
	r["read environ of the sibling"] = errString(err)
	r["truncate"] = errString(unix.Truncate(filepath.Join(dir, "truncate"), 0))
	// Landlock's TCP rights cover IPPROTO_TCP sockets only, and Go
	// listens with MPTCP by default where the kernel has it, so both
	// checks ask for plain TCP.
	r["tcp connect"] = errString(func() error {
		var d net.Dialer
		d.SetMultipathTCP(false)
		c, err := d.Dial("tcp", os.Getenv(envLandlockTCP))
		if err == nil {
			c.Close()
		}
		return err
	}())
	r["tcp bind"] = errString(func() error {
		var lc net.ListenConfig
		lc.SetMultipathTCP(false)
		l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
		if err == nil {
			l.Close()
		}
		return err
	}())
	r["signal the sibling"] = errString(unix.Kill(peer, 0))
	r["connect abstract unix socket"] = errString(func() error {
		c, err := net.Dial("unix", "@"+os.Getenv(envLandlockUnix))
		if err == nil {
			c.Close()
		}
		return err
	}())
	return r
}

func runLandlockChild(t *testing.T, mode string, env []string) landlockChildResult {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), landlockChildEnv+"="+mode)
	cmd.Env = append(cmd.Env, env...)
	asCommand(cmd)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	var r landlockChildResult
	if jerr := json.Unmarshal(out, &r); jerr != nil {
		t.Fatalf("%s child: %v %v\n%s\n%s", mode, err, jerr, out, stderr.String())
	}
	if r.Err != "" || err != nil {
		t.Fatalf("%s child: %v %s\n%s", mode, err, r.Err, stderr.String())
	}
	return r
}

// TestRestrictCommand checks that the Landlock domain of version commands
// denies what the running kernel's ABI can deny, and nothing it cannot.
func TestRestrictCommand(t *testing.T) {
	abi := sandboxtest.LandlockABI(t)
	if _, set := os.LookupEnv(sandboxtest.EnvLandlockABI); abi == 0 && !set {
		t.Skip("Landlock not available")
	}
	t.Logf("RestrictCommand at ABI %d: %s", abi, sandbox.LandlockCommand(abi))

	dir, err := os.MkdirTemp("", "landlock-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	os.Chmod(dir, 0o777)
	for _, name := range []string{"existing", "truncate"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("content"), 0o666); err != nil {
			t.Fatal(err)
		}
		os.Chmod(filepath.Join(dir, name), 0o666)
	}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	abstract := fmt.Sprintf("bomcensus-landlock-test-%d", os.Getpid())
	ul, err := net.Listen("unix", "@"+abstract)
	if err != nil {
		t.Fatal(err)
	}
	defer ul.Close()
	for _, l := range []net.Listener{tcp, ul} {
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
	}

	sibling := exec.Command(os.Args[0])
	sibling.Env = append(os.Environ(), landlockChildEnv+"=sibling")
	asCommand(sibling)
	if err := sibling.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sibling.Process.Kill(); sibling.Wait() })
	// The sibling has executed again, without capabilities, when its
	// command line changed.
	for i := 0; ; i++ {
		if b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", sibling.Process.Pid)); bytes.Contains(b, []byte(sleepArg)) {
			break
		}
		if i == 100 {
			t.Fatal("sibling did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}

	env := []string{envLandlockDir + "=" + dir, envLandlockTCP + "=" + tcp.Addr().String(),
		envLandlockUnix + "=" + abstract, envLandlockPeer + "=" + strconv.Itoa(sibling.Process.Pid)}
	control := runLandlockChild(t, "none", env)
	for _, c := range landlockChecks {
		if e := control.Results[c.name]; e != "" {
			t.Fatalf("control run without Landlock: %s failed: %s", c.name, e)
		}
	}

	// The kernel's own ABI through RestrictCommand, then every older ABI
	// on this kernel: what a kernel of that ABI gets.
	checkLandlock(t, dir, abi, runLandlockChild(t, "landlock", env))
	for older := abi - 1; older >= 1; older-- {
		t.Run(fmt.Sprintf("ABI %d", older), func(t *testing.T) {
			checkLandlock(t, dir, older, runLandlockChild(t, "landlock", append(env, envLandlockAs+"="+strconv.Itoa(older))))
		})
	}
}

func checkLandlock(t *testing.T, dir string, abi int, r landlockChildResult) {
	t.Helper()
	os.WriteFile(filepath.Join(dir, "truncate"), []byte("content"), 0o666)
	defer os.WriteFile(filepath.Join(dir, "truncate"), []byte("content"), 0o666)
	if r.Applied != abi {
		t.Errorf("applied ABI %d, want %d", r.Applied, abi)
	}
	for _, c := range landlockChecks {
		e, ok := r.Results[c.name]
		switch {
		case !ok:
			t.Errorf("%s: not checked", c.name)
		case c.abi > 0 && abi >= c.abi && e == "":
			t.Errorf("%s: allowed at ABI %d, denied from ABI %d", c.name, abi, c.abi)
		case (c.abi == 0 || abi < c.abi) && e != "":
			t.Errorf("%s: denied at ABI %d (%s), not handled below ABI %d", c.name, abi, e, c.abi)
		case e != "":
			t.Logf("ABI %d: %-30s denied: %s", abi, c.name, e)
		default:
			t.Logf("ABI %d: %-30s allowed", abi, c.name)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "existing")); string(b) != "content" {
		t.Errorf("existing file changed: %q", b)
	}
}
