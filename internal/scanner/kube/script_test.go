// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package kube

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const testNonce = "0123456789abcdef"

func scriptProbe(body string) []byte { return []byte("#!/bin/sh\n" + body + "\n") }

func scriptParams(dirs []string, probe []byte, request string) sessionParams {
	return sessionParams{
		nonce: testNonce, dirs: dirs, memLimit: "64MiB", maxProcs: 1,
		maxStdout: 16 << 20, tailBytes: 4096,
		probe:   func(string) ([]byte, error) { return probe, nil },
		request: []byte(request),
	}
}

func runLocal(t *testing.T, sh []string, env []string, p sessionParams) sessionResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return runSession(ctx, &localExecutor{shell: sh, env: env}, "", "", "", p)
}

func TestScriptSuccess(t *testing.T) {
	// The padding makes the probe larger than any pipe or stdio buffer, so
	// that a reader consuming more than the announced size would eat the
	// request.
	padding := "# " + strings.Repeat("x", 3<<20)
	probe := scriptProbe(`echo "args=$*"; echo "mem=$GOMEMLIMIT procs=$GOMAXPROCS"; echo probe-stderr >&2; cat` + "\n" + padding)
	request := `{"sections":["processes"],"policy":{}}`
	want := "args=collect\nmem=64MiB procs=1\n" + request

	for name, sh := range testShells(t) {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			res := runLocal(t, sh, nil, scriptParams([]string{filepath.Join(dir, "missing"), dir}, probe, request))
			if !slices.Equal(res.seq, []string{tokStart, tokWant, tokReady, tokPID, tokExit}) {
				t.Fatalf("tokens %v, tail %q, err %v", res.seq, res.tail, res.execErr)
			}
			if res.path != dir+"/"+probeFileName(testNonce) {
				t.Errorf("path %q", res.path)
			}
			if !res.exitSeen || res.exitCode != 0 || res.execErr != nil {
				t.Errorf("exit %v %d err %v", res.exitSeen, res.exitCode, res.execErr)
			}
			if string(res.stdout) != want {
				t.Errorf("stdout %q, want %q", res.stdout, want)
			}
			if !strings.Contains(res.tail, "probe-stderr") {
				t.Errorf("tail %q", res.tail)
			}
			if archFromUname(res.unameArch) == "" {
				t.Errorf("uname arch %q not mapped", res.unameArch)
			}
			if es := dirEntries(t, dir); len(es) != 0 {
				t.Errorf("left behind: %v", es)
			}
		})
	}
}

func TestScriptDDFallback(t *testing.T) {
	path := toolPath(t, "rm", "chmod", "dd", "wc", "cat", "uname")
	padding := "# " + strings.Repeat("y", 300<<10)
	probe := scriptProbe("cat\n" + padding)
	request := `{"policy":{}}`
	shells := testShells(t)
	delete(shells, "busybox") // may resolve head as a built-in applet regardless of PATH
	for name, sh := range shells {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			res := runLocal(t, sh, []string{"PATH=" + path}, scriptParams([]string{dir}, probe, request))
			if res.exitCode != 0 || !res.exitSeen || string(res.stdout) != request {
				t.Fatalf("tokens %v exit %d stdout %q tail %q", res.seq, res.exitCode, res.stdout, res.tail)
			}
			if es := dirEntries(t, dir); len(es) != 0 {
				t.Errorf("left behind: %v", es)
			}
		})
	}
}

func TestScriptNoTool(t *testing.T) {
	shells := testShells(t)
	delete(shells, "busybox")
	cases := []struct {
		tools []string
		want  string
	}{
		{[]string{"rm"}, "chmod"},
		{[]string{"rm", "chmod"}, "head"},
		{[]string{"rm", "chmod", "dd"}, "head"}, // dd without wc
	}
	for name, sh := range shells {
		for _, c := range cases {
			t.Run(name+"/"+strings.Join(c.tools, "+"), func(t *testing.T) {
				dir := t.TempDir()
				res := runLocal(t, sh, []string{"PATH=" + toolPath(t, c.tools...)}, scriptParams([]string{dir}, scriptProbe("exit 0"), "{}"))
				if res.noTool != c.want || res.path != "" {
					t.Fatalf("noTool %q path %q tokens %v", res.noTool, res.path, res.seq)
				}
			})
		}
	}
}

func TestScriptNoWritableDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not apply to root")
	}
	for name, sh := range testShells(t) {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			ro := filepath.Join(base, "ro")
			if err := os.Mkdir(ro, 0o555); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Chmod(ro, 0o755) })
			res := runLocal(t, sh, nil, scriptParams([]string{filepath.Join(base, "missing"), ro}, scriptProbe("exit 0"), "{}"))
			if !res.noDir || res.path != "" || len(res.stdout) != 0 {
				t.Fatalf("noDir %v path %q tokens %v", res.noDir, res.path, res.seq)
			}
			var ee interface{ ExitStatus() int }
			if res.execErr == nil || !errors.As(res.execErr, &ee) || ee.ExitStatus() != 3 {
				t.Errorf("exec error %v", res.execErr)
			}
		})
	}
}

// TestScriptNoexecDir needs a writable noexec mount (often /dev/shm or
// /run/user/<uid>); it is skipped when there is none.
func TestScriptNoexecDir(t *testing.T) {
	dir := noexecDir(t)
	for name, sh := range testShells(t) {
		t.Run(name, func(t *testing.T) {
			res := runLocal(t, sh, nil, scriptParams([]string{dir}, scriptProbe("exit 0"), "{}"))
			if !res.noDir {
				t.Fatalf("noDir false, tokens %v", res.seq)
			}
			if es := dirEntries(t, dir); len(es) != 0 {
				t.Errorf("left behind: %v", es)
			}
		})
	}
}

func noexecDir(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		t.Skip("no /proc/self/mounts")
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || !slices.Contains(strings.Split(f[3], ","), "noexec") || slices.Contains(strings.Split(f[3], ","), "ro") {
			continue
		}
		d, err := os.MkdirTemp(f[1], "kube-noexec-")
		if err != nil {
			continue
		}
		t.Cleanup(func() { os.RemoveAll(d) })
		return d
	}
	t.Skip("no writable noexec mount")
	return ""
}

func TestScriptProbeFailure(t *testing.T) {
	for name, sh := range testShells(t) {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			res := runLocal(t, sh, nil, scriptParams([]string{dir}, scriptProbe("echo broken >&2; exit 7"), "{}"))
			if !res.exitSeen || res.exitCode != 7 || !strings.Contains(res.tail, "broken") {
				t.Fatalf("exit %v %d tail %q", res.exitSeen, res.exitCode, res.tail)
			}
			if es := dirEntries(t, dir); len(es) != 0 {
				t.Errorf("left behind: %v", es)
			}
		})
	}
}

// startScript runs the script with raw pipes for tests that drive the
// protocol by hand.
func startScript(t *testing.T, sh []string, dir string) (*exec.Cmd, io.WriteCloser, *bufio.Scanner) {
	t.Helper()
	args := append(slices.Clone(sh[1:]), "-c", collectScript, "bomcensus", testNonce, "64MiB", "1", dir)
	cmd := exec.Command(sh[0], args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	return cmd, stdin, bufio.NewScanner(stderr)
}

func nextToken(t *testing.T, sc *bufio.Scanner) (string, string) {
	t.Helper()
	prefix := "@@BOMCENSUS-" + testNonce + " "
	for sc.Scan() {
		if i := strings.Index(sc.Text(), prefix); i >= 0 {
			name, arg, _ := strings.Cut(sc.Text()[i+len(prefix):], " ")
			return name, arg
		}
	}
	return "", ""
}

func TestScriptShortTransfer(t *testing.T) {
	for name, sh := range testShells(t) {
		for _, hdr := range []string{"10\nabc", "abc\n", ""} {
			t.Run(name+"/"+strconv.Quote(hdr), func(t *testing.T) {
				dir := t.TempDir()
				cmd, stdin, sc := startScript(t, sh, dir)
				for {
					tok, _ := nextToken(t, sc)
					if tok == tokWant {
						break
					}
					if tok == "" {
						t.Fatal("no WANT")
					}
				}
				io.WriteString(stdin, hdr)
				stdin.Close()
				if tok, _ := nextToken(t, sc); tok != tokShort {
					t.Fatalf("token %q, want SHORT", tok)
				}
				cmd.Wait()
				if es := dirEntries(t, dir); len(es) != 0 {
					t.Errorf("left behind: %v", es)
				}
			})
		}
	}
}

// TestScriptCleanupOnTerm terminates the shell while the probe runs: the
// trap must kill the probe and remove the file.
func TestScriptCleanupOnTerm(t *testing.T) {
	for name, sh := range testShells(t) {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			cmd, stdin, sc := startScript(t, sh, dir)
			var pid int
			for pid == 0 {
				tok, arg := nextToken(t, sc)
				switch tok {
				case tokWant:
					probe := scriptProbe("exec sleep 30")
					io.WriteString(stdin, strconv.Itoa(len(probe))+"\n")
					stdin.Write(probe)
				case tokPID:
					pid, _ = strconv.Atoi(arg)
				case "":
					t.Fatal("stream ended before PID")
				}
			}
			if !waitFor(5*time.Second, func() bool {
				exe, _ := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
				return strings.HasSuffix(exe, "/sleep")
			}) {
				t.Fatal("probe did not start")
			}
			if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			cmd.Wait()
			if !waitFor(5*time.Second, func() bool { return !alive(pid) }) {
				t.Errorf("probe %d still running", pid)
			}
			if es := dirEntries(t, dir); len(es) != 0 {
				t.Errorf("left behind: %v", es)
			}
		})
	}
}

func alive(pid int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	// state is the field after the parenthesized command name
	i := bytes.LastIndexByte(b, ')')
	return i < 0 || i+2 >= len(b) || b[i+2] != 'Z'
}

func TestScriptCleanupScript(t *testing.T) {
	for name, sh := range testShells(t) {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			sleepBin, err := exec.LookPath("sleep")
			if err != nil {
				t.Skip("no sleep")
			}
			b, err := os.ReadFile(sleepBin)
			if err != nil {
				t.Skip(err)
			}
			f := filepath.Join(dir, probeFileName(testNonce))
			if err := os.WriteFile(f, b, 0o700); err != nil {
				t.Fatal(err)
			}
			p := exec.Command(f, "30")
			if err := p.Start(); err != nil {
				t.Fatal(err)
			}
			defer p.Process.Kill()
			other := exec.Command(sleepBin, "30")
			if err := other.Start(); err != nil {
				t.Fatal(err)
			}
			defer other.Process.Kill()

			// A pid running something else must survive.
			args := append(slices.Clone(sh[1:]), "-c", cleanupScript, "bomcensus", strconv.Itoa(other.Process.Pid), f)
			if out, err := exec.Command(sh[0], args...).CombinedOutput(); err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			if !alive(other.Process.Pid) {
				t.Error("unrelated process was killed")
			}
			if _, err := os.Stat(f); !os.IsNotExist(err) {
				t.Error("file not removed")
			}
			args = append(slices.Clone(sh[1:]), "-c", cleanupScript, "bomcensus", strconv.Itoa(p.Process.Pid), f)
			if out, err := exec.Command(sh[0], args...).CombinedOutput(); err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			done := make(chan error, 1)
			go func() { done <- p.Wait() }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("probe not killed")
			}
		})
	}
}

func TestStatusWriter(t *testing.T) {
	var got []token
	w := newStatusWriter("n1", 32, func(tk token) { got = append(got, tk) })
	w.Write([]byte("noise\n@@BOMCENSUS-n1 START x86_64\npartial @@BOMCENSUS-n1 WANT /tmp/a b\n@@BOMCENSUS-other EXIT 0\n"))
	w.Write([]byte("@@BOMCENSUS-n1 EX"))
	w.Write([]byte("IT 3"))
	tail := w.finish()
	want := []token{{tokStart, "x86_64"}, {tokWant, "/tmp/a b"}, {tokExit, "3"}}
	if !slices.Equal(got, want) {
		t.Errorf("tokens %v, want %v", got, want)
	}
	if strings.Contains(tail, "@@BOMCENSUS-n1") || !strings.Contains(tail, "EXIT 0") || len(tail) > 32 {
		t.Errorf("tail %q", tail)
	}
}
