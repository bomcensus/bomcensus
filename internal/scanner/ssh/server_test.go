// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// testServer is an in-process SSH server that runs exec requests with the
// local /bin/sh inside a sandbox directory, the way sshd runs them with the
// login shell. It supports exec, signal and direct-tcpip, which is all the
// client uses.
type testServer struct {
	t       *testing.T
	ln      net.Listener
	hostKey gossh.Signer
	sandbox string
	home    string
	xdg     string
	tmp     string
	env     []string
	noise   bool // print login-script noise before each command

	mu         sync.Mutex
	commands   []string
	stdinBytes atomic.Int64
	conns      []net.Conn
	procs      map[int]*os.Process
	wg         sync.WaitGroup
	closeOnce  sync.Once
}

type serverOptions struct {
	password   string
	authorized gossh.PublicKey
	env        map[string]string
	noise      bool
}

const chmodShim = `#!/bin/sh
# Emulates a noexec mount below $NOEXEC_DIR: files there never become executable.
for a in "$@"; do last=$a; done
if [ -n "$NOEXEC_DIR" ]; then
  case $last in "$NOEXEC_DIR"/*) exec @CHMOD@ 600 "$last";; esac
fi
exec @CHMOD@ "$@"
`

const sudoShim = `#!/bin/sh
# Emulates sudo: SUDO_SHIM_MODE is refuse, nopasswd or empty (password).
nonint=; prompt="Password: "
while [ $# -gt 0 ]; do
  case $1 in
    -n) nonint=1; shift;;
    -S) shift;;
    -p) prompt=$2; shift 2;;
    --) shift; break;;
    -*) shift;;
    *) break;;
  esac
done
case $SUDO_SHIM_MODE in
  refuse) echo "sudo: user is not in the sudoers file" >&2; exit 1;;
  nopasswd) exec env BOMCENSUS_TEST_SUDO=1 "$@";;
esac
if [ -n "$nonint" ]; then echo "sudo: a password is required" >&2; exit 1; fi
tries=0
while [ $tries -lt 3 ]; do
  printf '%s' "$prompt" >&2
  IFS= read -r pw || { echo "sudo: no password was provided" >&2; exit 1; }
  if [ "$pw" = "$SUDO_SHIM_PASSWORD" ]; then exec env BOMCENSUS_TEST_SUDO=1 "$@"; fi
  echo "Sorry, try again." >&2
  tries=$((tries+1))
done
exit 1
`

func newTestServer(t *testing.T, o serverOptions) *testServer {
	t.Helper()
	_, hk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(hk)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	s := &testServer{
		t: t, hostKey: signer, sandbox: root,
		home: filepath.Join(root, "home"), xdg: filepath.Join(root, "xdg"), tmp: filepath.Join(root, "tmp"),
		noise: o.noise, procs: map[int]*os.Process{},
	}
	shim := filepath.Join(root, "shim")
	for _, d := range []string{s.home, s.xdg, s.tmp, shim} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	chmod, err := exec.LookPath("chmod")
	if err != nil {
		t.Fatal(err)
	}
	writeExec(t, filepath.Join(shim, "chmod"), strings.ReplaceAll(chmodShim, "@CHMOD@", chmod))
	writeExec(t, filepath.Join(shim, "sudo"), sudoShim)
	s.env = []string{
		"HOME=" + s.home,
		"XDG_RUNTIME_DIR=" + s.xdg,
		"PATH=" + shim + ":/usr/local/bin:/usr/bin:/bin",
		"LANG=C",
	}
	for k, v := range o.env {
		s.env = append(s.env, k+"="+v)
	}

	cfg := &gossh.ServerConfig{}
	if o.password != "" {
		cfg.PasswordCallback = func(_ gossh.ConnMetadata, pw []byte) (*gossh.Permissions, error) {
			if string(pw) == o.password {
				return nil, nil
			}
			return nil, errors.New("wrong password")
		}
	}
	if o.authorized != nil {
		cfg.PublicKeyCallback = func(_ gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			if string(key.Marshal()) == string(o.authorized.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("unknown key")
		}
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.ln = ln
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns = append(s.conns, c)
			s.mu.Unlock()
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.serveConn(c, cfg)
			}()
		}
	}()
	t.Cleanup(s.close)
	return s
}

func writeExec(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func (s *testServer) close() {
	s.closeOnce.Do(func() {
		s.ln.Close()
		s.mu.Lock()
		for _, c := range s.conns {
			c.Close()
		}
		for _, p := range s.procs {
			_ = syscall.Kill(-p.Pid, syscall.SIGKILL)
		}
		s.mu.Unlock()
		done := make(chan struct{})
		go func() { s.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			s.t.Error("test server did not shut down")
		}
	})
}

func (s *testServer) host() string { return "127.0.0.1" }

func (s *testServer) port() int { return s.ln.Addr().(*net.TCPAddr).Port }

func (s *testServer) hostKeyWire() []byte { return s.hostKey.PublicKey().Marshal() }

func (s *testServer) recorded() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.commands...)
}

func (s *testServer) serveConn(c net.Conn, cfg *gossh.ServerConfig) {
	_, chans, reqs, err := gossh.NewServerConn(c, cfg)
	if err != nil {
		c.Close()
		return
	}
	go gossh.DiscardRequests(reqs)
	for nc := range chans {
		switch nc.ChannelType() {
		case "session":
			ch, creqs, err := nc.Accept()
			if err != nil {
				continue
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.serveSession(ch, creqs)
			}()
		default:
			_ = nc.Reject(gossh.UnknownChannelType, "unsupported")
		}
	}
}

var signalNames = map[string]syscall.Signal{
	"TERM": syscall.SIGTERM, "HUP": syscall.SIGHUP, "INT": syscall.SIGINT, "KILL": syscall.SIGKILL,
}

func (s *testServer) serveSession(ch gossh.Channel, reqs <-chan *gossh.Request) {
	defer ch.Close()
	var cmd *exec.Cmd
	exited := make(chan int, 1)
	for {
		var req *gossh.Request
		var ok bool
		select {
		case req, ok = <-reqs:
			if !ok {
				return
			}
		case status := <-exited:
			_, _ = ch.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{uint32(status)}))
			return
		}
		switch req.Type {
		case "exec":
			var p struct{ Command string }
			if cmd != nil || gossh.Unmarshal(req.Payload, &p) != nil {
				_ = req.Reply(false, nil)
				continue
			}
			s.mu.Lock()
			s.commands = append(s.commands, p.Command)
			s.mu.Unlock()
			command := p.Command
			if s.noise {
				command = "echo login banner noise; echo stderr noise >&2; " + command
			}
			cmd = exec.Command("/bin/sh", "-c", command)
			cmd.Dir = s.home
			cmd.Env = s.env
			cmd.Stdout = ch
			cmd.Stderr = ch.Stderr()
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			pr, pw, err := os.Pipe()
			if err != nil {
				_ = req.Reply(false, nil)
				continue
			}
			cmd.Stdin = pr
			if err := cmd.Start(); err != nil {
				pr.Close()
				pw.Close()
				_ = req.Reply(false, nil)
				continue
			}
			pr.Close()
			_ = req.Reply(true, nil)
			s.mu.Lock()
			s.procs[cmd.Process.Pid] = cmd.Process
			s.mu.Unlock()
			go func() {
				n, _ := io.Copy(pw, ch)
				s.stdinBytes.Add(n)
				pw.Close()
			}()
			go func(cmd *exec.Cmd) {
				err := cmd.Wait()
				s.mu.Lock()
				delete(s.procs, cmd.Process.Pid)
				s.mu.Unlock()
				status := 0
				var ee *exec.ExitError
				if errors.As(err, &ee) {
					status = ee.ExitCode()
					if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
						status = 128 + int(ws.Signal())
					}
				} else if err != nil {
					status = 255
				}
				exited <- status
			}(cmd)
		case "signal":
			var p struct{ Signal string }
			if cmd != nil && gossh.Unmarshal(req.Payload, &p) == nil {
				if sig, ok := signalNames[p.Signal]; ok {
					_ = cmd.Process.Signal(sig)
				}
			}
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// leftovers lists uploaded probe files that are still in the sandbox.
func (s *testServer) leftovers() []string {
	var found []string
	_ = filepath.WalkDir(s.sandbox, func(path string, d os.DirEntry, err error) error {
		if err == nil && strings.HasPrefix(d.Name(), probeFilePrefix) {
			found = append(found, path)
		}
		return nil
	})
	return found
}

func (s *testServer) String() string { return fmt.Sprintf("testServer(%s)", s.ln.Addr()) }
