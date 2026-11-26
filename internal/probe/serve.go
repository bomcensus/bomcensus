// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package probe

// Serve is the socket listener of the node agent's probe container, the
// counterpart of bomcensus-probe.socket with Accept=yes: for every
// connection it starts one "bomcensus-probe collect" with the connection as
// standard input and output, and the child restricts itself before it reads
// the request. The listener parses nothing it receives.
//
// The listener runs as root, because its children must start as root to
// change their root directory and drop to uid 65534 with the two read
// capabilities. It restricts itself as far as that allows: no effective
// capabilities (the permitted set stays, so that a child started as root
// gets its capabilities back), no_new_privs, and the probe's seccomp filter
// without the chroot denial, which the children inherit.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"slices"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/bomcensus/bomcensus/internal/sandbox"
)

// Serve defaults.
const (
	DefaultServeConnections = 4
	DefaultServeRuntime     = 20 * time.Minute
)

// ServeOptions configures Serve.
type ServeOptions struct {
	// Socket is the path of the listening socket. A socket left there by an
	// earlier run is replaced; any other file is an error.
	Socket string
	// SocketMode is the permission of the socket file (default 0600).
	SocketMode fs.FileMode
	// AllowUIDs lists the peer uids that may connect; empty allows any
	// peer that can open the socket.
	AllowUIDs []int
	// MaxConnections bounds the collections that run at the same time;
	// further connections are closed at once.
	MaxConnections int
	// MaxRuntime bounds one collection; the child is killed after it.
	MaxRuntime time.Duration
	// Exe and Args start the collection of one connection (default
	// /proc/self/exe; Args must name the command, such as "collect").
	Exe  string
	Args []string
	// Env is the environment of the children (default PATH and LANG).
	Env []string
	// Stderr receives the children's logs (default os.Stderr).
	Stderr io.Writer
	// Sandbox restricts the listener after the socket is created.
	Sandbox bool
	Log     *slog.Logger
	// Ready is called once the socket accepts connections.
	Ready func()
}

func (o *ServeOptions) defaults() {
	if o.SocketMode == 0 {
		o.SocketMode = 0o600
	}
	if o.MaxConnections <= 0 {
		o.MaxConnections = DefaultServeConnections
	}
	if o.MaxRuntime <= 0 {
		o.MaxRuntime = DefaultServeRuntime
	}
	if o.Exe == "" {
		o.Exe = "/proc/self/exe"
	}
	if o.Env == nil {
		o.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
}

// Serve accepts connections until ctx ends, then kills the running
// collections and returns nil.
func Serve(ctx context.Context, o ServeOptions) error {
	o.defaults()
	if o.Socket == "" {
		return errors.New("serve: socket path is required")
	}
	ln, err := listenUnix(o.Socket, o.SocketMode)
	if err != nil {
		return err
	}
	defer ln.Close()
	if o.Sandbox {
		if err := restrictListener(o.Log); err != nil {
			return err
		}
	}
	o.Log.Info("probe listening", "socket", o.Socket, "max_connections", o.MaxConnections,
		"max_runtime", o.MaxRuntime.String(), "allowed_uids", o.AllowUIDs)
	if o.Ready != nil {
		o.Ready()
	}

	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	sem := make(chan struct{}, o.MaxConnections)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			// Out of descriptors and the like: wait instead of spinning.
			o.Log.Warn("accept", "err", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
			}
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			o.Log.Warn("connection refused: collection limit reached", "limit", o.MaxConnections)
			c.Close()
			continue
		}
		wg.Go(func() {
			defer func() { <-sem }()
			serveConn(ctx, &o, c)
		})
	}
}

func listenUnix(path string, mode fs.FileMode) (*net.UnixListener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode().Type() != fs.ModeSocket {
			return nil, fmt.Errorf("serve: %s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("serve: remove old socket: %w", err)
		}
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("serve: %w", err)
	}
	// Unlinking is denied once the filter is installed; the next start
	// replaces the socket instead.
	ln.SetUnlinkOnClose(false)
	// Until this chmod the socket has the umask's mode, which leaves group
	// and others without write permission: nobody else can connect yet.
	if err := os.Chmod(path, mode); err != nil {
		ln.Close()
		return nil, fmt.Errorf("serve: %w", err)
	}
	return ln, nil
}

// restrictListener clears the effective capabilities and installs
// no_new_privs and the listener filter. Every step must succeed.
func restrictListener(log *slog.Logger) error {
	caps, err := currentCaps()
	if err != nil {
		return fmt.Errorf("serve: capget: %w", err)
	}
	if err := allThreadsCapset(0, caps.permitted, 0); err != nil {
		return fmt.Errorf("serve: clear effective capabilities: %w", err)
	}
	if err := allThreadsPrctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL); err != nil && err != syscall.EINVAL {
		return fmt.Errorf("serve: clear ambient capabilities: %w", err)
	}
	if s := setNoNewPrivs(); s.Status != StepApplied {
		return fmt.Errorf("serve: no_new_privs: %s", s.Detail)
	}
	s := applySeccompRules(sandbox.ListenerRules())
	if s.Status != StepApplied {
		return fmt.Errorf("serve: seccomp: %s", s.Detail)
	}
	log.Info("listener restricted", "uid", os.Geteuid(), "permitted", listOrNone(caps.permitted.names()), "seccomp", s.Detail)
	return nil
}

func serveConn(ctx context.Context, o *ServeOptions, c *net.UnixConn) {
	defer c.Close()
	uid, err := peerUID(c)
	if err != nil {
		o.Log.Warn("connection refused: peer credentials", "err", err)
		return
	}
	log := o.Log.With("peer_uid", uid)
	if len(o.AllowUIDs) > 0 && !slices.Contains(o.AllowUIDs, uid) {
		log.Warn("connection refused: peer uid not allowed")
		return
	}
	f, err := c.File()
	if err != nil {
		log.Warn("connection", "err", err)
		return
	}
	defer f.Close()

	runCtx, cancel := context.WithTimeout(ctx, o.MaxRuntime)
	defer cancel()
	cmd := exec.CommandContext(runCtx, o.Exe, o.Args...)
	cmd.Args[0] = "bomcensus-probe"
	cmd.Stdin, cmd.Stdout, cmd.Stderr = f, f, o.Stderr
	cmd.Env = o.Env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 10 * time.Second
	start := time.Now()
	if err := cmd.Start(); err != nil {
		log.Warn("start collection", "err", err)
		return
	}
	// The child holds the connection now; the peer sees the end of the
	// report when the child exits.
	f.Close()
	c.Close()
	log.Info("collection started", "pid", cmd.Process.Pid)
	err = cmd.Wait()
	switch {
	case runCtx.Err() == context.DeadlineExceeded:
		log.Warn("collection killed after the runtime limit", "limit", o.MaxRuntime.String())
	case err != nil:
		log.Warn("collection failed", "err", err, "duration", time.Since(start).Round(time.Millisecond).String())
	default:
		log.Info("collection finished", "duration", time.Since(start).Round(time.Millisecond).String())
	}
}

func peerUID(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if cerr != nil {
		return 0, cerr
	}
	return int(cred.Uid), nil
}
