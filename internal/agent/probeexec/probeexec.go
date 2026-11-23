// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package probeexec obtains a report from the probe: over the systemd
// socket when it exists, otherwise by running bomcensus-probe as a child
// process with low CPU and I/O priority. Either way the request is
// report.Request as JSON and the answer is an encoded report.Report.
//
// On Windows there is no socket activation: the probe always runs as a
// child, in a job object that kills it when the agent goes away, at below
// normal priority (child_windows.go).
package probeexec

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/bomcensus/bomcensus/internal/release"
	"github.com/bomcensus/bomcensus/internal/report"
)

// Defaults.
const (
	// DefaultSocket is the probe socket of the systemd units; empty on
	// systems without one.
	DefaultSocket = defaultSocket
	// DefaultTimeout bounds a run when the policy sets no limit.
	DefaultTimeout = 30 * time.Minute
	// MaxOutput bounds the encoded report.
	MaxOutput = 512 << 20
	// killGrace is added to the policy limit before the probe is killed;
	// the probe enforces the limit itself.
	killGrace = time.Minute
)

// ProbeName is the probe executable next to the agent's own.
var ProbeName = release.ExeName(runtime.GOOS, "bomcensus-probe")

// Invoker runs the probe.
type Invoker struct {
	// Socket is the probe socket; empty selects DefaultSocket. A socket
	// that does not exist, or no socket at all, selects the child process.
	Socket string
	// RequireSocket fails a run when the socket is missing instead of
	// starting the probe as a child. The node agent of the Kubernetes chart
	// sets it: a child would run inside the agent's container, without
	// privileges, and report that container instead of the host.
	RequireSocket bool
	// Path is the probe executable; empty selects ProbeName next to the
	// running executable.
	Path string
	// Env is the environment of the child; nil selects a minimal one.
	Env []string
	// Timeout bounds a run when the policy sets no limit (default
	// DefaultTimeout).
	Timeout time.Duration
	Logger  *slog.Logger
}

func (inv *Invoker) logger() *slog.Logger {
	if inv.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return inv.Logger
}

// Collect runs the probe once.
func (inv *Invoker) Collect(ctx context.Context, req *report.Request) (*report.Report, error) {
	in, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	limit := inv.Timeout
	if limit <= 0 {
		limit = DefaultTimeout
	}
	if req.Policy.MaxRuntimeSeconds > 0 {
		limit = time.Duration(req.Policy.MaxRuntimeSeconds) * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, limit+killGrace)
	defer cancel()

	sock := inv.Socket
	if sock == "" {
		sock = DefaultSocket
	}
	var out []byte
	fi, serr := statSocket(sock)
	switch {
	case serr == nil && fi.Mode().Type() == fs.ModeSocket:
		out, err = inv.viaSocket(ctx, sock, in)
		if err != nil {
			return nil, err
		}
	case inv.RequireSocket && sock == "":
		return nil, errors.New("probe socket required, but none is configured")
	case inv.RequireSocket && serr != nil:
		return nil, fmt.Errorf("probe socket required: %w", serr)
	case inv.RequireSocket:
		return nil, fmt.Errorf("probe socket required: %s is not a socket", sock)
	default:
		out, err = inv.viaChild(ctx, in)
		if err != nil {
			return nil, err
		}
	}
	rep, err := report.Decode(bytes.NewReader(out))
	if err != nil {
		return nil, fmt.Errorf("probe output: %w", err)
	}
	return rep, nil
}

func (inv *Invoker) viaSocket(ctx context.Context, path string, in []byte) ([]byte, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("probe socket: %w", err)
	}
	defer c.Close()
	uc := c.(*net.UnixConn)
	if dl, ok := ctx.Deadline(); ok {
		_ = uc.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = uc.SetDeadline(time.Now()) })
	defer stop()
	if _, err := uc.Write(in); err != nil {
		return nil, fmt.Errorf("probe socket: write request: %w", err)
	}
	// The probe reads its request until EOF.
	if err := uc.CloseWrite(); err != nil {
		return nil, fmt.Errorf("probe socket: %w", err)
	}
	out, err := readLimited(uc)
	if err != nil {
		return nil, fmt.Errorf("probe socket: %w", err)
	}
	inv.logger().Debug("probe answered over the socket", "bytes", len(out))
	return out, nil
}

func (inv *Invoker) probePath() (string, error) {
	if inv.Path != "" {
		return inv.Path, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate own executable: %w", err)
	}
	return filepath.Join(filepath.Dir(exe), ProbeName), nil
}

func (inv *Invoker) viaChild(ctx context.Context, in []byte) ([]byte, error) {
	path, err := inv.probePath()
	if err != nil {
		return nil, err
	}
	log := inv.logger()
	cmd := exec.CommandContext(ctx, path, "collect")
	cmd.Stdin = bytes.NewReader(in)
	cmd.Env = inv.Env
	if cmd.Env == nil {
		cmd.Env = defaultEnv()
	}
	ch := prepareChild(cmd)
	cmd.WaitDelay = 10 * time.Second
	var stdout limitedBuffer
	cmd.Stdout = &stdout
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start probe: %w", err)
	}
	release := ch.started(log)
	defer release()
	logDone := make(chan struct{})
	go func() {
		defer close(logDone)
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 0, 4096), 64<<10)
		for sc.Scan() {
			log.Info("probe", "stderr", sc.Text())
		}
		_, _ = io.Copy(io.Discard, stderr)
	}()
	<-logDone
	err = cmd.Wait()
	if stdout.overflow {
		return nil, fmt.Errorf("probe output exceeds %d bytes", MaxOutput)
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("probe: %w", ctx.Err())
		}
		return nil, fmt.Errorf("probe: %w", err)
	}
	return stdout.Bytes(), nil
}

func readLimited(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxOutput+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxOutput {
		return nil, fmt.Errorf("probe output exceeds %d bytes", MaxOutput)
	}
	return b, nil
}

// limitedBuffer collects up to MaxOutput bytes and then fails writes.
type limitedBuffer struct {
	bytes.Buffer
	overflow bool
}

var errOverflow = errors.New("probe output too large")

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.overflow || b.Len()+len(p) > MaxOutput {
		b.overflow = true
		return 0, errOverflow
	}
	return b.Buffer.Write(p)
}
