// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build windows

package winsvc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// IsService reports whether the process was started by the Windows service
// control manager.
func IsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

// Run runs the process as the service name and returns when the service
// has stopped. start (may be nil) runs while the service reports
// START_PENDING; the service reports RUNNING only after start returned nil.
// run then runs until it returns or until its context is cancelled by a
// stop or shutdown request. An error from start or run stops the service
// with the service-specific exit code ExitFailure and is returned.
func Run(name string, start, run func(context.Context) error) error {
	h := &handler{start: start, run: run}
	if err := svc.Run(name, h); err != nil {
		return err
	}
	return h.err
}

// pendingHint is the wait hint reported while starting or stopping; the
// check point is advanced every hintInterval so the SCM keeps waiting.
const (
	pendingHint  = 30 * time.Second
	hintInterval = 5 * time.Second
)

type handler struct {
	start, run func(context.Context) error
	err        error
}

func (h *handler) Execute(_ []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if h.start != nil {
		done := make(chan error, 1)
		go func() { done <- h.start(ctx) }()
		if err := wait(svc.StartPending, done, r, s); err != nil {
			h.err = err
			return true, ExitFailure
		}
	}

	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	running := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	s <- running
	for {
		select {
		case err := <-done:
			s <- svc.Status{State: svc.StopPending}
			if err != nil {
				h.err = err
				return true, ExitFailure
			}
			return false, 0
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- running
			case svc.Stop, svc.Shutdown:
				cancel()
				if err := wait(svc.StopPending, done, r, s); err != nil && !errors.Is(err, context.Canceled) {
					h.err = err
				}
				return false, 0
			}
		}
	}
}

// wait reports state with an advancing check point until done delivers.
func wait(state svc.State, done <-chan error, r <-chan svc.ChangeRequest, s chan<- svc.Status) error {
	st := svc.Status{State: state, WaitHint: uint32(pendingHint / time.Millisecond)}
	s <- st
	t := time.NewTicker(hintInterval)
	defer t.Stop()
	for {
		select {
		case err := <-done:
			return err
		case <-t.C:
			st.CheckPoint++
			s <- st
		case c := <-r:
			if c.Cmd == svc.Interrogate {
				s <- st
			}
		}
	}
}

// EventLog returns a writer that sends each line to the Application event
// log under the event source name. The level of a log/slog text line
// selects the event type. The installer registers the source; without it
// the events are still written, with a note that the message text is
// missing from the source.
func EventLog(name string) (io.WriteCloser, error) {
	l, err := eventlog.Open(name)
	if err != nil {
		return nil, err
	}
	return &eventWriter{l: l, lineWriter: lineWriter{emit: func(lv Level, msg string) {
		switch lv {
		case LevelError:
			_ = l.Error(1, msg)
		case LevelWarning:
			_ = l.Warning(1, msg)
		default:
			_ = l.Info(1, msg)
		}
	}}}, nil
}

type eventWriter struct {
	lineWriter
	l *eventlog.Log
}

func (w *eventWriter) Close() error {
	w.lineWriter.Close()
	return w.l.Close()
}

// Control controls one service through the SCM. It keeps its connection
// and service handle open between calls, for a caller that polls; an error
// closes them and the next call opens them again. Close releases them.
type Control struct {
	Name string

	mu sync.Mutex
	m  *mgr.Mgr
	s  *mgr.Service
}

// PID returns the process ID of the service, or 0 when it does not run.
func (c *Control) PID() (uint32, error) {
	var pid uint32
	err := c.with(func(s *mgr.Service) error {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State != svc.Stopped {
			pid = st.ProcessId
		}
		return nil
	})
	return pid, err
}

// Restart stops the service and starts it again. A service that is stopped
// is left alone: it was stopped on purpose or has not been started yet.
func (c *Control) Restart(ctx context.Context, timeout time.Duration) error {
	return c.with(func(s *mgr.Service) error {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == svc.Stopped {
			return nil
		}
		deadline := time.Now().Add(timeout)
		for {
			if st.State == svc.Stopped {
				break
			}
			if st.State == svc.Running {
				if _, err := s.Control(svc.Stop); err != nil &&
					!errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) &&
					!errors.Is(err, windows.ERROR_SERVICE_CANNOT_ACCEPT_CTRL) {
					return fmt.Errorf("stop %s: %w", c.Name, err)
				}
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("stop %s: still %d after %s", c.Name, st.State, timeout)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(500 * time.Millisecond):
			}
			if st, err = s.Query(); err != nil {
				return err
			}
		}
		if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
			return fmt.Errorf("start %s: %w", c.Name, err)
		}
		return nil
	})
}

// Close closes the service handle and the SCM connection.
func (c *Control) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked()
	return nil
}

func (c *Control) closeLocked() {
	if c.s != nil {
		c.s.Close()
		c.s = nil
	}
	if c.m != nil {
		c.m.Disconnect()
		c.m = nil
	}
}

func (c *Control) with(f func(*mgr.Service) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.s == nil {
		m, err := mgr.Connect()
		if err != nil {
			return err
		}
		s, err := m.OpenService(c.Name)
		if err != nil {
			m.Disconnect()
			return err
		}
		c.m, c.s = m, s
	}
	err := f(c.s)
	if err != nil {
		// The handle may be stale (service deleted, SCM restarted).
		c.closeLocked()
	}
	return err
}
