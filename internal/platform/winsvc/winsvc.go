// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package winsvc runs bomcensus commands as Windows services: it talks to
// the service control manager (SCM), sends log lines to the Windows event
// log and controls other services. On other systems IsService is always
// false and the other functions fail.
package winsvc

import (
	"bytes"
	"errors"
	"sync"
)

// ErrUnsupported is returned by the service functions on systems other than
// Windows.
var ErrUnsupported = errors.New("winsvc: Windows services are not supported on this system")

// ExitFailure is the service-specific exit code reported when the service
// function fails. The installer sets the failure actions flag of the
// services, so the SCM applies the recovery actions (restart) to this exit
// code, not only to crashes.
const ExitFailure = 1

// Level is the event type of a log line.
type Level int

const (
	LevelInfo Level = iota
	LevelWarning
	LevelError
)

// lineLevel derives the event type from a log/slog text line.
func lineLevel(line []byte) Level {
	switch {
	case bytes.Contains(line, []byte("level=ERROR")):
		return LevelError
	case bytes.Contains(line, []byte("level=WARN")):
		return LevelWarning
	}
	return LevelInfo
}

// maxLine bounds one event; longer lines are split.
const maxLine = 16 << 10

// lineWriter passes every complete line written to it to emit.
type lineWriter struct {
	mu   sync.Mutex
	buf  []byte
	emit func(Level, string)
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			if len(w.buf) >= maxLine {
				w.send(w.buf[:maxLine])
				w.buf = append(w.buf[:0], w.buf[maxLine:]...)
				continue
			}
			return len(p), nil
		}
		w.send(w.buf[:i])
		w.buf = append(w.buf[:0], w.buf[i+1:]...)
	}
}

// Close sends a pending incomplete line.
func (w *lineWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.buf) > 0 {
		w.send(w.buf)
		w.buf = nil
	}
	return nil
}

func (w *lineWriter) send(line []byte) {
	line = bytes.TrimRight(line, "\r")
	if len(line) == 0 {
		return
	}
	w.emit(lineLevel(line), string(line))
}
