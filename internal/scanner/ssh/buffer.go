// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package ssh

import (
	"bytes"
	"errors"
	"sync"
)

// streamBuffer keeps the first headMax and the last tailMax bytes of a
// remote stream and signals every write on changed. Writes never fail, so
// the remote side is never blocked by a full window.
type streamBuffer struct {
	mu      sync.Mutex
	headMax int
	tailMax int
	headB   []byte
	tailB   []byte
	changed chan struct{}
}

func newStreamBuffer(headMax, tailMax int) *streamBuffer {
	return &streamBuffer{headMax: headMax, tailMax: tailMax, changed: make(chan struct{}, 1)}
}

func (b *streamBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	if room := b.headMax - len(b.headB); room > 0 {
		b.headB = append(b.headB, p[:min(room, len(p))]...)
	}
	if b.tailMax > 0 {
		b.tailB = append(b.tailB, p...)
		if over := len(b.tailB) - b.tailMax; over > 0 {
			b.tailB = append(b.tailB[:0:0], b.tailB[over:]...)
		}
	}
	b.mu.Unlock()
	select {
	case b.changed <- struct{}{}:
	default:
	}
	return len(p), nil
}

func (b *streamBuffer) head() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.headB)
}

func (b *streamBuffer) tailBytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.tailB)
}

var errSinkFull = errors.New("report sink full")

// reportSink receives the probe's standard output. It discards everything up
// to the start marker line (output of login scripts) and then keeps up to
// max bytes. Beyond that it closes overflow and fails the write, which stops
// the copy; the caller then closes the session.
type reportSink struct {
	mu       sync.Mutex
	marker   []byte
	pre      []byte
	started  bool
	data     bytes.Buffer
	max      int64
	full     bool
	overflow chan struct{}
}

func newReportSink(marker string, max int64) *reportSink {
	return &reportSink{marker: []byte(marker + "\n"), max: max, overflow: make(chan struct{})}
}

func (s *reportSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.full {
		return 0, errSinkFull
	}
	n := len(p)
	if !s.started {
		s.pre = append(s.pre, p...)
		i := bytes.Index(s.pre, s.marker)
		if i < 0 {
			if len(s.pre) > controlOutputLimit {
				// Keep only what could still be the start of a marker.
				s.pre = append(s.pre[:0:0], s.pre[len(s.pre)-len(s.marker):]...)
			}
			return n, nil
		}
		s.started = true
		p = s.pre[i+len(s.marker):]
		s.pre = nil
	}
	if int64(s.data.Len()+len(p)) > s.max {
		s.full = true
		close(s.overflow)
		return 0, errSinkFull
	}
	s.data.Write(p)
	return n, nil
}

func (s *reportSink) overflowed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.full
}

func (s *reportSink) result() ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Bytes(), s.started
}
