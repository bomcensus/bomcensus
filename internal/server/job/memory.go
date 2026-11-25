// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package job

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/bomcensus/bomcensus/server/scope"
)

// Memory is an in-process queue for tests and single-process tools. Jobs
// are lost when the process ends.
type Memory struct {
	// Backoff is the delay before the next attempt after a failed one.
	// Nil uses the River schedule (attempt⁴ seconds). Set before Start.
	Backoff func(attempt int) time.Duration

	log *slog.Logger

	mu       sync.Mutex
	handlers map[string]Handler
	periodic []memPeriodic
	pending  []*memJob
	unique   map[string]string // kind+key -> job id, until the job finishes
	nextID   int64
	running  int
	started  bool
	stopping bool
	wake     chan struct{}
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

type memJob struct {
	Job
	key   string
	runAt time.Time
}

type memPeriodic struct {
	kind     string
	interval time.Duration
	args     json.RawMessage
	opts     []Option
}

// NewMemory returns an empty in-memory queue. A nil log discards messages.
func NewMemory(log *slog.Logger) *Memory {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Memory{log: log, handlers: map[string]Handler{}, unique: map[string]string{},
		wake: make(chan struct{}, 1)}
}

// Register implements Queue.
func (m *Memory) Register(kind string, h Handler) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return ErrAlreadyStarted
	}
	if _, ok := m.handlers[kind]; ok {
		return fmt.Errorf("job: handler for %s already registered", kind)
	}
	m.handlers[kind] = h
	return nil
}

// Periodic implements Queue.
func (m *Memory) Periodic(kind string, interval time.Duration, args any, opts ...Option) error {
	raw, err := encodeArgs(args)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return ErrAlreadyStarted
	}
	m.periodic = append(m.periodic, memPeriodic{kind, interval, raw, append([]Option{UniqueKey(kind)}, opts...)})
	return nil
}

// Enqueue implements Queue.
func (m *Memory) Enqueue(ctx context.Context, kind string, args any, opts ...Option) (Result, error) {
	raw, err := encodeArgs(args)
	if err != nil {
		return Result{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.started {
		return Result{}, ErrNotStarted
	}
	return m.enqueueLocked(kind, raw, applyOptions(opts)), nil
}

func (m *Memory) enqueueLocked(kind string, raw json.RawMessage, o Options) Result {
	key := ""
	if o.UniqueKey != "" {
		key = kind + "\x00" + o.UniqueKey
		if id, ok := m.unique[key]; ok {
			return Result{ID: id, Duplicate: true}
		}
	}
	m.nextID++
	id := strconv.FormatInt(m.nextID, 10)
	if key != "" {
		m.unique[key] = id
	}
	runAt := o.ScheduledAt
	if runAt.IsZero() {
		runAt = time.Now()
	}
	m.pending = append(m.pending, &memJob{Job: Job{ID: id, Kind: kind, Args: raw, MaxAttempts: o.MaxAttempts},
		key: key, runAt: runAt})
	m.signal()
	return Result{ID: id}
}

func (m *Memory) signal() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// Start implements Queue.
func (m *Memory) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return ErrAlreadyStarted
	}
	m.started = true
	m.ctx, m.cancel = context.WithCancel(context.WithoutCancel(ctx))
	for _, p := range m.periodic {
		m.enqueueLocked(p.kind, p.args, applyOptions(p.opts))
		m.wg.Add(1)
		go m.tick(p)
	}
	m.wg.Add(1)
	go m.dispatch()
	return nil
}

func (m *Memory) tick(p memPeriodic) {
	defer m.wg.Done()
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-t.C:
			m.mu.Lock()
			if !m.stopping {
				m.enqueueLocked(p.kind, p.args, applyOptions(p.opts))
			}
			m.mu.Unlock()
		}
	}
}

// dispatch starts due jobs and sleeps until the next one is due.
func (m *Memory) dispatch() {
	defer m.wg.Done()
	for {
		m.mu.Lock()
		now := time.Now()
		next := time.Time{}
		var due []*memJob
		keep := m.pending[:0]
		for _, j := range m.pending {
			if m.stopping {
				keep = append(keep, j)
				continue
			}
			if _, ok := m.handlers[j.Kind]; ok && !j.runAt.After(now) {
				due = append(due, j)
				continue
			}
			keep = append(keep, j)
			if _, ok := m.handlers[j.Kind]; ok && (next.IsZero() || j.runAt.Before(next)) {
				next = j.runAt
			}
		}
		m.pending = keep
		for _, j := range due {
			m.running++
			m.wg.Add(1)
			go m.run(j, m.handlers[j.Kind])
		}
		m.mu.Unlock()

		wait := time.Hour
		if !next.IsZero() {
			wait = time.Until(next)
		}
		timer := time.NewTimer(wait)
		select {
		case <-m.ctx.Done():
			timer.Stop()
			return
		case <-m.wake:
		case <-timer.C:
		}
		timer.Stop()
	}
}

func (m *Memory) run(j *memJob, h Handler) {
	defer m.wg.Done()
	j.Attempt++
	err := h(scope.System(m.ctx), j.Job)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.running--
	d, snoozed := snoozeOf(err)
	switch {
	case err == nil:
	case snoozed && m.ctx.Err() == nil:
		j.Attempt--
		j.runAt = time.Now().Add(d)
		m.pending = append(m.pending, j)
		m.signal()
		return
	case IsPermanent(err) || j.Attempt >= j.MaxAttempts || m.ctx.Err() != nil:
		m.log.Warn("job discarded", "kind", j.Kind, "id", j.ID, "attempt", j.Attempt, "err", err)
	default:
		delay := backoff(j.Attempt)
		if m.Backoff != nil {
			delay = m.Backoff(j.Attempt)
		}
		j.runAt = time.Now().Add(delay)
		m.pending = append(m.pending, j)
		m.signal()
		return
	}
	if j.key != "" {
		delete(m.unique, j.key)
	}
}

// Stop implements Queue. Queued jobs are dropped.
func (m *Memory) Stop(ctx context.Context) error {
	m.mu.Lock()
	if !m.started || m.stopping {
		m.mu.Unlock()
		return nil
	}
	m.stopping = true
	m.mu.Unlock()

	done := make(chan struct{})
	go func() {
		// Running jobs finish; the dispatcher and tickers stop with the
		// context, which is cancelled once running jobs are done or ctx
		// expires.
		m.waitRunning(ctx)
		m.cancel()
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		m.cancel()
		<-done
		return ctx.Err()
	}
}

// waitRunning polls until no job is running or ctx is done.
func (m *Memory) waitRunning(ctx context.Context) {
	for {
		m.mu.Lock()
		running := m.running
		m.mu.Unlock()
		if running == 0 {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Millisecond):
		}
	}
}

var _ Queue = (*Memory)(nil)
