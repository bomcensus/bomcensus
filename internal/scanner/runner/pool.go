// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package runner

import (
	"context"
	"errors"
	"log/slog"
	"sync"
)

// Pool errors.
var (
	// ErrInFlight: a job with the same key is queued or running.
	ErrInFlight = errors.New("runner: a job with this key is already in flight")
	// ErrPoolFull: the backlog is full.
	ErrPoolFull = errors.New("runner: too many jobs queued")
	// ErrPoolClosed: Close was called.
	ErrPoolClosed = errors.New("runner: pool is closed")
)

// Pool runs jobs off the caller's goroutine with bounded concurrency and a
// bounded backlog. At most one job per key is queued or running. A panic in
// a job is logged and ends only that job.
type Pool struct {
	log    *slog.Logger
	ctx    context.Context
	cancel context.CancelFunc
	sem    chan struct{}

	mu      sync.Mutex
	keys    map[string]bool
	pending int
	backlog int
	closed  bool
	wg      sync.WaitGroup
}

// NewPool returns a pool running up to workers jobs at once with up to
// backlog more waiting. Jobs get a context that ends with Close.
func NewPool(workers, backlog int, log *slog.Logger) *Pool {
	if workers <= 0 {
		workers = 1
	}
	if backlog < 0 {
		backlog = 0
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Pool{log: log, ctx: ctx, cancel: cancel, sem: make(chan struct{}, workers),
		keys: map[string]bool{}, backlog: workers + backlog}
}

// Submit queues fn under key. It returns ErrInFlight, ErrPoolFull or
// ErrPoolClosed without queuing.
func (p *Pool) Submit(key string, fn func(ctx context.Context)) error {
	p.mu.Lock()
	switch {
	case p.closed:
		p.mu.Unlock()
		return ErrPoolClosed
	case key != "" && p.keys[key]:
		p.mu.Unlock()
		return ErrInFlight
	case p.pending >= p.backlog:
		p.mu.Unlock()
		return ErrPoolFull
	}
	if key != "" {
		p.keys[key] = true
	}
	p.pending++
	p.wg.Add(1)
	p.mu.Unlock()

	go func() {
		defer func() {
			p.mu.Lock()
			if key != "" {
				delete(p.keys, key)
			}
			p.pending--
			p.mu.Unlock()
			p.wg.Done()
		}()
		select {
		case p.sem <- struct{}{}:
		case <-p.ctx.Done():
			// Still run the job so that it can report its cancellation.
			p.sem <- struct{}{}
		}
		defer func() { <-p.sem }()
		defer func() {
			if v := recover(); v != nil {
				_ = recovered(p.log, key, v)
			}
		}()
		fn(p.ctx)
	}()
	return nil
}

// InFlight reports whether a job with the key is queued or running.
func (p *Pool) InFlight(key string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.keys[key]
}

// Close cancels the jobs' context, refuses new jobs and waits until every
// job returned or ctx ends.
func (p *Pool) Close(ctx context.Context) error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	p.cancel()
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
