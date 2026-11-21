// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package state

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"sync"
)

// DefaultCounterBatch is the number of counter values reserved per write.
const DefaultCounterBatch = 64

const maxCounter = 1<<63 - 1

// Counter is the agent's monotonic message counter
// (msgsig.CounterSource). Values are reserved in batches: the file holds
// the highest reserved value, which is written before any value of the
// batch is handed out, so a crash skips values but never reuses one.
type Counter struct {
	d     *Dir
	batch uint64

	mu       sync.Mutex
	next     uint64
	reserved uint64
}

// Counter opens the message counter. batch <= 0 selects
// DefaultCounterBatch.
func (d *Dir) Counter(batch int) (*Counter, error) {
	if batch <= 0 {
		batch = DefaultCounterBatch
	}
	reserved, err := d.readCounter()
	if err != nil {
		return nil, err
	}
	return &Counter{d: d, batch: uint64(batch), next: reserved + 1, reserved: reserved}, nil
}

func (d *Dir) readCounter() (uint64, error) {
	b, err := d.ReadFile(counterName)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("state: read %s: %w", counterName, err)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || n > maxCounter {
		// Refuse to guess: a lower value could reuse counters.
		return 0, fmt.Errorf("state: %s is damaged", counterName)
	}
	return n, nil
}

// Next returns a value greater than every value returned before and every
// value passed to Observe. The value is persisted before it is returned.
func (c *Counter) Next(ctx context.Context) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.next
	if n == 0 || n > maxCounter {
		return 0, errors.New("state: counter exhausted")
	}
	if n > c.reserved {
		r := min(n+c.batch-1, maxCounter)
		if err := c.d.WriteFile(counterName, []byte(strconv.FormatUint(r, 10)+"\n"), 0o600); err != nil {
			return 0, err
		}
		c.reserved = r
	}
	c.next = n + 1
	return n, nil
}

// Observe raises the counter above last, the value the server reports as
// last accepted.
func (c *Counter) Observe(_ context.Context, last uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if last >= c.next {
		c.next = last + 1
	}
	return nil
}

// Reserved returns the highest value written to disk.
func (c *Counter) Reserved() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reserved
}
