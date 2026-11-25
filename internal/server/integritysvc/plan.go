// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package integritysvc

import (
	"crypto/rand"
	"encoding/hex"
	"slices"
	"time"

	"github.com/bomcensus/bomcensus/internal/nightwindow"
	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

const (
	// ChunkLength bounds one SSH chunk, inside the SSH job timeout. A lost
	// connection costs at most one chunk.
	ChunkLength = 25 * time.Minute
	// minChunk is the least time left in a window for a chunk to start.
	minChunk = 2 * time.Minute
	// intervalSlack lets a pass start earlier in the window than the last
	// one did: the start is jittered every night.
	intervalSlack = 12 * time.Hour
	// stalePass is when an unfinished pass is given up and a new one
	// starts.
	stalePass = 14 * 24 * time.Hour
)

// Chunk is the next chunk of a subject's pass.
type Chunk struct {
	Query report.IntegrityQuery
	// Limit is the probe's runtime limit.
	Limit time.Duration
}

// NextChunk decides whether a chunk of subject's pass is due at now, from
// its last pass (nil when there is none). It continues an unfinished pass
// or starts a new one once the interval since the last start has passed,
// inside the window placed in the host's local time.
func NextChunk(p Policy, subject string, last *store.IntegrityPass, now time.Time) (Chunk, bool) {
	w, err := nightwindow.Parse(p.WindowStart, p.WindowEnd)
	if err != nil {
		return Chunk{}, false
	}
	var offset *int
	if last != nil {
		offset = last.UTCOffset
	}
	from, to := w.Around(now, nightwindow.Location(offset, time.Local))
	start := from.Add(nightwindow.Jitter(subject, from, to.Sub(from)))
	if now.Before(start) || to.Sub(now) < minChunk {
		return Chunk{}, false
	}
	q := report.IntegrityQuery{MaxReadMBps: p.MaxReadMBps, ExcludePaths: slices.Clone(p.ExcludePaths)}
	switch {
	case last != nil && last.CompletedAt == nil && now.Sub(last.StartedAt) < stalePass:
		q.PassID, q.Cursor = last.PassKey, last.Cursor
	case last != nil && now.Before(last.StartedAt.Add(time.Duration(p.IntervalDays)*24*time.Hour-intervalSlack)):
		return Chunk{}, false
	default:
		q.PassID = newPassID()
	}
	return Chunk{Query: q, Limit: min(ChunkLength, to.Sub(now))}, true
}

func newPassID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
