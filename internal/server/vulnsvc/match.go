// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package vulnsvc matches the server's unique components against the active
// feed server and keeps the results.
//
// Matching works on unique components, not assets: a component installed
// on ten thousand assets is queried once. A request carries only what
// identifies the software (purl, CPE, source package, origin) and the
// os-release identity of OS packages; no asset name, address or ID.
package vulnsvc

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/feedsvc"
	"github.com/bomcensus/bomcensus/internal/server/job"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// MatchPath is the feed server's match endpoint.
const MatchPath = "/v1/match"

// Defaults of Config.
const (
	DefaultBatchSize = 5000
	// DefaultRunFor keeps one job run well inside River's job timeout; a
	// run with work left snoozes and continues.
	DefaultRunFor = 40 * time.Second
	// DefaultInterval is how often the data status is checked.
	DefaultInterval = 15 * time.Minute
)

// maxResponse bounds a match response.
const maxResponse = 256 << 20

// Feed is the connection to the active feed server (feedsvc.Service).
type Feed interface {
	Session(ctx context.Context) (store.FeedServer, http.RoundTripper, error)
	Report(ctx context.Context, srv store.FeedServer, err error)
	RefreshData(ctx context.Context, srv store.FeedServer, rt http.RoundTripper) (store.FeedData, error)
}

// Store is what the matcher reads and writes.
type Store interface {
	PendingMatches(ctx context.Context, e store.MatchEpoch, limit int) ([]store.Component, error)
	SaveMatches(ctx context.Context, b store.MatchBatch) error
	ResetMatches(ctx context.Context, serverID string) error
}

// Config holds the dependencies of Matcher.
type Config struct {
	Store Store
	Feed  Feed
	// Queue runs KindFeedMatch; optional for tests that call Run.
	Queue     job.Queue
	Logger    *slog.Logger
	BatchSize int
	RunFor    time.Duration
	Now       func() time.Time
	// Matched, when set, is called after a run that stored results.
	Matched func(ctx context.Context)
}

// Matcher runs the match job.
type Matcher struct {
	st       Store
	feed     Feed
	queue    job.Queue
	log      *slog.Logger
	batch    int
	runFor   time.Duration
	now      func() time.Time
	sleep    func(ctx context.Context, d time.Duration) error
	compress bool
	matched  func(ctx context.Context)
}

// New returns a Matcher. Store and Feed are required.
func New(cfg Config) (*Matcher, error) {
	if cfg.Store == nil || cfg.Feed == nil {
		return nil, errors.New("vulnsvc: store and feed are required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = DefaultBatchSize
	}
	if cfg.RunFor <= 0 {
		cfg.RunFor = DefaultRunFor
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Matcher{st: cfg.Store, feed: cfg.Feed, queue: cfg.Queue, log: cfg.Logger, batch: cfg.BatchSize,
		runFor: cfg.RunFor, now: cfg.Now, sleep: sleepCtx, compress: true, matched: cfg.Matched}, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Register registers the match job and its periodic run with q.
func (m *Matcher) Register(q job.Queue, interval time.Duration) error {
	if interval <= 0 {
		interval = DefaultInterval
	}
	if err := q.Register(job.KindFeedMatch, func(ctx context.Context, _ job.Job) error { return m.Run(ctx) }); err != nil {
		return err
	}
	return q.Periodic(job.KindFeedMatch, interval, nil, job.UniqueKey(job.KindFeedMatch))
}

// Trigger queues a match run after delay unless one is queued already.
func (m *Matcher) Trigger(ctx context.Context, delay time.Duration) error {
	if m.queue == nil {
		return errors.New("vulnsvc: no queue")
	}
	opts := []job.Option{job.UniqueKey(job.KindFeedMatch)}
	if delay > 0 {
		opts = append(opts, job.ScheduledAt(m.now().Add(delay)))
	}
	_, err := m.queue.Enqueue(ctx, job.KindFeedMatch, nil, opts...)
	return err
}

// Rematch forgets the matches against a server and queues a run, so that
// every live component is matched again.
func (m *Matcher) Rematch(ctx context.Context, serverID string) error {
	if err := m.st.ResetMatches(ctx, serverID); err != nil {
		return err
	}
	return m.Trigger(ctx, 0)
}

// Run matches pending components: it reads the data status of the active
// server, then sends batches until nothing is pending or RunFor has passed
// (it then returns job.Snooze to continue). No active server is not an
// error.
func (m *Matcher) Run(ctx context.Context) error {
	srv, rt, err := m.feed.Session(ctx)
	if errors.Is(err, feedsvc.ErrNoServer) {
		return nil
	}
	if err != nil {
		return err
	}
	data, err := m.feed.RefreshData(ctx, srv, rt)
	if err != nil {
		m.feed.Report(ctx, srv, err)
		return fmt.Errorf("vulnsvc: data status of %s: %w", srv.URL, err)
	}
	epoch := store.MatchEpoch{ServerID: srv.ID, Revision: data.Revision, Rules: data.RulesDigest}
	deadline := m.now().Add(m.runFor)
	total := 0
	defer func() {
		if total > 0 && m.matched != nil {
			m.matched(context.WithoutCancel(ctx))
		}
	}()
	for {
		comps, err := m.st.PendingMatches(ctx, epoch, m.batch)
		if err != nil {
			return err
		}
		if len(comps) == 0 {
			if total > 0 {
				m.log.Info("components matched", "server", srv.URL, "count", total, "revision", epoch.Revision)
			}
			return nil
		}
		res, err := m.send(ctx, rt, srv.URL, comps)
		var rl *rateLimited
		if errors.As(err, &rl) {
			if wait := rl.after; m.now().Add(wait).Before(deadline) {
				if err := m.sleep(ctx, wait); err != nil {
					return err
				}
				continue
			}
			m.log.Info("feed server asked to slow down", "server", srv.URL, "retry_after", rl.after)
			return job.Snooze(rl.after)
		}
		if err != nil {
			m.feed.Report(ctx, srv, err)
			return fmt.Errorf("vulnsvc: match at %s: %w", srv.URL, err)
		}
		// Results are stored under the data they were computed from; when
		// it moved on, so does the epoch (components matched earlier in this
		// run are then pending again).
		if res.Data.Revision > epoch.Revision || res.Data.Rules != epoch.Rules {
			epoch.Revision, epoch.Rules = res.Data.Revision, res.Data.Rules
		}
		b, err := convert(res, comps, epoch, m.now())
		if err != nil {
			return err
		}
		if err := m.st.SaveMatches(ctx, b); err != nil {
			return err
		}
		total += len(comps)
		if !m.now().Before(deadline) {
			m.log.Info("components matched, more pending", "server", srv.URL, "count", total)
			return job.Snooze(time.Second)
		}
	}
}

// rateLimited is a 429 answer.
type rateLimited struct{ after time.Duration }

func (e *rateLimited) Error() string { return fmt.Sprintf("rate limited, retry after %s", e.after) }

// send posts one match request.
func (m *Matcher) send(ctx context.Context, rt http.RoundTripper, baseURL string, comps []store.Component) (*matchResult, error) {
	body, err := json.Marshal(buildRequest(comps))
	if err != nil {
		return nil, err
	}
	encoding := ""
	if m.compress {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write(body)
		if err := zw.Close(); err != nil {
			return nil, err
		}
		body, encoding = buf.Bytes(), "gzip"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(baseURL, "/")+MatchPath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if encoding != "" {
		req.Header.Set("Content-Encoding", encoding)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return nil, err
	}
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		after := time.Minute
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
			after = time.Duration(s) * time.Second
		}
		return nil, &rateLimited{after: after}
	case resp.StatusCode != http.StatusOK:
		var e struct{ Code, Message string }
		_ = json.Unmarshal(raw, &e)
		if e.Code == "" {
			e.Message = strings.TrimSpace(string(raw))
		}
		return nil, fmt.Errorf("HTTP %d %s: %s", resp.StatusCode, e.Code, e.Message)
	case len(raw) > maxResponse:
		return nil, errors.New("match response too large")
	}
	var res matchResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("match response: %w", err)
	}
	return &res, nil
}
