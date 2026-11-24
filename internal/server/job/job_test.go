// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package job

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

// newTestPool creates a fresh, empty database from
// BOMCENSUS_TEST_DATABASE_URL and drops it when the test ends. The test is
// skipped when the variable is unset.
func newTestPool(t testing.TB) *pgxpool.Pool {
	t.Helper()
	base := os.Getenv("BOMCENSUS_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("BOMCENSUS_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	name := "bomcensus_test_" + hex.EncodeToString(b[:])
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		admin.Close(ctx)
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			t.Errorf("drop database: %v", err)
		}
		admin.Close(ctx)
	})
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	u.Path = "/" + name
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

type echoArgs struct {
	N int `json:"n"`
}

// exercise runs the same round trip against any Queue: a job runs, a unique
// key deduplicates while the job is pending, a failing job is retried, a
// permanent error is not, and a periodic job fires.
func exercise(t *testing.T, q Queue, periodicEvery time.Duration) {
	ctx := context.Background()
	got := make(chan int, 16)
	release := make(chan struct{})
	var flaky atomic.Int32
	var permanent atomic.Int32
	periodic := make(chan struct{}, 16)

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(q.Register("echo", func(ctx context.Context, j Job) error {
		var a echoArgs
		if err := j.Decode(&a); err != nil {
			return err
		}
		got <- a.N
		return nil
	}))
	must(q.Register("block", func(ctx context.Context, j Job) error {
		<-release
		got <- -1
		return nil
	}))
	must(q.Register("flaky", func(ctx context.Context, j Job) error {
		if flaky.Add(1) == 1 {
			return errors.New("first attempt fails")
		}
		got <- 100 + j.Attempt
		return nil
	}))
	var sleepy atomic.Int32
	must(q.Register("sleepy", func(ctx context.Context, j Job) error {
		if sleepy.Add(1) == 1 {
			return Snooze(100 * time.Millisecond)
		}
		got <- 200
		return nil
	}))
	must(q.Register("bad", func(ctx context.Context, j Job) error {
		permanent.Add(1)
		return Permanent(errors.New("never"))
	}))
	must(q.Register("tick", func(ctx context.Context, j Job) error {
		select {
		case periodic <- struct{}{}:
		default:
		}
		return nil
	}))
	must(q.Periodic("tick", periodicEvery, nil))

	if _, err := q.Enqueue(ctx, "echo", echoArgs{1}); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("enqueue before start: %v", err)
	}
	must(q.Start(ctx))
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := q.Stop(stopCtx); err != nil {
			t.Errorf("stop: %v", err)
		}
	}()
	if err := q.Register("late", func(context.Context, Job) error { return nil }); !errors.Is(err, ErrAlreadyStarted) {
		t.Fatalf("register after start: %v", err)
	}

	wait := func(want int) {
		t.Helper()
		select {
		case n := <-got:
			if n != want {
				t.Fatalf("got %d, want %d", n, want)
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("job %d did not run", want)
		}
	}

	res, err := q.Enqueue(ctx, "echo", echoArgs{7})
	must(err)
	if res.ID == "" || res.Duplicate {
		t.Fatalf("enqueue result %+v", res)
	}
	wait(7)

	first, err := q.Enqueue(ctx, "block", nil, UniqueKey("k"))
	must(err)
	dup, err := q.Enqueue(ctx, "block", nil, UniqueKey("k"))
	must(err)
	if !dup.Duplicate || dup.ID != first.ID {
		t.Fatalf("unique key did not deduplicate: %+v %+v", first, dup)
	}
	other, err := q.Enqueue(ctx, "block", nil, UniqueKey("other"))
	must(err)
	if other.Duplicate {
		t.Fatal("different key deduplicated")
	}
	close(release)
	wait(-1)
	wait(-1)

	_, err = q.Enqueue(ctx, "echo", echoArgs{9}, ScheduledAt(time.Now().Add(1500*time.Millisecond)))
	must(err)
	select {
	case n := <-got:
		t.Fatalf("scheduled job ran early: %d", n)
	case <-time.After(500 * time.Millisecond):
	}
	wait(9)

	_, err = q.Enqueue(ctx, "flaky", nil)
	must(err)
	wait(102)

	// A snoozed job runs again without a retry error, even with one attempt.
	_, err = q.Enqueue(ctx, "sleepy", nil, MaxAttempts(1))
	must(err)
	wait(200)

	_, err = q.Enqueue(ctx, "bad", nil)
	must(err)
	deadline := time.Now().Add(10 * time.Second)
	for permanent.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(1500 * time.Millisecond)
	if n := permanent.Load(); n != 1 {
		t.Fatalf("permanent job ran %d times", n)
	}

	for i := 0; i < 2; i++ {
		select {
		case <-periodic:
		case <-time.After(60 * time.Second):
			t.Fatalf("periodic job fired %d times", i)
		}
	}
}

func TestMemoryQueue(t *testing.T) {
	q := NewMemory(nil)
	q.Backoff = func(int) time.Duration { return 10 * time.Millisecond }
	exercise(t, q, 200*time.Millisecond)
}

func TestRiverQueue(t *testing.T) {
	pool := newTestPool(t)
	q := NewRiver(pool, nil, RiverConfig{Workers: 4, FetchPollInterval: 100 * time.Millisecond})
	exercise(t, q, time.Second)

	// Migrations are idempotent and a second queue on the same database
	// starts.
	q2 := NewRiver(pool, nil, RiverConfig{})
	if err := q2.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := q2.Enqueue(context.Background(), "echo", echoArgs{1}, UniqueKey("x")); err != nil {
		t.Fatal(err)
	}
	if err := q2.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

type fakeIngester struct {
	mu    sync.Mutex
	calls int
	errs  []error
}

func (f *fakeIngester) IngestStored(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if len(f.errs) == 0 {
		return nil
	}
	err := f.errs[0]
	f.errs = f.errs[1:]
	return err
}

type retryLater struct{}

func (retryLater) Error() string    { return "not yet" }
func (retryLater) RetryLater() bool { return true }

type rejected struct{}

func (rejected) Error() string   { return "forbidden" }
func (rejected) Permanent() bool { return true }

func TestIngestReportHandler(t *testing.T) {
	ing := &fakeIngester{errs: []error{retryLater{}, nil}}
	h := IngestReportHandler(ing, nil)
	job := Job{Kind: KindIngestReport, Args: []byte(`{"report_id":"r1"}`), Attempt: 1}
	if err := h(context.Background(), job); err == nil || IsPermanent(err) || !IsRetryLater(err) {
		t.Fatalf("retry later: %v", err)
	}
	if err := h(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	ing.errs = []error{rejected{}}
	if err := h(context.Background(), job); !IsPermanent(err) {
		t.Fatalf("rejected: %v", err)
	}
	if err := h(context.Background(), Job{Kind: KindIngestReport, Args: []byte(`{}`)}); !IsPermanent(err) {
		t.Fatalf("missing id: %v", err)
	}
}

type fakeCleanup struct {
	calls map[string]time.Time
}

func (f *fakeCleanup) DeleteExpiredSessions(_ context.Context, now time.Time) (int64, error) {
	f.calls["sessions"] = now
	return 1, nil
}
func (f *fakeCleanup) DeleteExpiredEnrollSessions(_ context.Context, now time.Time) (int64, error) {
	f.calls["enroll"] = now
	return 0, nil
}
func (f *fakeCleanup) DeleteExpiredDirectives(_ context.Context, now, acked time.Time) (int64, error) {
	f.calls["directives"] = acked
	return 0, nil
}
func (f *fakeCleanup) DeleteExpiredScanLeases(_ context.Context, t time.Time) (int64, error) {
	f.calls["leases"] = t
	return 0, nil
}
func (f *fakeCleanup) DeleteReportsBefore(_ context.Context, t time.Time) (int64, error) {
	f.calls["reports"] = t
	return 0, errors.New("boom")
}
func (f *fakeCleanup) DeleteProcessEventsBefore(_ context.Context, t time.Time) (int64, error) {
	f.calls["events"] = t
	return 0, nil
}
func (f *fakeCleanup) PurgeGone(_ context.Context, t time.Time) (store.PurgeResult, error) {
	f.calls["gone"] = t
	return store.PurgeResult{Assets: 1}, nil
}

func TestCleanupHandler(t *testing.T) {
	now := time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)
	st := &fakeCleanup{calls: map[string]time.Time{}}
	r := DefaultRetention()
	r.ProcessEvents = 0
	err := CleanupHandler(st, r, nil, func() time.Time { return now })(context.Background(), Job{})
	if err == nil {
		t.Fatal("store error not reported")
	}
	day := 24 * time.Hour
	want := map[string]time.Time{
		"sessions": now, "enroll": now, "directives": now.Add(-7 * day), "leases": now.Add(-day),
		"reports": now.Add(-30 * day), "gone": now.Add(-30 * day),
	}
	if len(st.calls) != len(want) {
		t.Fatalf("calls %v", st.calls)
	}
	for k, v := range want {
		if !st.calls[k].Equal(v) {
			t.Errorf("%s at %v, want %v", k, st.calls[k], v)
		}
	}
}
