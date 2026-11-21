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

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
	"github.com/riverqueue/river/rivertype"
)

// RiverConfig configures the River queue.
type RiverConfig struct {
	// Workers is the number of jobs run at the same time (default 10).
	Workers int
	// FetchPollInterval is how often the queue looks for jobs besides
	// notifications (default River's, 1 s).
	FetchPollInterval time.Duration
}

// River is the PostgreSQL queue. It shares the server's pool and keeps its
// tables (river_*) next to the store's.
type River struct {
	pool *pgxpool.Pool
	log  *slog.Logger
	cfg  RiverConfig

	mu       sync.Mutex
	workers  *river.Workers
	nworkers int
	periodic []*river.PeriodicJob
	client   *river.Client[pgx.Tx]
	cancel   context.CancelFunc
}

// NewRiver returns a queue on pool. A nil log discards River's messages.
func NewRiver(pool *pgxpool.Pool, log *slog.Logger, cfg RiverConfig) *River {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 10
	}
	return &River{pool: pool, log: log, cfg: cfg, workers: river.NewWorkers()}
}

// riverArgs carries any kind through River. The unique key is the only
// field River's ByArgs uniqueness looks at.
type riverArgs struct {
	kind      string
	UniqueKey string          `json:"unique_key,omitempty" river:"unique"`
	Args      json.RawMessage `json:"args"`
}

func (a riverArgs) Kind() string { return a.kind }

type riverWorker struct {
	river.WorkerDefaults[riverArgs]
	kind string
	h    Handler
}

func (w *riverWorker) Work(ctx context.Context, j *river.Job[riverArgs]) error {
	err := w.h(ctx, Job{
		ID:          strconv.FormatInt(j.ID, 10),
		Kind:        w.kind,
		Args:        j.Args.Args,
		Attempt:     j.Attempt,
		MaxAttempts: j.MaxAttempts,
	})
	if err != nil && IsPermanent(err) {
		return river.JobCancel(err)
	}
	return err
}

// Register implements Queue.
func (q *River) Register(kind string, h Handler) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.client != nil {
		return ErrAlreadyStarted
	}
	if err := addWorker(q.workers, riverArgs{kind: kind}, &riverWorker{kind: kind, h: h}); err != nil {
		return fmt.Errorf("job: register %s: %w", kind, err)
	}
	q.nworkers++
	return nil
}

// addWorker turns River's registration panic into an error.
func addWorker(ws *river.Workers, args riverArgs, w river.Worker[riverArgs]) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	river.AddWorkerArgs(ws, args, w)
	return nil
}

// Periodic implements Queue. The job is enqueued with the kind as its
// unique key unless opts give one, so that a slow run does not pile up.
func (q *River) Periodic(kind string, interval time.Duration, args any, opts ...Option) error {
	raw, err := encodeArgs(args)
	if err != nil {
		return err
	}
	o := applyOptions(append([]Option{UniqueKey(kind)}, opts...))
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.client != nil {
		return ErrAlreadyStarted
	}
	q.periodic = append(q.periodic, river.NewPeriodicJob(river.PeriodicInterval(interval),
		func() (river.JobArgs, *river.InsertOpts) {
			return riverArgs{kind: kind, UniqueKey: o.UniqueKey, Args: raw}, insertOpts(o)
		}, &river.PeriodicJobOpts{ID: kind, RunOnStart: true}))
	return nil
}

// uniqueStates are the states in which a job blocks another with the same
// unique key: everything before it finishes.
var uniqueStates = []rivertype.JobState{
	rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRunning,
	rivertype.JobStateRetryable, rivertype.JobStateScheduled,
}

func insertOpts(o Options) *river.InsertOpts {
	io := &river.InsertOpts{MaxAttempts: o.MaxAttempts, ScheduledAt: o.ScheduledAt}
	if o.UniqueKey != "" {
		io.UniqueOpts = river.UniqueOpts{ByArgs: true, ByState: uniqueStates}
	}
	return io
}

// Enqueue implements Queue.
func (q *River) Enqueue(ctx context.Context, kind string, args any, opts ...Option) (Result, error) {
	raw, err := encodeArgs(args)
	if err != nil {
		return Result{}, err
	}
	q.mu.Lock()
	c := q.client
	q.mu.Unlock()
	if c == nil {
		return Result{}, ErrNotStarted
	}
	o := applyOptions(opts)
	res, err := c.Insert(ctx, riverArgs{kind: kind, UniqueKey: o.UniqueKey, Args: raw}, insertOpts(o))
	if err != nil {
		return Result{}, fmt.Errorf("job: enqueue %s: %w", kind, err)
	}
	return Result{ID: strconv.FormatInt(res.Job.ID, 10), Duplicate: res.UniqueSkippedAsDuplicate}, nil
}

// riverMigrateLock serializes River migrations of several servers.
const riverMigrateLock = int64(0x626f6d63_72697672) // "bomcrivr"

// Migrate applies River's migrations. Start calls it.
func (q *River) Migrate(ctx context.Context) error {
	conn, err := q.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("job: acquire connection: %w", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, riverMigrateLock); err != nil {
		return fmt.Errorf("job: lock migrations: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, riverMigrateLock)
	}()
	m, err := rivermigrate.New(riverpgxv5.New(q.pool), &rivermigrate.Config{Logger: q.log})
	if err != nil {
		return fmt.Errorf("job: river migrator: %w", err)
	}
	if _, err := m.Migrate(ctx, rivermigrate.DirectionUp, nil); err != nil {
		return fmt.Errorf("job: river migrations: %w", err)
	}
	return nil
}

// Start implements Queue: it applies River's migrations and starts the
// client. Without registered handlers the client only inserts.
func (q *River) Start(ctx context.Context) error {
	if err := q.Migrate(ctx); err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.client != nil {
		return ErrAlreadyStarted
	}
	cfg := &river.Config{
		Logger:            q.log,
		MaxAttempts:       DefaultMaxAttempts,
		FetchPollInterval: q.cfg.FetchPollInterval,
	}
	if q.nworkers > 0 {
		cfg.Queues = map[string]river.QueueConfig{river.QueueDefault: {MaxWorkers: q.cfg.Workers}}
		cfg.Workers = q.workers
		cfg.PeriodicJobs = q.periodic
	}
	c, err := river.NewClient(riverpgxv5.New(q.pool), cfg)
	if err != nil {
		return fmt.Errorf("job: river client: %w", err)
	}
	if q.nworkers > 0 {
		runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
		if err := c.Start(runCtx); err != nil {
			cancel()
			return fmt.Errorf("job: start river: %w", err)
		}
		q.cancel = cancel
	}
	q.client = c
	return nil
}

// Stop implements Queue.
func (q *River) Stop(ctx context.Context) error {
	q.mu.Lock()
	c, cancel := q.client, q.cancel
	q.mu.Unlock()
	if c == nil || cancel == nil {
		return nil
	}
	defer cancel()
	if err := c.Stop(ctx); err != nil {
		if ctx.Err() != nil {
			stopCtx, done := context.WithTimeout(context.Background(), 10*time.Second)
			defer done()
			return c.StopAndCancel(stopCtx)
		}
		return fmt.Errorf("job: stop river: %w", err)
	}
	return nil
}

var _ Queue = (*River)(nil)
