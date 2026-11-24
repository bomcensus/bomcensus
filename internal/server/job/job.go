// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package job is the background job queue of the server: a Queue interface,
// a PostgreSQL implementation on River and an in-memory one for tests, the
// job kinds with their argument types, and the handlers that only need the
// store and ingest.
package job

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Job kinds.
const (
	// KindIngestReport applies a stored raw report (IngestReportArgs).
	KindIngestReport = "ingest_report"
	// KindScanSSHDue starts the SSH scans whose interval has passed
	// (ScanSSHDueArgs).
	KindScanSSHDue = "scan_ssh_due"
	// KindK8sSyncDue starts the Kubernetes inventory syncs that are due
	// (K8sSyncDueArgs).
	KindK8sSyncDue = "k8s_sync_due"
	// KindCleanup deletes expired and old records (CleanupArgs).
	KindCleanup = "cleanup"
	// KindRenewCertificates renews server and agent certificates that are
	// close to expiry (RenewCertificatesArgs).
	KindRenewCertificates = "renew_certificates"
	// KindFeedMatch matches pending components against the active feed
	// server (no arguments).
	KindFeedMatch = "feed_match"
	// KindFindingsRefresh computes the findings of assets whose inputs
	// changed (no arguments).
	KindFindingsRefresh = "findings_refresh"
)

// IngestReportArgs names a raw report stored by the upload handler.
type IngestReportArgs struct {
	ReportID string `json:"report_id"`
}

// ScanSSHDueArgs are the arguments of KindScanSSHDue.
type ScanSSHDueArgs struct{}

// K8sSyncDueArgs are the arguments of KindK8sSyncDue.
type K8sSyncDueArgs struct{}

// CleanupArgs are the arguments of KindCleanup.
type CleanupArgs struct{}

// RenewCertificatesArgs are the arguments of KindRenewCertificates.
type RenewCertificatesArgs struct{}

// IngestReportKey is the unique key of the ingest job of a report, so that
// a report is queued once.
func IngestReportKey(reportID string) string { return "report:" + reportID }

// DefaultMaxAttempts is the number of attempts of a job enqueued without
// MaxAttempts. With the backoff of attempt⁴ seconds the last attempt runs
// about four hours after the first.
const DefaultMaxAttempts = 10

var (
	// ErrNotStarted is returned by Enqueue before Start.
	ErrNotStarted = errors.New("job: queue not started")
	// ErrAlreadyStarted is returned by Register, Periodic and Start after
	// Start.
	ErrAlreadyStarted = errors.New("job: queue already started")
)

// Job is one execution of a queued job.
type Job struct {
	ID   string
	Kind string
	// Args is the JSON encoding of the enqueued arguments.
	Args json.RawMessage
	// Attempt counts from 1.
	Attempt     int
	MaxAttempts int
}

// Decode unmarshals the arguments into v.
func (j Job) Decode(v any) error {
	if err := json.Unmarshal(j.Args, v); err != nil {
		return Permanent(fmt.Errorf("job %s: decode args: %w", j.Kind, err))
	}
	return nil
}

// Handler runs a job. Returning nil completes it. An error marked with
// Permanent (or one with a Permanent() bool method returning true) discards
// the job; any other error schedules a retry with exponential backoff until
// the attempts are used up.
type Handler func(ctx context.Context, j Job) error

// Queue is the job queue.
type Queue interface {
	// Register sets the handler of a kind. It must be called before Start.
	Register(kind string, h Handler) error
	// Periodic enqueues args under kind once at Start and then every
	// interval. With several servers only one of them enqueues. It must be
	// called before Start.
	Periodic(kind string, interval time.Duration, args any, opts ...Option) error
	// Enqueue queues a job. With UniqueKey, a job of the same kind and key
	// that has not finished yet makes this a no-op (Result.Duplicate).
	Enqueue(ctx context.Context, kind string, args any, opts ...Option) (Result, error)
	// Start begins running jobs. Jobs inherit ctx's values, not its
	// cancellation; Stop ends them.
	Start(ctx context.Context) error
	// Stop waits for running jobs until ctx is done, then cancels them.
	Stop(ctx context.Context) error
}

// Result tells what Enqueue did.
type Result struct {
	ID string
	// Duplicate is set when a unique job with the same key exists and
	// nothing was queued; ID is then the existing job's.
	Duplicate bool
}

// Options are the enqueue options.
type Options struct {
	UniqueKey   string
	ScheduledAt time.Time
	MaxAttempts int
}

// Option sets an enqueue option.
type Option func(*Options)

// UniqueKey deduplicates jobs of one kind: while a job with the key is
// queued, scheduled, running or waiting for a retry, enqueueing another one
// is a no-op.
func UniqueKey(key string) Option { return func(o *Options) { o.UniqueKey = key } }

// ScheduledAt delays the job until t.
func ScheduledAt(t time.Time) Option { return func(o *Options) { o.ScheduledAt = t } }

// MaxAttempts bounds the attempts of the job (default DefaultMaxAttempts).
func MaxAttempts(n int) Option { return func(o *Options) { o.MaxAttempts = n } }

func applyOptions(opts []Option) Options {
	var o Options
	for _, f := range opts {
		f(&o)
	}
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = DefaultMaxAttempts
	}
	return o
}

// Permanent marks err so that the job is not retried.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return &permanentError{err}
}

type permanentError struct{ err error }

func (e *permanentError) Error() string   { return e.err.Error() }
func (e *permanentError) Unwrap() error   { return e.err }
func (e *permanentError) Permanent() bool { return true }

// Snooze returns an error that runs the job again after d without using an
// attempt: for a job that stopped early with work left, or that was asked
// to wait.
func Snooze(d time.Duration) error { return &snoozeError{d: d} }

type snoozeError struct{ d time.Duration }

func (e *snoozeError) Error() string { return fmt.Sprintf("job: snoozed for %s", e.d) }

// snoozeOf returns the delay of a Snooze error.
func snoozeOf(err error) (time.Duration, bool) {
	var s *snoozeError
	if errors.As(err, &s) {
		return max(s.d, 0), true
	}
	return 0, false
}

// IsPermanent reports whether err (or an error it wraps) says it is
// permanent.
func IsPermanent(err error) bool {
	var p interface{ Permanent() bool }
	return errors.As(err, &p) && p.Permanent()
}

// IsRetryLater reports whether err (or an error it wraps) says the same
// input may succeed later.
func IsRetryLater(err error) bool {
	var r interface{ RetryLater() bool }
	return errors.As(err, &r) && r.RetryLater()
}

func encodeArgs(args any) (json.RawMessage, error) {
	if args == nil {
		return json.RawMessage("{}"), nil
	}
	b, err := json.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("job: encode args: %w", err)
	}
	return b, nil
}

// backoff is the delay before attempt+1 after a failed attempt.
func backoff(attempt int) time.Duration {
	a := time.Duration(attempt)
	return a * a * a * a * time.Second
}
