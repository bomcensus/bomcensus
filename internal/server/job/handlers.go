// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package job

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

// ReportIngester applies a stored raw report (ingest.Service).
type ReportIngester interface {
	IngestStored(ctx context.Context, reportID string) error
}

// IngestReportHandler handles KindIngestReport. A report whose subject is
// not known yet (an error with RetryLater() true) is retried with backoff;
// a report that can never be applied (Permanent() true) is discarded.
func IngestReportHandler(ing ReportIngester, log *slog.Logger) Handler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return func(ctx context.Context, j Job) error {
		var a IngestReportArgs
		if err := j.Decode(&a); err != nil {
			return err
		}
		if a.ReportID == "" {
			return Permanent(errors.New("job: ingest_report without report id"))
		}
		err := ing.IngestStored(ctx, a.ReportID)
		switch {
		case err == nil:
			return nil
		case IsPermanent(err):
			log.Warn("report rejected", "report", a.ReportID, "err", err)
			return Permanent(err)
		case IsRetryLater(err):
			log.Debug("report deferred", "report", a.ReportID, "attempt", j.Attempt, "err", err)
		}
		return err
	}
}

// CleanupStore is what the cleanup job deletes from.
type CleanupStore interface {
	DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error)
	DeleteExpiredEnrollSessions(ctx context.Context, now time.Time) (int64, error)
	DeleteExpiredDirectives(ctx context.Context, now, ackedBefore time.Time) (int64, error)
	DeleteExpiredScanLeases(ctx context.Context, t time.Time) (int64, error)
	DeleteReportsBefore(ctx context.Context, t time.Time) (int64, error)
	DeleteProcessEventsBefore(ctx context.Context, t time.Time) (int64, error)
	PurgeGone(ctx context.Context, before time.Time) (store.PurgeResult, error)
}

// Retention says how long old records are kept. Zero keeps them forever.
type Retention struct {
	Reports       time.Duration
	ProcessEvents time.Duration
	// Gone is how long gone assets, containers, workloads and pods stay.
	Gone time.Duration
	// AckedDirectives is how long acknowledged directives stay.
	AckedDirectives time.Duration
}

// ScanLeaseKeep is how long an ended scan lease is kept.
const ScanLeaseKeep = 24 * time.Hour

// DefaultRetention keeps raw reports, process events and gone inventory
// for 30 days and acknowledged directives for 7.
func DefaultRetention() Retention {
	const day = 24 * time.Hour
	return Retention{Reports: 30 * day, ProcessEvents: 30 * day, Gone: 30 * day, AckedDirectives: 7 * day}
}

// CleanupHandler handles KindCleanup: expired sessions, enrollment
// sessions, directives and scan leases, old raw reports and process events,
// and inventory that has been gone longer than the retention. A nil now
// uses time.Now.
func CleanupHandler(st CleanupStore, r Retention, log *slog.Logger, now func() time.Time) Handler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if now == nil {
		now = time.Now
	}
	return func(ctx context.Context, _ Job) error {
		t := now().UTC()
		var errs []error
		count := func(what string, n int64, err error) {
			if err != nil {
				errs = append(errs, fmt.Errorf("cleanup %s: %w", what, err))
				return
			}
			if n > 0 {
				log.Info("cleanup", "what", what, "deleted", n)
			}
		}
		n, err := st.DeleteExpiredSessions(ctx, t)
		count("sessions", n, err)
		n, err = st.DeleteExpiredEnrollSessions(ctx, t)
		count("enrollment sessions", n, err)
		acked := time.Time{}
		if r.AckedDirectives > 0 {
			acked = t.Add(-r.AckedDirectives)
		}
		n, err = st.DeleteExpiredDirectives(ctx, t, acked)
		count("directives", n, err)
		// Ended scan leases are kept a day: schedulers read when the last
		// attempt started.
		n, err = st.DeleteExpiredScanLeases(ctx, t.Add(-ScanLeaseKeep))
		count("scan leases", n, err)
		if r.Reports > 0 {
			n, err = st.DeleteReportsBefore(ctx, t.Add(-r.Reports))
			count("reports", n, err)
		}
		if r.ProcessEvents > 0 {
			n, err = st.DeleteProcessEventsBefore(ctx, t.Add(-r.ProcessEvents))
			count("process events", n, err)
		}
		if r.Gone > 0 {
			res, err := st.PurgeGone(ctx, t.Add(-r.Gone))
			count("gone inventory", res.Assets+res.Containers+res.Workloads+res.Pods, err)
		}
		return errors.Join(errs...)
	}
}
