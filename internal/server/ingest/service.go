// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package ingest turns uploaded reports, Kubernetes inventories and scan
// results into inventory records. It is synchronous and idempotent: applying
// the same input twice leaves the inventory as after the first time.
package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// Error kinds. Errors returned by the service wrap one of these when the
// cause is the input rather than the store.
var (
	// ErrForbidden: the sender may not report on the subject.
	ErrForbidden = errors.New("ingest: subject not allowed for sender")
	// ErrInvalid: the input cannot be decoded or is incomplete.
	ErrInvalid = errors.New("ingest: invalid input")
	// ErrRetryLater: the subject is not known yet (a pod that the next
	// inventory sync will bring). The raw report is kept; ingesting it again
	// later may succeed.
	ErrRetryLater = errors.New("ingest: subject not known yet")
)

// Error is an input error. RetryLater and Permanent let callers that cannot
// import this package (the job queue) classify it.
type Error struct {
	kind error
	msg  string
}

func newErr(kind error, format string, args ...any) *Error {
	return &Error{kind: kind, msg: fmt.Sprintf(format, args...)}
}

func (e *Error) Error() string { return e.kind.Error() + ": " + e.msg }
func (e *Error) Unwrap() error { return e.kind }

// RetryLater reports whether the same input may succeed later.
func (e *Error) RetryLater() bool { return e.kind == ErrRetryLater }

// Permanent reports whether the same input will always fail.
func (e *Error) Permanent() bool { return e.kind == ErrForbidden || e.kind == ErrInvalid }

// Sender is the authenticated uploader.
type Sender struct {
	// AgentID is the agent or scanner id; empty for the embedded scanner.
	AgentID string
	Kind    store.AgentKind
	// RemoteAddr is the peer address ("host:port" or "host"), if known.
	RemoteAddr string
}

// EmbeddedScanner is the sender of the scanner that runs inside the server.
func EmbeddedScanner() Sender { return Sender{Kind: store.AgentKindScanner} }

// Service applies reports to the store.
type Service struct {
	st  store.Store
	log *slog.Logger
	now func() time.Time
}

// New returns a service. A nil log discards messages; a nil now uses
// time.Now.
func New(st store.Store, log *slog.Logger, now func() time.Time) *Service {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if now == nil {
		now = time.Now
	}
	return &Service{st: st, log: log, now: func() time.Time { return now().UTC() }}
}

// Accept decodes and authorizes a report and stores it raw. It returns the
// report id for IngestStored. The upload handler calls it and queues the
// rest, so that decoding and authorization errors reach the uploader.
func (s *Service) Accept(ctx context.Context, sender Sender, raw []byte) (string, error) {
	r, err := decode(raw)
	if err != nil {
		return "", err
	}
	if _, err := s.authorize(ctx, s.st, sender, r); err != nil {
		return "", err
	}
	return s.storeRaw(ctx, sender, r, raw)
}

// IngestReport stores the raw report and applies it.
func (s *Service) IngestReport(ctx context.Context, sender Sender, raw []byte) error {
	r, err := decode(raw)
	if err != nil {
		return err
	}
	if _, err := s.authorize(ctx, s.st, sender, r); err != nil {
		return err
	}
	id, err := s.storeRaw(ctx, sender, r, raw)
	if err != nil {
		return err
	}
	return s.apply(ctx, sender, id, r)
}

// IngestStored applies a report stored by Accept. The sender is the one
// recorded with the report.
func (s *Service) IngestStored(ctx context.Context, reportID string) error {
	rr, err := s.st.GetReport(ctx, reportID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return newErr(ErrInvalid, "report %s not found", reportID)
		}
		return fmt.Errorf("ingest: get report: %w", err)
	}
	r, err := decode(rr.Body)
	if err != nil {
		return err
	}
	if rr.SenderKind == "" {
		return newErr(ErrInvalid, "report %s has no sender kind", reportID)
	}
	sender := Sender{AgentID: rr.SourceID, Kind: rr.SenderKind, RemoteAddr: rr.RemoteAddr}
	return s.apply(ctx, sender, rr.ID, r)
}

func decode(raw []byte) (*report.Report, error) {
	r, err := report.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, newErr(ErrInvalid, "%v", err)
	}
	return r, nil
}

func (s *Service) storeRaw(ctx context.Context, sender Sender, r *report.Report, raw []byte) (string, error) {
	rr := store.RawReport{
		SourceID:    sender.AgentID,
		SenderKind:  sender.Kind,
		RemoteAddr:  sender.RemoteAddr,
		SubjectKind: string(subjectKind(r)),
		ReceivedAt:  s.now(),
		Body:        raw,
	}
	if r.Subject != nil {
		b, err := json.Marshal(r.Subject)
		if err != nil {
			return "", fmt.Errorf("ingest: encode subject: %w", err)
		}
		rr.Subject = b
	}
	id, err := s.st.StoreReport(ctx, rr)
	if err != nil {
		return "", fmt.Errorf("ingest: store report: %w", err)
	}
	return id, nil
}

func subjectKind(r *report.Report) report.SubjectKind {
	if r.Subject == nil || r.Subject.Kind == "" {
		return report.SubjectSelf
	}
	return r.Subject.Kind
}

// apply runs the whole report in one transaction.
func (s *Service) apply(ctx context.Context, sender Sender, reportID string, r *report.Report) error {
	if d := r.Detectors; d != nil && (d.Error != "" || len(d.Rejected) > 0) {
		s.log.WarnContext(ctx, "probe did not use all of the detector table", "report", reportID, "sender", sender.AgentID,
			"digest", d.Digest, "source", d.Source, "error", d.Error, "rejected", len(d.Rejected))
	}
	err := s.st.WithTx(ctx, func(tx store.Store) error {
		subj, err := s.authorize(ctx, tx, sender, r)
		if err != nil {
			return err
		}
		var assetID, container string
		if subj.k8s != nil {
			assetID, err = s.applyK8sContainer(ctx, tx, subj, r)
			container = subj.k8s.Container
		} else {
			assetID, err = s.applyHost(ctx, tx, sender, subj, r)
		}
		if err != nil {
			return err
		}
		if err := s.applyGoSymbols(ctx, tx, assetID, container, r); err != nil {
			return err
		}
		if subj.k8s == nil {
			if err := s.applyIntegrity(ctx, tx, assetID, r); err != nil {
				return err
			}
		}
		if assetID != "" {
			if err := tx.SetReportAsset(ctx, reportID, assetID); err != nil {
				return fmt.Errorf("ingest: link report: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		var ie *Error
		if errors.As(err, &ie) {
			return err
		}
		return fmt.Errorf("ingest: report %s: %w", reportID, err)
	}
	return nil
}

// reportTime is the collection time of a section, falling back to the
// report's and then to now.
func (s *Service) reportTime(r *report.Report, m *report.SectionMeta) time.Time {
	if m != nil && !m.CollectedAt.IsZero() {
		return m.CollectedAt.UTC()
	}
	if !r.CollectedAt.IsZero() {
		return r.CollectedAt.UTC()
	}
	return s.now()
}
