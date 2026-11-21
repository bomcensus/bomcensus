// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package ingest

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

// ScanResult is the outcome of one SSH scan of a target.
type ScanResult struct {
	Status     store.ScanResult
	Message    string
	StartedAt  time.Time
	FinishedAt time.Time
}

// RecordScanResult stores the outcome of a scan of target targetID. Only the
// target's scanner may send it. A failed scan marks the coverage of the
// target's asset, if it has one, as failed with the message.
func (s *Service) RecordScanResult(ctx context.Context, sender Sender, targetID string, res ScanResult) error {
	switch res.Status {
	case store.ScanOK, store.ScanPartial, store.ScanFailed:
	default:
		return newErr(ErrInvalid, "unknown scan status %q", res.Status)
	}
	return s.st.WithTx(ctx, func(tx store.Store) error {
		if sender.Kind != store.AgentKindScanner {
			return newErr(ErrForbidden, "only scanners send scan results")
		}
		if _, err := senderAgent(ctx, tx, sender); err != nil {
			return err
		}
		t, err := tx.GetScanTarget(ctx, targetID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return newErr(ErrForbidden, "unknown scan target %q", targetID)
			}
			return fmt.Errorf("ingest: get scan target: %w", err)
		}
		if t.ScannerID != sender.AgentID {
			return newErr(ErrForbidden, "scan target %s is not assigned to scanner %q", t.ID, sender.AgentID)
		}
		at := res.FinishedAt.UTC()
		if at.IsZero() {
			at = s.now()
		}
		var d time.Duration
		if !res.StartedAt.IsZero() && res.FinishedAt.After(res.StartedAt) {
			d = res.FinishedAt.Sub(res.StartedAt)
		}
		if err := tx.RecordScanRun(ctx, t.ID, store.ScanRun{At: at, Result: res.Status, Message: res.Message, Duration: d}); err != nil {
			return fmt.Errorf("ingest: record scan run: %w", err)
		}
		if res.Status != store.ScanFailed || t.AssetID == "" {
			return nil
		}
		msg := res.Message
		if msg == "" {
			msg = "scan failed"
		}
		if err := tx.UpdateAssetFacts(ctx, t.AssetID, store.AssetFacts{Coverage: store.CoverageFailed, CoverageReason: msg}); err != nil {
			return fmt.Errorf("ingest: mark asset failed: %w", err)
		}
		return nil
	})
}
