// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

// StoreReport implements store.Reports.
func (d *DB) StoreReport(ctx context.Context, r store.RawReport) (string, error) {
	const op = "store report"
	if r.AssetID != "" && !ivValidID(r.AssetID) {
		return "", ivInvalid(op, "malformed asset id")
	}
	var subject any
	if len(r.Subject) > 0 {
		if !json.Valid(r.Subject) {
			return "", ivInvalid(op, "subject is not JSON")
		}
		subject = string(r.Subject)
	}
	body := r.Body
	if body == nil {
		body = []byte{}
	}
	id := ivNewID()
	_, err := d.q.Exec(ctx, `
		INSERT INTO reports (id, source_id, sender_kind, remote_addr, subject_kind, subject, asset_id,
			received_at, size, body)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10)`,
		id, r.SourceID, string(r.SenderKind), r.RemoteAddr, r.SubjectKind, subject, ivNull(r.AssetID),
		ivAt(r.ReceivedAt), len(body), body)
	if err != nil {
		return "", ivErr(op, err)
	}
	return id, nil
}

// GetReport implements store.Reports.
func (d *DB) GetReport(ctx context.Context, id string) (store.RawReport, error) {
	const op = "get report"
	var r store.RawReport
	if !ivValidID(id) {
		return r, ivNotFound(op)
	}
	var subject *string
	err := d.q.QueryRow(ctx, `
		SELECT id::text, source_id, sender_kind, remote_addr, subject_kind, subject::text,
			COALESCE(asset_id::text, ''), received_at, body
		FROM reports WHERE id = $1`, id).
		Scan(&r.ID, &r.SourceID, &r.SenderKind, &r.RemoteAddr, &r.SubjectKind, &subject, &r.AssetID,
			&r.ReceivedAt, &r.Body)
	if err != nil {
		return r, ivErr(op, err)
	}
	if subject != nil {
		r.Subject = []byte(*subject)
	}
	r.ReceivedAt = r.ReceivedAt.UTC()
	return r, nil
}

// SetReportAsset implements store.Reports.
func (d *DB) SetReportAsset(ctx context.Context, reportID, assetID string) error {
	const op = "set report asset"
	if !ivValidID(reportID) || !ivValidID(assetID) {
		return ivNotFound(op)
	}
	tag, err := d.q.Exec(ctx, `UPDATE reports SET asset_id = $2 WHERE id = $1`, reportID, assetID)
	if err != nil {
		return ivErr(op, err)
	}
	if tag.RowsAffected() == 0 {
		return ivNotFound(op)
	}
	return nil
}

// DeleteReportsBefore implements store.Reports.
func (d *DB) DeleteReportsBefore(ctx context.Context, t time.Time) (int64, error) {
	tag, err := d.q.Exec(ctx, `DELETE FROM reports WHERE received_at < $1`, t.UTC())
	if err != nil {
		return 0, ivErr("delete reports", err)
	}
	return tag.RowsAffected(), nil
}
