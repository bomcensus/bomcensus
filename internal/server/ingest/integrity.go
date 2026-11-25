// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package ingest

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// maxIntegrityField bounds the text fields of a finding.
const maxIntegrityField = 4096

var integrityAlgos = map[string]int{"md5": 32, "sha1": 40, "sha256": 64, "sha384": 96, "sha512": 128}

// applyIntegrity stores one chunk of an integrity pass of the host asset.
// A chunk that checked nothing and did not end the pass (a package manager
// was running) is not recorded.
func (s *Service) applyIntegrity(ctx context.Context, tx store.Store, assetID string, r *report.Report) error {
	sec := r.Integrity
	if sec == nil || assetID == "" || sec.PassID == "" || len(sec.PassID) > report.MaxIntegrityPassIDLen {
		return nil
	}
	if !sec.PassDone && sec.Packages == 0 && len(sec.Findings) == 0 {
		return nil
	}
	c := store.IntegrityChunk{
		AssetID:    assetID,
		PassKey:    sec.PassID,
		At:         s.reportTime(r, &sec.SectionMeta),
		Done:       sec.PassDone,
		Cursor:     bounded(sec.Cursor, report.MaxIntegrityCursorLen),
		UTCOffset:  max(min(sec.UTCOffsetSeconds, 14*3600), -14*3600),
		Checked:    max(sec.Checked, 0),
		Excluded:   max(sec.Excluded, 0),
		Unreadable: max(sec.Unreadable, 0),
		Coverage:   string(sec.Coverage),
		Reason:     bounded(sec.Reason, 2048),
	}
	dropped := 0
	for i, f := range sec.Findings {
		if i >= report.MaxIntegrityFindings {
			dropped += len(sec.Findings) - i
			break
		}
		o, ok := integrityObservation(f)
		if !ok {
			dropped++
			continue
		}
		c.Findings = append(c.Findings, o)
	}
	if dropped > 0 {
		s.log.Warn("integrity findings dropped", "asset", assetID, "count", dropped)
	}
	if err := tx.RecordIntegrityChunk(ctx, c); err != nil {
		return fmt.Errorf("ingest: integrity chunk: %w", err)
	}
	return nil
}

// integrityObservation checks a finding from a collector: known status,
// package type and algorithm, hex digests of the right length, an absolute
// path.
func integrityObservation(f report.IntegrityFinding) (store.IntegrityObservation, bool) {
	n, ok := integrityAlgos[f.Algo]
	if !ok || !strings.HasPrefix(f.Path, "/") || len(f.Path) > maxIntegrityField || !isHex(f.Expected, n) {
		return store.IntegrityObservation{}, false
	}
	switch f.PkgType {
	case report.PackageDeb, report.PackageRPM, report.PackageAPK:
	default:
		return store.IntegrityObservation{}, false
	}
	o := store.IntegrityObservation{
		Path: f.Path, Status: f.Status, PkgType: f.PkgType,
		Package: bounded(f.Package, 512), Version: bounded(f.Version, 512), Arch: bounded(f.Arch, 64),
		Algo: f.Algo, Expected: strings.ToLower(f.Expected),
	}
	switch f.Status {
	case report.IntegrityModified:
		sha := strings.ToLower(f.SHA256())
		if !isHex(f.Actual, n) || !isHex(sha, 64) {
			return store.IntegrityObservation{}, false
		}
		o.Actual, o.ActualSHA256 = strings.ToLower(f.Actual), sha
		o.Size = max(f.Size, 0)
		o.Mtime, o.Ctime = timePtr(f.Mtime), timePtr(f.Ctime)
	case report.IntegrityMissing:
	default:
		return store.IntegrityObservation{}, false
	}
	if o.Package == "" || o.Version == "" {
		return store.IntegrityObservation{}, false
	}
	return o, true
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
			return false
		}
	}
	return true
}

func bounded(s string, n int) string {
	if len(s) > n {
		s = s[:n]
	}
	return strings.ToValidUTF8(s, "")
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}
