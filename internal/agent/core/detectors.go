// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package core

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/bomcensus/bomcensus/agentproto/dto"
	"github.com/bomcensus/bomcensus/internal/detectors"
	"github.com/bomcensus/bomcensus/internal/report"
)

// Detector tables follow the trust bundle: the configuration carries the
// digest of the server's table, the poll request the digest of the table
// the agent holds, and the server adds the table to the poll result while
// the two differ. The agent keeps the table in its state directory and
// passes it to its probe (report.Request.Detectors); the probe decides how
// much of it to trust.

// detectorTable is the table received from the server.
type detectorTable struct {
	digest string
	// table is nil when the table with this digest could not be used; the
	// digest is still reported so that the server does not send it again,
	// and the probe uses its built-in table.
	table *report.DetectorTable
}

// loadDetectorTable reads the stored table. A damaged one is dropped: the
// server sends it again.
func loadDetectorTable(b []byte) (*detectorTable, error) {
	if len(b) == 0 {
		return nil, nil
	}
	t, err := detectors.Decode(b)
	if err != nil {
		return nil, err
	}
	d, err := detectors.Digest(t)
	if err != nil {
		return nil, err
	}
	return &detectorTable{digest: d, table: t}, nil
}

// Detectors returns the detector table for the probe, nil for its built-in
// table. The table must not be modified.
func (r *Runtime) Detectors() *report.DetectorTable {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.detectors == nil {
		return nil
	}
	return r.detectors.table
}

// DetectorsDigest returns the digest of the table the agent holds, empty
// when it holds none.
func (r *Runtime) DetectorsDigest() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.detectors == nil {
		return ""
	}
	return r.detectors.digest
}

// applyDetectors brings the held table in line with the configuration of a
// poll result, using the table the result carries when there is one.
func (r *Runtime) applyDetectors(cfg dto.AgentConfig, sent *dto.DetectorTable) {
	held := r.DetectorsDigest()
	switch {
	case cfg.DetectorsDigest == nil:
		// The server has no detector tables (or no longer): the probe
		// uses its built-in table.
		if held != "" {
			r.setDetectors(nil, nil)
			r.log.Info("detector table removed; the probe uses its built-in table")
		}
	case *cfg.DetectorsDigest == held:
	case sent == nil:
		r.log.Debug("detector table changed on the server; waiting for it", "digest", *cfg.DetectorsDigest)
	default:
		t, raw, err := checkDetectorTable(*cfg.DetectorsDigest, sent)
		if err != nil {
			// Remember the digest so that the table is not sent with
			// every poll; the probe uses its built-in table.
			r.log.Warn("detector table refused; the probe uses its built-in table", "digest", *cfg.DetectorsDigest, "error", err)
			r.setDetectors(&detectorTable{digest: *cfg.DetectorsDigest}, nil)
			return
		}
		r.setDetectors(&detectorTable{digest: sent.Digest, table: t}, raw)
		r.log.Info("detector table updated", "digest", sent.Digest, "detectors", len(t.Detectors))
	}
}

// checkDetectorTable verifies a received table against the digest of the
// configuration.
func checkDetectorTable(want string, sent *dto.DetectorTable) (*report.DetectorTable, []byte, error) {
	if sent.Digest != want {
		return nil, nil, fmt.Errorf("table digest %s, configuration %s", sent.Digest, want)
	}
	sum := sha256.Sum256(sent.Table)
	if hex.EncodeToString(sum[:]) != want {
		return nil, nil, errors.New("table does not match its digest")
	}
	t, err := detectors.Decode(sent.Table)
	if err != nil {
		return nil, nil, err
	}
	// The bytes must be the canonical form, so that the probe computes
	// the same digest.
	if d, err := detectors.Digest(t); err != nil || d != want {
		return nil, nil, errors.New("table is not in canonical form")
	}
	return t, sent.Table, nil
}

// setDetectors replaces the held table and stores it (raw nil removes it).
func (r *Runtime) setDetectors(t *detectorTable, raw []byte) {
	r.mu.Lock()
	r.detectors = t
	r.mu.Unlock()
	if err := r.st.SaveDetectors(raw); err != nil {
		r.log.Warn("store detector table", "error", err)
	}
}
