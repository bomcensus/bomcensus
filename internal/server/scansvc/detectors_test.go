// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package scansvc

import (
	"testing"

	"github.com/bomcensus/bomcensus/internal/report"
)

// TestEmbeddedScannerDetectors: the embedded scanner hands the server's
// detector table to its probes.
func TestEmbeddedScannerDetectors(t *testing.T) {
	table := &report.DetectorTable{SchemaVersion: report.DetectorSchemaVersion}
	s := &Service{detect: func() *report.DetectorTable { return table }}
	if d := s.deps(nil); d.Detectors == nil || d.Detectors() != table {
		t.Fatal("detector table not passed")
	}
	if d := (&Service{}).deps(nil); d.Detectors != nil {
		t.Fatal("detector table without a source")
	}
}
