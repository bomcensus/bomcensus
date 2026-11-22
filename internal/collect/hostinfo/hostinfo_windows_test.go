// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package hostinfo

import (
	"context"
	"testing"

	"github.com/bomcensus/bomcensus/internal/collect"
	"github.com/bomcensus/bomcensus/internal/report"
)

func TestDescribe(t *testing.T) {
	o, kernel := describe(10, 0, 26100, currentVersion{ProductName: "Windows 10 Pro", DisplayVersion: "24H2", UBR: 2314})
	if o.Name != "Windows 11 Pro" || o.Version != "24H2" || o.VersionID != "10.0.26100" {
		t.Errorf("os = %+v", o)
	}
	if kernel != "10.0.26100.2314" {
		t.Errorf("kernel = %q", kernel)
	}
	if o.PrettyName != "Windows 11 Pro 24H2 (10.0.26100.2314)" {
		t.Errorf("pretty = %q", o.PrettyName)
	}
	o, _ = describe(10, 0, 17763, currentVersion{ProductName: "Windows Server 2019 Datacenter", ReleaseID: "1809"})
	if o.Name != "Windows Server 2019 Datacenter" || o.Version != "1809" {
		t.Errorf("server os = %+v", o)
	}
}

func TestCollectLive(t *testing.T) {
	sec := Collect(context.Background(), collect.NewEnv())
	if sec.OS.Family != "windows" || sec.Hostname == "" || sec.Arch == "" || sec.OS.VersionID == "" {
		t.Fatalf("section = %+v", sec)
	}
	if sec.Coverage != report.CoverageFull {
		t.Logf("coverage %s: %s", sec.Coverage, sec.Reason)
	}
	if sec.Digest == "" {
		t.Error("no digest")
	}
}
