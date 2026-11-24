// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package vulnsvc

import (
	"testing"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

func exposures(rows []store.FindingRow) map[string]string {
	out := map[string]string{}
	for _, r := range rows {
		out[r.Container+"/"+r.ComponentID+"/"+r.VulnID] = r.Exposure
	}
	return out
}

func TestCompute(t *testing.T) {
	libssl := store.Component{ID: "ssl", Type: "deb", Name: "libssl3", Arch: "amd64"}
	zlib := store.Component{ID: "zlib", Type: "deb", Name: "zlib1g", Arch: "amd64"}
	jar := store.Component{ID: "log4j", Type: "maven", Name: "log4j-core"}
	gobin := store.Component{ID: "gobin", Type: "golang", Name: "example.com/app"}
	musl := store.Component{ID: "musl", Type: "apk", Name: "musl"}
	in := store.FindingInputs{
		Kind: store.AssetHost,
		Sources: []store.FindingSource{
			{Component: libssl, VulnIDs: []string{"CVE-1", "CVE-2"}},
			{Component: zlib, VulnIDs: []string{"CVE-3"}},
			{Component: jar, Locations: []string{"/opt/app/lib/log4j-core.jar"}, InUse: true, VulnIDs: []string{"CVE-4"}},
			{Component: gobin, Locations: []string{"/usr/local/bin/app"}, VulnIDs: []string{"CVE-5"}},
			// Image content of container "web"; its processes do not report
			// packages (an older probe).
			{Container: "web", Layer: store.FindingLayerImage, ImageDigest: "sha256:a", Component: musl, VulnIDs: []string{"CVE-6"}},
		},
		Processes: []store.FindingProcess{
			// The multi-arch owner name links nginx to libssl3.
			{PID: 10, Exe: "/usr/sbin/nginx", Packages: []string{"libssl3:amd64", "nginx"}, Ports: []string{"tcp/443"}},
			{PID: 11, Exe: "/usr/bin/cron", Packages: []string{"cron"}},
			// The Go binary, found by its hash, listening on loopback only.
			{PID: 12, Exe: "/srv/app", SHA256: "h1", Packages: []string{}},
			{Container: "web", PID: 20, Exe: "/bin/busybox"},
		},
		ProcessCoverage: map[string]store.Coverage{"": store.CoverageFull},
		HashComponents:  map[string][]string{"h1": {"gobin"}},
	}
	got := exposures(Compute(in))
	want := map[string]string{
		"/ssl/CVE-1":     store.ExposureListening,
		"/ssl/CVE-2":     store.ExposureListening,
		"/zlib/CVE-3":    store.ExposureInstalled,
		"/log4j/CVE-4":   store.ExposureRunning,
		"/gobin/CVE-5":   store.ExposureRunning,
		"web/musl/CVE-6": store.ExposureUnknown,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %s, want %s", k, got[k], v)
		}
	}
	for _, r := range Compute(in) {
		if r.ComponentID == "ssl" && (len(r.Processes) != 1 || r.Processes[0].PID != 10 || r.Processes[0].Ports[0] != "tcp/443") {
			t.Errorf("ssl processes %+v", r.Processes)
		}
		if r.ComponentID == "musl" && (r.Layer != store.FindingLayerImage || r.ImageDigest != "sha256:a") {
			t.Errorf("musl row %+v", r)
		}
	}

	// A process without package data makes OS packages unknown, not
	// installed; partial coverage does too.
	in.Processes = append(in.Processes, store.FindingProcess{PID: 13, Exe: "/usr/bin/old"})
	if e := exposures(Compute(in))["/zlib/CVE-3"]; e != store.ExposureUnknown {
		t.Errorf("zlib with an unlinked process: %s", e)
	}
	in.Processes = in.Processes[:len(in.Processes)-1]
	in.ProcessCoverage[""] = store.CoveragePartial
	if e := exposures(Compute(in))["/zlib/CVE-3"]; e != store.ExposureUnknown {
		t.Errorf("zlib with partial coverage: %s", e)
	}
	// Host containers take the host's process coverage; workloads their
	// own.
	in.ProcessCoverage[""] = store.CoverageFull
	in.Processes[3].Packages = []string{"busybox"}
	if e := exposures(Compute(in))["web/musl/CVE-6"]; e != store.ExposureInstalled {
		t.Errorf("host container: %s", e)
	}
	in.Kind = store.AssetWorkload
	if e := exposures(Compute(in))["web/musl/CVE-6"]; e != store.ExposureUnknown {
		t.Errorf("workload container without its own coverage: %s", e)
	}

	if rows := Compute(store.FindingInputs{Gone: true, Sources: in.Sources}); len(rows) != 0 {
		t.Fatalf("gone asset: %+v", rows)
	}
}

func TestComputeLayers(t *testing.T) {
	c := store.Component{ID: "jar", Type: "maven"}
	in := store.FindingInputs{
		Kind: store.AssetWorkload,
		Sources: []store.FindingSource{
			{Container: "app", Layer: store.FindingLayerImage, ImageDigest: "sha256:a", Component: c, VulnIDs: []string{"CVE-1"}},
			{Container: "app", Layer: store.FindingLayerRuntime, Component: c, InUse: true, VulnIDs: []string{"CVE-1"}},
		},
	}
	rows := Compute(in)
	if len(rows) != 1 || rows[0].Layer != store.FindingLayerRuntime || rows[0].Exposure != store.ExposureRunning {
		t.Fatalf("rows %+v", rows)
	}
}
