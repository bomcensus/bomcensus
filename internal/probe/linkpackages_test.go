// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package probe

import (
	"os"
	"slices"
	"testing"

	"github.com/bomcensus/bomcensus/internal/report"
)

func TestLinkPackages(t *testing.T) {
	if _, err := os.Stat("/proc/self/root"); err != nil {
		t.Skip("no /proc")
	}
	owners := map[string]string{
		"/usr/sbin/nginx":                       "nginx",
		"/usr/lib/x86_64-linux-gnu/libssl.so.3": "libssl3",
		"/usr/lib/x86_64-linux-gnu/libz.so.1":   "zlib1g",
	}
	owner := func(p string) (string, bool) { pkg, ok := owners[p]; return pkg, ok }
	pid := os.Getpid()
	sec := &report.ProcessesSection{Processes: []report.Process{
		{PID: pid, Exe: "/usr/sbin/nginx", ExeSource: report.ExeFromProc,
			Mapped: []string{"/usr/lib/x86_64-linux-gnu/libz.so.1", "/usr/lib/x86_64-linux-gnu/libssl.so.3", "/opt/own.so"}},
		// maps not read
		{PID: pid, Exe: "/usr/sbin/nginx", ExeSource: report.ExeFromProc},
		// maps read, no other mappings
		{PID: pid, Exe: "/usr/sbin/nginx", ExeSource: report.ExeFromProc, Mapped: []string{}},
	}}
	linkPackages("/proc", sec, "/", owner)
	p := sec.Processes[0]
	if !p.PackagesKnown || !slices.Equal(p.Packages, []string{"libssl3", "nginx", "zlib1g"}) {
		t.Fatalf("linked %+v", p)
	}
	if sec.Processes[1].PackagesKnown {
		t.Fatal("process without maps linked")
	}
	if !sec.Processes[2].PackagesKnown || len(sec.Processes[2].Packages) != 1 {
		t.Fatalf("exe only %+v", sec.Processes[2])
	}

	// A root that is not the process's root links nothing.
	other := &report.ProcessesSection{Processes: []report.Process{{PID: pid, Exe: "/usr/sbin/nginx", ExeSource: report.ExeFromProc, Mapped: []string{}}}}
	linkPackages("/proc", other, t.TempDir(), owner)
	if other.Processes[0].PackagesKnown {
		t.Fatal("linked through a foreign root")
	}
}
