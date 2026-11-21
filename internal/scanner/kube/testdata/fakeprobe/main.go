// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Command fakeprobe stands in for bomcensus-probe in tests. It reads a
// report.Request from stdin and writes a report with the requested sections.
// Entries of Policy.ExcludePaths starting with "fake:" select behaviors:
// "fake:sleep=SECONDS", "fake:exit=CODE", "fake:garbage", "fake:big=BYTES",
// "fake:partial".
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bomcensus/bomcensus/internal/report"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "collect" {
		fmt.Fprintln(os.Stderr, "usage: fakeprobe collect")
		os.Exit(2)
	}
	var req report.Request
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		fmt.Fprintln(os.Stderr, "fakeprobe: bad request:", err)
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "fakeprobe: running")
	partial := false
	for _, p := range req.Policy.ExcludePaths {
		k, v, _ := strings.Cut(strings.TrimPrefix(p, "fake:"), "=")
		if !strings.HasPrefix(p, "fake:") {
			continue
		}
		switch k {
		case "sleep":
			n, _ := strconv.Atoi(v)
			time.Sleep(time.Duration(n) * time.Second)
		case "exit":
			n, _ := strconv.Atoi(v)
			fmt.Fprintln(os.Stderr, "fakeprobe: exiting as asked")
			os.Exit(n)
		case "garbage":
			os.Stdout.WriteString("not a report")
			return
		case "big":
			n, _ := strconv.Atoi(v)
			os.Stdout.Write(make([]byte, n))
			return
		case "partial":
			partial = true
		}
	}
	now := time.Now().UTC()
	meta := report.SectionMeta{Coverage: report.CoverageFull, CollectedAt: now}
	host, _ := os.Hostname()
	r := &report.Report{
		SchemaVersion: report.SchemaVersion, ProbeVersion: "fake", CollectedAt: now,
		Privilege: report.Privilege{Level: report.PrivilegeNonRoot, UID: os.Getuid()},
	}
	sections := req.Sections
	if len(sections) == 0 {
		sections = report.AllSections
	}
	for _, s := range sections {
		switch s {
		case report.SectionHost:
			r.Host = &report.HostSection{SectionMeta: meta, Hostname: host, Arch: "fake",
				Kernel: fmt.Sprintf("GOMEMLIMIT=%s GOMAXPROCS=%s mem=%d runtime=%d scan_containers=%t",
					os.Getenv("GOMEMLIMIT"), os.Getenv("GOMAXPROCS"), req.Policy.MemoryLimitMB,
					req.Policy.MaxRuntimeSeconds, req.Policy.ScanContainers)}
		case report.SectionPackages:
			m := meta
			if partial {
				m.Coverage, m.Reason = report.CoveragePartial, "asked to be partial"
			}
			r.Packages = &report.PackagesSection{SectionMeta: m, Packages: []report.Package{{Type: report.PackageAPK, Name: "fake", Version: "1.0-r0"}}}
		case report.SectionArtifacts:
			r.Artifacts = &report.ArtifactsSection{SectionMeta: meta}
		case report.SectionProcesses:
			r.Processes = &report.ProcessesSection{SectionMeta: meta, Processes: []report.Process{{PID: os.Getpid(), Exe: "/fake"}}}
		}
	}
	if err := report.Encode(os.Stdout, r); err != nil {
		fmt.Fprintln(os.Stderr, "fakeprobe:", err)
		os.Exit(1)
	}
}
