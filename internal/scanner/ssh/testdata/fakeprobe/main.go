// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Command fakeprobe stands in for bomcensus-probe in the tests of package
// ssh. Policy.ExcludePaths entries starting with "test:" select behaviors.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bomcensus/bomcensus/internal/report"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Println("fakeprobe 1.0.0")
	case "collect":
		os.Exit(collect())
	default:
		os.Exit(2)
	}
}

func collect() int {
	var req report.Request
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		fmt.Fprintln(os.Stderr, "fakeprobe: bad request:", err)
		return 3
	}
	has := func(s string) bool { return slices.Contains(req.Policy.ExcludePaths, s) }
	if has("test:sleep") {
		if home := os.Getenv("HOME"); home != "" {
			_ = os.WriteFile(filepath.Join(home, "probe.pid"), []byte(strconv.Itoa(os.Getpid())), 0o600)
		}
		time.Sleep(2 * time.Minute)
	}
	if has("test:fail") {
		fmt.Fprintln(os.Stderr, "fakeprobe: failing on request")
		return 4
	}
	if has("test:big") {
		chunk := make([]byte, 64<<10)
		for range 64 {
			if _, err := os.Stdout.Write(chunk); err != nil {
				return 5
			}
		}
		return 0
	}
	level := report.PrivilegeNonRoot
	if os.Getuid() == 0 || os.Getenv("BOMCENSUS_TEST_SUDO") == "1" {
		level = report.PrivilegePrivileged
	}
	now := time.Now().UTC()
	rep := &report.Report{
		SchemaVersion: report.SchemaVersion,
		ProbeVersion:  "fake",
		CollectedAt:   now,
		Subject:       &report.Subject{Kind: report.SubjectSelf},
		Privilege:     report.Privilege{Level: level, UID: os.Getuid()},
		Host: &report.HostSection{
			SectionMeta: report.SectionMeta{Coverage: report.CoverageFull, CollectedAt: now},
			Hostname:    "fake:" + strings.Join(req.Sections, ","),
			OS:          report.OS{Family: "linux"},
			Arch:        runtime.GOARCH,
		},
		Cache: req.Cache,
	}
	fmt.Fprintln(os.Stderr, "fakeprobe: collected")
	if err := report.Encode(os.Stdout, rep); err != nil {
		fmt.Fprintln(os.Stderr, "fakeprobe:", err)
		return 6
	}
	return 0
}
