// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Command fakeprobe stands in for bomcensus-probe in tests. It reads a
// report.Request from stdin and writes a report with deterministic content
// for the requested sections, marking sections whose digest the caller
// already knows as unchanged.
//
// Environment: FAKEPROBE_VARIANT_FILE names a file whose content becomes
// part of the package list; FAKEPROBE_REQUESTS names a file every request
// is appended to; FAKEPROBE_FAIL=1 makes the run fail.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/bomcensus/bomcensus/internal/report"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fakeprobe:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 2 || os.Args[1] != "collect" {
		return fmt.Errorf("usage: fakeprobe collect")
	}
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	if p := os.Getenv("FAKEPROBE_REQUESTS"); p != "" {
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		if err != nil {
			return err
		}
		fmt.Fprintf(f, "%s\n", strings.TrimSpace(string(in)))
		f.Close()
	}
	if os.Getenv("FAKEPROBE_FAIL") == "1" {
		return fmt.Errorf("failing on request")
	}
	var req report.Request
	if err := json.Unmarshal(in, &req); err != nil {
		return err
	}
	var cache struct {
		Runs int `json:"runs"`
	}
	if len(req.Cache) > 0 {
		_ = json.Unmarshal(req.Cache, &cache)
	}
	cache.Runs++
	variant := "base"
	if p := os.Getenv("FAKEPROBE_VARIANT_FILE"); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			variant = strings.TrimSpace(string(b))
		}
	}
	fmt.Fprintf(os.Stderr, "fake probe run %d\n", cache.Runs)

	now := time.Now().UTC()
	rep := &report.Report{
		SchemaVersion: report.SchemaVersion,
		ProbeVersion:  fmt.Sprintf("fake-%d", cache.Runs),
		CollectedAt:   now,
		Privilege:     report.Privilege{Level: report.PrivilegeNonRoot, UID: os.Getuid()},
	}
	sections := req.Sections
	if len(sections) == 0 {
		sections = report.AllSections
	}
	meta := func(name string, body any) (report.SectionMeta, bool, error) {
		d, err := report.Digest(body)
		if err != nil {
			return report.SectionMeta{}, false, err
		}
		m := report.SectionMeta{Digest: d, Coverage: report.CoverageFull, CollectedAt: now}
		if req.KnownDigests[name] == d {
			m.Unchanged = true
		}
		return m, m.Unchanged, nil
	}
	for _, s := range sections {
		switch s {
		case report.SectionHost:
			h := &report.HostSection{Hostname: "fakehost", OS: report.OS{Family: "linux", ID: "fake"}, Arch: "amd64"}
			m, unchanged, err := meta(s, struct {
				Hostname string
				OS       report.OS
			}{h.Hostname, h.OS})
			if err != nil {
				return err
			}
			if unchanged {
				h = &report.HostSection{}
			}
			h.SectionMeta = m
			rep.Host = h
		case report.SectionPackages:
			pkgs := []report.Package{{Type: report.PackageDeb, Name: "libc6", Version: "2.36"}, {Type: report.PackageDeb, Name: "variant", Version: variant}}
			m, unchanged, err := meta(s, pkgs)
			if err != nil {
				return err
			}
			if unchanged {
				pkgs = nil
			}
			rep.Packages = &report.PackagesSection{SectionMeta: m, Packages: pkgs}
		case report.SectionArtifacts:
			arts := []report.Artifact{{Kind: report.ArtifactJar, Path: "/opt/app.jar", Name: "app", Method: report.MethodManifest}}
			m, unchanged, err := meta(s, arts)
			if err != nil {
				return err
			}
			if unchanged {
				arts = nil
			}
			rep.Artifacts = &report.ArtifactsSection{SectionMeta: m, Artifacts: arts}
		case report.SectionProcesses:
			procs := []report.Process{{PID: 1, User: "root", Exe: "/sbin/init", ExeSource: report.ExeFromCmdline, ExeState: report.ExeNormal}}
			m, unchanged, err := meta(s, procs)
			if err != nil {
				return err
			}
			if unchanged {
				procs = nil
			}
			rep.Processes = &report.ProcessesSection{SectionMeta: m, Processes: procs}
		case report.SectionContainers:
			cs := []report.Container{{ID: "c1", Name: "web", Runtime: "docker", Running: true, InitPID: 42, UpperDir: "/var/lib/docker/x", Coverage: report.CoverageFull}}
			m, unchanged, err := meta(s, []string{"c1"})
			if err != nil {
				return err
			}
			if unchanged {
				cs = nil
			}
			rep.Containers = &report.ContainersSection{SectionMeta: m, Containers: cs}
		}
	}
	c, _ := json.Marshal(cache)
	rep.Cache = c
	return report.Encode(os.Stdout, rep)
}
