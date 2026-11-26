// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package probe

import (
	"bytes"
	"context"
	"testing"

	"github.com/bomcensus/bomcensus/internal/report"
)

func TestRunWindows(t *testing.T) {
	rep, err := Run(context.Background(), report.Request{Policy: report.DefaultPolicy()}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Host == nil || rep.Host.OS.Family != "windows" || rep.Host.Hostname == "" {
		t.Fatalf("host = %+v", rep.Host)
	}
	for name, m := range map[string]*report.SectionMeta{
		report.SectionPackages:   &rep.Packages.SectionMeta,
		report.SectionArtifacts:  &rep.Artifacts.SectionMeta,
		report.SectionProcesses:  &rep.Processes.SectionMeta,
		report.SectionContainers: &rep.Containers.SectionMeta,
	} {
		if m.Coverage != report.CoverageNone || m.Reason != notCollectedReason || m.Digest != "" {
			t.Errorf("%s: %+v", name, m)
		}
	}
	var buf bytes.Buffer
	if err := report.Encode(&buf, rep); err != nil {
		t.Fatal(err)
	}
	back, err := report.Decode(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if back.Host.OS.Family != "windows" {
		t.Errorf("decoded host = %+v", back.Host)
	}

	known := map[string]string{report.SectionHost: rep.Host.Digest}
	rep2, err := Run(context.Background(), report.Request{Sections: []string{report.SectionHost}, KnownDigests: known, Policy: report.DefaultPolicy()}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !rep2.Host.Unchanged || rep2.Packages != nil {
		t.Errorf("second run: %+v", rep2)
	}
}

func TestSandboxWindows(t *testing.T) {
	res := ApplySandbox(nil)
	if len(res.Steps) != 1 || res.Steps[0].Status != StepSkipped {
		t.Errorf("steps = %+v", res.Steps)
	}
	// The probe itself is not restricted; the version command check
	// runs or says why not (the test binary's directory may not be
	// readable for AppContainers).
	c := CheckSandbox()
	if len(c) < 2 || c[0].Name != "sandbox" || c[0].OK || c[1].Name != "version command" {
		t.Errorf("checks = %+v", c)
	}
	for _, x := range c[1:] {
		t.Logf("%-40s %-5v %s", x.Name, x.OK, x.Detail)
		if c[1].OK && !x.OK {
			t.Errorf("%s: %s", x.Name, x.Detail)
		}
	}
}
