// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package kube

import (
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/bomcensus/bomcensus/internal/report"
)

func scopeSection(probeNS uint64) *report.ProcessesSection {
	return &report.ProcessesSection{
		SectionMeta:  report.SectionMeta{Coverage: report.CoverageFull, Digest: "d1"},
		ProbeMountNS: probeNS,
		Processes: []report.Process{
			{PID: 1, Exe: "/app", MountNS: 10, Listen: []report.Listen{{Proto: "tcp", Address: "0.0.0.0", Port: 8080}}},
			{PID: 2, Exe: "/sandboxed", MountNS: 11},
			{PID: 3, Exe: "/usr/sbin/sshd", MountNS: 0},
		},
		UnownedPorts: []report.UnownedPort{{Listen: report.Listen{Proto: "tcp", Address: "0.0.0.0", Port: 22}}},
	}
}

func pidsOf(sec *report.ProcessesSection) []int {
	var out []int
	for _, p := range sec.Processes {
		out = append(out, p.PID)
	}
	return out
}

func TestScopeProcesses(t *testing.T) {
	share := true
	cases := []struct {
		name     string
		spec     corev1.PodSpec
		probeNS  uint64
		pids     []int
		coverage report.Coverage
		reason   string
	}{
		{"own pid namespace", corev1.PodSpec{}, 10, []int{1, 2, 3}, report.CoverageFull, ""},
		{"host network", corev1.PodSpec{HostNetwork: true}, 10, []int{1, 2, 3}, report.CoverageFull, ""},
		{"host pid", corev1.PodSpec{HostPID: true}, 10, []int{1}, report.CoveragePartial, "unreadable for 1 processes"},
		{"shared pid namespace", corev1.PodSpec{ShareProcessNamespace: &share}, 10, []int{1}, report.CoveragePartial, "unreadable for 1 processes"},
		{"probe namespace unknown", corev1.PodSpec{HostPID: true}, 0, []int{1, 2, 3}, report.CoveragePartial, "probe unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sec := scopeSection(c.probeNS)
			scopeProcesses(sec, &c.spec)
			if len(sec.UnownedPorts) != 0 {
				t.Errorf("unowned ports kept: %+v", sec.UnownedPorts)
			}
			if got := pidsOf(sec); !slices.Equal(got, c.pids) {
				t.Errorf("pids %v, want %v", got, c.pids)
			}
			if sec.Coverage != c.coverage || !strings.Contains(sec.Reason, c.reason) {
				t.Errorf("coverage %q reason %q", sec.Coverage, sec.Reason)
			}
			if sec.Digest != "d1" {
				t.Errorf("digest %q", sec.Digest)
			}
		})
	}
}

func TestScopeProcessesUnchanged(t *testing.T) {
	sec := &report.ProcessesSection{SectionMeta: report.SectionMeta{Unchanged: true, Coverage: report.CoverageFull}}
	scopeProcesses(sec, &corev1.PodSpec{HostPID: true})
	if sec.Coverage != report.CoverageFull || sec.Reason != "" {
		t.Errorf("unchanged section altered: %+v", sec)
	}
	scopeProcesses(nil, &corev1.PodSpec{HostPID: true})
}
