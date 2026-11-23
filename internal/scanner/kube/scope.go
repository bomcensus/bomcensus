// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package kube

import (
	"fmt"
	"slices"

	corev1 "k8s.io/api/core/v1"

	"github.com/bomcensus/bomcensus/internal/report"
)

// scopeProcesses reduces a processes section collected inside one container
// of a pod to what belongs to that container.
//
//   - Unowned ports are dropped. A socket that no process of the container
//     holds belongs to another container of the pod or, with hostNetwork,
//     to the host.
//   - When the pod shares a PID namespace (hostPID, shareProcessNamespace)
//     the probe also sees processes of the host or of other containers.
//     Only those in the probe's mount namespace are kept; processes whose
//     mount namespace could not be read are left out and lower the
//     coverage. Without a shared PID namespace every visible process is the
//     container's, including ones that made a mount namespace of their own.
//
// The section digest stays the probe's, taken over everything it saw. It
// changes whenever the kept part changes, which is all change detection
// needs.
func scopeProcesses(sec *report.ProcessesSection, spec *corev1.PodSpec) {
	if sec == nil || sec.Unchanged {
		return
	}
	sec.UnownedPorts = nil
	if !spec.HostPID && (spec.ShareProcessNamespace == nil || !*spec.ShareProcessNamespace) {
		return
	}
	if sec.ProbeMountNS == 0 {
		degrade(sec, "mount namespace of the probe unknown, processes of other containers may be included")
		return
	}
	unknown := 0
	sec.Processes = slices.DeleteFunc(sec.Processes, func(p report.Process) bool {
		if p.MountNS == 0 {
			unknown++
		}
		return p.MountNS != sec.ProbeMountNS
	})
	if unknown > 0 {
		degrade(sec, fmt.Sprintf("mount namespace unreadable for %d processes, left out", unknown))
	}
}

func degrade(sec *report.ProcessesSection, reason string) {
	if sec.Coverage == report.CoverageNone {
		return
	}
	sec.Coverage = report.CoveragePartial
	if sec.Reason != "" {
		reason = sec.Reason + "; " + reason
	}
	sec.Reason = reason
}
