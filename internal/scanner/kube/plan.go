// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package kube

import (
	"cmp"
	"context"
	"slices"

	corev1 "k8s.io/api/core/v1"

	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/report"
)

// PlanOptions tune Plan.
type PlanOptions struct {
	// FullSections and ProcessSections override the package defaults.
	FullSections    []string
	ProcessSections []string
	// FullPerWorkload gives every workload container one full collection
	// even when its image digest is known, to see files added at run time.
	FullPerWorkload bool
}

// Plan decides what to collect from the running containers of the included
// workloads (ARCH 4.2). Per workload container, one running pod gets a full
// collection if its image digest is not in known and not already planned
// for a full collection on the same architecture (an image index digest
// covers several architectures); every other running replica gets the
// process section only. A container without a digest gets one full
// collection per workload container. Ready containers are preferred for the
// full collection. Pods on nodes with an operating system other than Linux
// are skipped.
//
// Full targets come first, then process-only targets.
func Plan(inv *Inventory, known map[string]bool, opts PlanOptions) []ExecTarget {
	full := opts.FullSections
	if len(full) == 0 {
		full = FullSections
	}
	procs := opts.ProcessSections
	if len(procs) == 0 {
		procs = ProcessSections
	}
	excluded := map[workloadKey]bool{}
	for _, w := range inv.Workloads {
		if w.ExcludedBy != "" {
			excluded[workloadKey{w.Namespace, w.Kind, w.Name}] = true
		}
	}

	type groupKey struct{ namespace, kind, name, container string }
	type cand struct {
		pod *Pod
		c   *Container
	}
	groups := map[groupKey][]cand{}
	var keys []groupKey
	for i := range inv.Pods {
		p := &inv.Pods[i]
		if p.Phase != corev1.PodRunning || (p.OS != "" && p.OS != "linux") {
			continue
		}
		if excluded[workloadKey{p.Namespace, p.WorkloadKind, p.WorkloadName}] {
			continue
		}
		for j := range p.Containers {
			c := &p.Containers[j]
			if !c.Running {
				continue
			}
			k := groupKey{p.Namespace, p.WorkloadKind, p.WorkloadName, c.Name}
			if _, ok := groups[k]; !ok {
				keys = append(keys, k)
			}
			groups[k] = append(groups[k], cand{p, c})
		}
	}
	slices.SortFunc(keys, func(a, b groupKey) int {
		return cmp.Or(cmp.Compare(a.namespace, b.namespace), cmp.Compare(a.kind, b.kind),
			cmp.Compare(a.name, b.name), cmp.Compare(a.container, b.container))
	})

	planned := map[string]bool{}
	var fullT, procT []ExecTarget
	for _, k := range keys {
		cs := groups[k]
		slices.SortFunc(cs, func(a, b cand) int {
			if a.c.Ready != b.c.Ready {
				if a.c.Ready {
					return -1
				}
				return 1
			}
			return cmp.Compare(a.pod.Name, b.pod.Name)
		})
		groupFull := false
		for _, x := range cs {
			d := x.c.ImageDigest
			isFull := false
			switch {
			case d == "":
				isFull = !groupFull
			default:
				isFull = !known[d] && !planned[d+"|"+x.pod.Arch]
			}
			if opts.FullPerWorkload && !groupFull {
				isFull = true
			}
			t := ExecTarget{
				Namespace: x.pod.Namespace, Pod: x.pod.Name, Container: x.c.Name,
				Node: x.pod.Node, OS: x.pod.OS, Arch: x.pod.Arch,
				WorkloadKind: k.kind, WorkloadName: k.name,
				ImageRef: x.c.ImageRef, ImageDigest: d,
			}
			if isFull {
				groupFull = true
				if d != "" {
					planned[d+"|"+x.pod.Arch] = true
				}
				t.Sections = slices.Clone(full)
				fullT = append(fullT, t)
			} else {
				t.Sections = slices.Clone(procs)
				procT = append(procT, t)
			}
		}
	}
	return append(fullT, procT...)
}

// Limits bound concurrent exec sessions. Zero fields take the defaults.
type Limits struct {
	Total        int
	PerNode      int
	PerNamespace int
}

// DefaultLimits keep the load on any node and namespace low (ARCH 4.5).
var DefaultLimits = Limits{Total: 8, PerNode: 1, PerNamespace: 2}

// Result is one finished target of RunPlan.
type Result struct {
	Target  ExecTarget
	Report  *report.Report
	Outcome ContainerOutcome
	Err     error
}

// CollectFunc collects one target, normally a closure over CollectContainer.
type CollectFunc func(ctx context.Context, t ExecTarget) (*report.Report, ContainerOutcome, error)

// RunPlan runs collect for every target within the limits, in order where
// the limits allow. done is called once per target, never concurrently.
// When ctx ends, targets not yet started are reported with ctx.Err() and
// RunPlan returns ctx.Err() after the running ones finished.
func RunPlan(ctx context.Context, targets []ExecTarget, lim Limits, collect CollectFunc, done func(Result)) error {
	if lim.Total <= 0 {
		lim.Total = DefaultLimits.Total
	}
	if lim.PerNode <= 0 {
		lim.PerNode = DefaultLimits.PerNode
	}
	if lim.PerNamespace <= 0 {
		lim.PerNamespace = DefaultLimits.PerNamespace
	}
	pending := slices.Clone(targets)
	byNode := map[string]int{}
	byNS := map[string]int{}
	running := 0
	finished := make(chan Result)

	for len(pending) > 0 || running > 0 {
		if ctx.Err() == nil {
			for i := 0; i < len(pending) && running < lim.Total; {
				t := pending[i]
				if byNode[t.Node] >= lim.PerNode || byNS[t.Namespace] >= lim.PerNamespace {
					i++
					continue
				}
				pending = slices.Delete(pending, i, i+1)
				byNode[t.Node]++
				byNS[t.Namespace]++
				running++
				go func() {
					r, o, err := collect(ctx, t)
					finished <- Result{Target: t, Report: r, Outcome: o, Err: err}
				}()
			}
		} else {
			for _, t := range pending {
				done(Result{Target: t, Outcome: ContainerOutcome{Coverage: agentapi.CoverageFailed, Reason: "canceled", ExitCode: -1}, Err: ctx.Err()})
			}
			pending = nil
		}
		if running == 0 {
			continue
		}
		select {
		case r := <-finished:
			running--
			byNode[r.Target.Node]--
			byNS[r.Target.Namespace]--
			done(r)
		case <-ctx.Done():
			// Loop once more to flush the pending targets; then keep waiting
			// for the running ones.
			if len(pending) == 0 {
				r := <-finished
				running--
				byNode[r.Target.Node]--
				byNS[r.Target.Namespace]--
				done(r)
			}
		}
	}
	return ctx.Err()
}
