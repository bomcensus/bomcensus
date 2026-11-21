// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package kube

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/bomcensus/bomcensus/internal/report"
)

func planPod(ns, name, kind, wl, node, arch string, ready bool, containers ...Container) Pod {
	return Pod{Namespace: ns, Name: name, WorkloadKind: kind, WorkloadName: wl, Node: node, OS: "linux", Arch: arch,
		Phase: corev1.PodRunning, Containers: containers}
}

func ctr(name, digest string, ready bool) Container {
	return Container{Name: name, ImageDigest: digest, Ready: ready, Running: true}
}

type planned struct{ pod, container, kind string }

func summarize(ts []ExecTarget) []planned {
	var out []planned
	for _, t := range ts {
		kind := "full"
		if slices.Equal(t.Sections, ProcessSections) {
			kind = "proc"
		} else if !slices.Equal(t.Sections, FullSections) {
			kind = fmt.Sprint(t.Sections)
		}
		out = append(out, planned{t.Pod, t.Container, kind})
	}
	return out
}

func TestPlanRules(t *testing.T) {
	const dA, dB, dC = "sha256:aa", "sha256:bb", "sha256:cc"
	inv := &Inventory{
		Workloads: []Workload{
			{Namespace: "app", Kind: KindDeployment, Name: "web"},
			{Namespace: "app", Kind: KindDeployment, Name: "api"},
			{Namespace: "app", Kind: KindDeployment, Name: "zeta"},
			{Namespace: "app", Kind: KindDeployment, Name: "off", ExcludedBy: "label_exclude: x"},
		},
		Pods: []Pod{
			// web: three replicas with a sidecar; web-a is not ready, so
			// web-b gets the full collection of the main container.
			planPod("app", "web-a", KindDeployment, "web", "n1", "amd64", false, ctr("main", dA, false), ctr("proxy", dC, true)),
			planPod("app", "web-b", KindDeployment, "web", "n1", "amd64", true, ctr("main", dA, true), ctr("proxy", dC, true)),
			planPod("app", "web-c", KindDeployment, "web", "n2", "amd64", true, ctr("main", dA, true), ctr("proxy", dC, true)),
			// api: known digest → processes only everywhere; one replica
			// mid-rollout with a new digest gets a full collection.
			planPod("app", "api-a", KindDeployment, "api", "n1", "amd64", true, ctr("main", dB, true)),
			planPod("app", "api-b", KindDeployment, "api", "n2", "amd64", true, ctr("main", dB, true)),
			planPod("app", "api-new", KindDeployment, "api", "n2", "amd64", true, ctr("main", "sha256:new", true)),
			// zeta: same digest as web main. On another architecture it gets
			// one more full collection; on amd64 it shares web's.
			planPod("app", "zeta-arm", KindDeployment, "zeta", "n3", "arm64", true, ctr("main", dA, true)),
			planPod("app", "zeta-amd", KindDeployment, "zeta", "n1", "amd64", true, ctr("main", dA, true)),
			// excluded workload, a not running container, a pending pod and a
			// container without digest
			planPod("app", "off-a", KindDeployment, "off", "n1", "amd64", true, ctr("main", "sha256:off", true)),
			planPod("app", "solo", KindPod, "solo", "n1", "amd64", true, ctr("main", "", true), Container{Name: "dead", ImageDigest: "sha256:dead"}),
			{Namespace: "app", Name: "pending", WorkloadKind: KindPod, WorkloadName: "pending", Phase: corev1.PodPending,
				Containers: []Container{ctr("main", "sha256:p", false)}},
			{Namespace: "win", Name: "w", WorkloadKind: KindPod, WorkloadName: "w", OS: "windows", Phase: corev1.PodRunning,
				Containers: []Container{ctr("main", "sha256:w", true)}},
		},
	}
	got := summarize(Plan(inv, map[string]bool{dB: true}, PlanOptions{}))
	want := []planned{
		{"api-new", "main", "full"},
		{"web-b", "main", "full"},
		{"web-a", "proxy", "full"},
		{"zeta-arm", "main", "full"},
		{"solo", "main", "full"},
		{"api-a", "main", "proc"},
		{"api-b", "main", "proc"},
		{"web-c", "main", "proc"},
		{"web-a", "main", "proc"},
		{"web-b", "proxy", "proc"},
		{"web-c", "proxy", "proc"},
		{"zeta-amd", "main", "proc"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("plan\n got %v\nwant %v", got, want)
	}
}

func TestPlanOptions(t *testing.T) {
	inv := &Inventory{Pods: []Pod{
		planPod("app", "a", KindDeployment, "web", "n1", "amd64", true, ctr("main", "sha256:k", true)),
		planPod("app", "b", KindDeployment, "web", "n1", "amd64", true, ctr("main", "sha256:k", true)),
	}}
	known := map[string]bool{"sha256:k": true}
	if got := summarize(Plan(inv, known, PlanOptions{})); !slices.Equal(got, []planned{{"a", "main", "proc"}, {"b", "main", "proc"}}) {
		t.Errorf("known digest: %v", got)
	}
	if got := summarize(Plan(inv, known, PlanOptions{FullPerWorkload: true})); !slices.Equal(got, []planned{{"a", "main", "full"}, {"b", "main", "proc"}}) {
		t.Errorf("full per workload: %v", got)
	}
	ts := Plan(inv, nil, PlanOptions{FullSections: []string{report.SectionPackages}})
	if !slices.Equal(ts[0].Sections, []string{report.SectionPackages}) || ts[0].Arch != "amd64" || ts[0].Node != "n1" || ts[0].ImageDigest != "sha256:k" {
		t.Errorf("target %+v", ts[0])
	}
}

func TestRunPlanLimits(t *testing.T) {
	var targets []ExecTarget
	for i := range 40 {
		targets = append(targets, ExecTarget{Namespace: fmt.Sprintf("ns%d", i%3), Node: fmt.Sprintf("n%d", i%4), Pod: fmt.Sprintf("p%d", i)})
	}
	lim := Limits{Total: 5, PerNode: 2, PerNamespace: 2}
	var mu sync.Mutex
	nodes, nss := map[string]int{}, map[string]int{}
	var total, maxTotal, maxNode, maxNS int
	collect := func(ctx context.Context, t ExecTarget) (*report.Report, ContainerOutcome, error) {
		mu.Lock()
		total++
		nodes[t.Node]++
		nss[t.Namespace]++
		maxTotal = max(maxTotal, total)
		maxNode = max(maxNode, nodes[t.Node])
		maxNS = max(maxNS, nss[t.Namespace])
		mu.Unlock()
		time.Sleep(5 * time.Millisecond)
		mu.Lock()
		total--
		nodes[t.Node]--
		nss[t.Namespace]--
		mu.Unlock()
		return nil, ContainerOutcome{Coverage: "full"}, nil
	}
	var inDone atomic.Int32
	seen := map[string]int{}
	err := RunPlan(context.Background(), targets, lim, collect, func(r Result) {
		if inDone.Add(1) != 1 {
			t.Error("done called concurrently")
		}
		seen[r.Target.Pod]++
		inDone.Add(-1)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != len(targets) {
		t.Errorf("%d targets finished, want %d", len(seen), len(targets))
	}
	for p, n := range seen {
		if n != 1 {
			t.Errorf("%s finished %d times", p, n)
		}
	}
	if maxTotal > lim.Total || maxNode > lim.PerNode || maxNS > lim.PerNamespace {
		t.Errorf("max total %d node %d namespace %d exceed %+v", maxTotal, maxNode, maxNS, lim)
	}
	if maxTotal < 2 {
		t.Errorf("no concurrency (max %d)", maxTotal)
	}
}

func TestRunPlanCancel(t *testing.T) {
	var targets []ExecTarget
	for i := range 10 {
		targets = append(targets, ExecTarget{Namespace: "ns", Node: "n", Pod: fmt.Sprintf("p%d", i)})
	}
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{}, 10)
	collect := func(ctx context.Context, t ExecTarget) (*report.Report, ContainerOutcome, error) {
		started <- struct{}{}
		<-ctx.Done()
		return nil, ContainerOutcome{Coverage: "failed", Reason: "canceled"}, ctx.Err()
	}
	go func() { <-started; cancel() }()
	var results []Result
	err := RunPlan(ctx, targets, Limits{Total: 1, PerNode: 1, PerNamespace: 1}, collect, func(r Result) { results = append(results, r) })
	if err != context.Canceled {
		t.Errorf("err %v", err)
	}
	if len(results) != len(targets) {
		t.Fatalf("%d results", len(results))
	}
	if len(started) != 0 {
		t.Errorf("%d more targets started after cancel", len(started))
	}
	for _, r := range results {
		if r.Err == nil || r.Outcome.Coverage != "failed" {
			t.Errorf("%s: %+v", r.Target.Pod, r)
		}
	}
}
