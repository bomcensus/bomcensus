// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package kube

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/bomcensus/bomcensus/agentproto/dto"
)

func TestNormalizeDigest(t *testing.T) {
	hex := strings.Repeat("0a", 32)
	for in, want := range map[string]string{
		"docker-pullable://nginx@sha256:" + hex:            "sha256:" + hex,
		"docker.io/library/nginx@sha256:" + hex:            "sha256:" + hex,
		"sha256:" + hex:                                    "sha256:" + hex,
		"docker://sha256:" + hex:                           "sha256:" + hex,
		"registry:5000/a/b@sha256:" + strings.ToUpper(hex): "sha256:" + hex,
		"":                          "",
		"nginx:1.27":                "",
		"sha256:" + hex[:62]:        "",
		"sha256:" + hex + "00":      "",
		"sha256:" + hex[:62] + "zz": "",
		"sha512:" + hex + hex:       "",
	} {
		if got := NormalizeDigest(in); got != want {
			t.Errorf("NormalizeDigest(%q) = %q, want %q", in, got, want)
		}
	}
}

func ctrl(kind, name string, uid types.UID) []metav1.OwnerReference {
	yes := true
	return []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: kind, Name: name, UID: uid, Controller: &yes}}
}

func tpl(labels map[string]string, images ...string) corev1.PodTemplateSpec {
	var cs []corev1.Container
	for i, img := range images {
		cs = append(cs, corev1.Container{Name: fmt.Sprintf("c%d", i), Image: img})
	}
	return corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: corev1.PodSpec{Containers: cs}}
}

func runningPod(ns, name string, owners []metav1.OwnerReference, labels map[string]string, image string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID("uid-" + name), OwnerReferences: owners, Labels: labels},
		Spec: corev1.PodSpec{
			NodeName:       "n1",
			InitContainers: []corev1.Container{{Name: "init", Image: "busybox"}},
			Containers:     []corev1.Container{{Name: "c0", Image: image}},
		},
		Status: corev1.PodStatus{
			Phase:                 corev1.PodRunning,
			InitContainerStatuses: []corev1.ContainerStatus{{Name: "init", ImageID: "sha256:" + strings.Repeat("ee", 32)}},
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "c0", Ready: true, ImageID: "docker.io/" + image + "@sha256:" + strings.Repeat("1f", 32),
				State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			}},
		},
	}
}

func i32(n int32) *int32 { return &n }

// clusterObjects builds a cluster with every owner shape Sync resolves.
func clusterObjects() []k8sruntime.Object {
	return []k8sruntime.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app", Labels: map[string]string{"team": "a"}}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1", Labels: map[string]string{labelArch: "arm64", labelOS: "linux"}}},

		// Deployment → ReplicaSet → pods
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "web", UID: "d-web", Labels: map[string]string{"tier": "front"}},
			Spec: appsv1.DeploymentSpec{Replicas: i32(3), Template: tpl(map[string]string{"app": "web"}, "nginx:1.27")}},
		&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "web-abc", UID: "rs-web", OwnerReferences: ctrl(KindDeployment, "web", "d-web")},
			Spec: appsv1.ReplicaSetSpec{Replicas: i32(3), Template: tpl(map[string]string{"app": "web"}, "nginx:1.27")}},
		runningPod("app", "web-abc-1", ctrl(KindReplicaSet, "web-abc", "rs-web"), map[string]string{"app": "web"}, "nginx:1.27"),
		runningPod("app", "web-abc-2", ctrl(KindReplicaSet, "web-abc", "rs-web"), map[string]string{"app": "web"}, "nginx:1.27"),

		// A Deployment scaled to zero has no pods but is a workload.
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "idle", UID: "d-idle"},
			Spec: appsv1.DeploymentSpec{Replicas: i32(0), Template: tpl(nil, "idle:1")}},

		// CronJob → Job → pod
		&batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "nightly", UID: "cj-n"},
			Spec: batchv1.CronJobSpec{JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{Template: tpl(nil, "backup:2")}}}},
		&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "nightly-1", UID: "job-n", OwnerReferences: ctrl(KindCronJob, "nightly", "cj-n")},
			Spec: batchv1.JobSpec{Template: tpl(nil, "backup:2")}},
		runningPod("app", "nightly-1-x", ctrl(KindJob, "nightly-1", "job-n"), nil, "backup:2"),

		// StatefulSet and DaemonSet
		&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "db", UID: "sts-db"},
			Spec: appsv1.StatefulSetSpec{Replicas: i32(2), Template: tpl(nil, "postgres:18")}},
		runningPod("app", "db-0", ctrl(KindStatefulSet, "db", "sts-db"), nil, "postgres:18"),
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "agent", UID: "ds-a"},
			Spec: appsv1.DaemonSetSpec{Template: tpl(nil, "agent:1")}, Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 4}},
		runningPod("kube-system", "agent-x", ctrl(KindDaemonSet, "agent", "ds-a"), nil, "agent:1"),

		// Bare pod
		runningPod("app", "solo", nil, map[string]string{"app": "solo"}, "alpine:3.20"),

		// Custom resource owning a ReplicaSet, and one owning a pod directly
		&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "ro-123", UID: "rs-ro", OwnerReferences: ctrl("Rollout", "ro", "crd-ro")},
			Spec: appsv1.ReplicaSetSpec{Replicas: i32(2), Template: tpl(nil, "ro:1")}},
		runningPod("app", "ro-123-a", ctrl(KindReplicaSet, "ro-123", "rs-ro"), map[string]string{"app": "ro"}, "ro:1"),
		runningPod("app", "ro-123-b", ctrl(KindReplicaSet, "ro-123", "rs-ro"), map[string]string{"app": "ro"}, "ro:1"),
		runningPod("app", "vm-1", ctrl("VirtualMachineInstance", "vm", "crd-vm"), nil, "virt-launcher:1"),

		// Static pods mirrored by the kubelet are owned by their node.
		runningPod("kube-system", "etcd-n1", nodeOwner("n1"), map[string]string{"component": "etcd"}, "etcd:3.5"),
		runningPod("kube-system", "kube-proxy-n1", nodeOwner("n1"), map[string]string{"component": "kube-proxy"}, "kube-proxy:1.31"),
	}
}

func nodeOwner(name string) []metav1.OwnerReference {
	yes := true
	return []metav1.OwnerReference{{APIVersion: "v1", Kind: "Node", Name: name, UID: types.UID("node-" + name), Controller: &yes}}
}

func workloadIndex(inv *Inventory) map[string]Workload {
	out := map[string]Workload{}
	for _, w := range inv.Workloads {
		out[w.Namespace+"/"+w.Kind+"/"+w.Name] = w
	}
	return out
}

func podIndex(inv *Inventory) map[string]Pod {
	out := map[string]Pod{}
	for _, p := range inv.Pods {
		out[p.Namespace+"/"+p.Name] = p
	}
	return out
}

func TestSyncOwnerResolution(t *testing.T) {
	c := NewClientWith(fake.NewClientset(clusterObjects()...), nil)
	inv, err := Sync(context.Background(), c, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Warnings) != 0 {
		t.Errorf("warnings %v", inv.Warnings)
	}
	ws := workloadIndex(inv)
	wantWorkloads := map[string]int{
		"app/Deployment/web":            3,
		"app/Deployment/idle":           0,
		"app/CronJob/nightly":           1,
		"app/StatefulSet/db":            2,
		"kube-system/DaemonSet/agent":   4,
		"app/Pod/solo":                  1,
		"app/Rollout/ro":                2,
		"app/VirtualMachineInstance/vm": 1,
		"kube-system/Pod/etcd-n1":       1,
		"kube-system/Pod/kube-proxy-n1": 1,
	}
	if len(ws) != len(wantWorkloads) {
		t.Errorf("workloads %v", slices.Sorted(maps.Keys(ws)))
	}
	for k, replicas := range wantWorkloads {
		w, ok := ws[k]
		if !ok {
			t.Errorf("missing workload %s", k)
			continue
		}
		if w.Replicas != replicas {
			t.Errorf("%s replicas %d, want %d", k, w.Replicas, replicas)
		}
		if w.ExcludedBy != "" {
			t.Errorf("%s excluded by %q", k, w.ExcludedBy)
		}
	}
	if w := ws["app/Deployment/web"]; w.UID != "d-web" || w.Labels["app"] != "web" || w.Labels["tier"] != "front" ||
		len(w.Containers) != 1 || w.Containers[0].Image != "nginx:1.27" {
		t.Errorf("web workload %+v", w)
	}
	if w := ws["kube-system/Pod/etcd-n1"]; w.UID != "uid-etcd-n1" || w.Labels["component"] != "etcd" || len(w.Containers) != 1 || w.Containers[0].Image != "etcd:3.5" {
		t.Errorf("static pod workload %+v", w)
	}
	if w := ws["app/Rollout/ro"]; w.UID != "crd-ro" || w.Labels["app"] != "ro" || len(w.Containers) != 1 || w.Containers[0].Image != "ro:1" {
		t.Errorf("rollout workload %+v", w)
	}

	ps := podIndex(inv)
	wantPods := map[string]string{
		"app/web-abc-1":             "Deployment/web",
		"app/web-abc-2":             "Deployment/web",
		"app/nightly-1-x":           "CronJob/nightly",
		"app/db-0":                  "StatefulSet/db",
		"kube-system/agent-x":       "DaemonSet/agent",
		"app/solo":                  "Pod/solo",
		"app/ro-123-a":              "Rollout/ro",
		"app/ro-123-b":              "Rollout/ro",
		"app/vm-1":                  "VirtualMachineInstance/vm",
		"kube-system/etcd-n1":       "Pod/etcd-n1",
		"kube-system/kube-proxy-n1": "Pod/kube-proxy-n1",
	}
	if len(ps) != len(wantPods) {
		t.Errorf("pods %v", slices.Sorted(maps.Keys(ps)))
	}
	for k, wl := range wantPods {
		p, ok := ps[k]
		if !ok {
			t.Errorf("missing pod %s", k)
			continue
		}
		if p.WorkloadKind+"/"+p.WorkloadName != wl {
			t.Errorf("%s workload %s/%s, want %s", k, p.WorkloadKind, p.WorkloadName, wl)
		}
		if p.Arch != "arm64" || p.OS != "linux" || p.Node != "n1" || p.Phase != corev1.PodRunning {
			t.Errorf("%s node data %+v", k, p)
		}
		if len(p.Containers) != 1 || p.Containers[0].Name != "c0" || p.Containers[0].ImageDigest != "sha256:"+strings.Repeat("1f", 32) || !p.Containers[0].Running {
			t.Errorf("%s containers %+v", k, p.Containers)
		}
	}
	if len(inv.Namespaces) != 2 || inv.Namespaces[0].Name != "app" || inv.Namespaces[0].Labels["team"] != "a" {
		t.Errorf("namespaces %+v", inv.Namespaces)
	}

	pl := inv.Payload("cluster-1", "job-1")
	if pl.ClusterId != "cluster-1" || *pl.JobId != "job-1" || len(pl.Workloads) != len(inv.Workloads) || len(pl.Pods) != len(inv.Pods) {
		t.Errorf("payload %+v", pl)
	}
	for _, p := range pl.Pods {
		if p.Phase != dto.K8sPodPhaseRunning || len(p.Containers) != 1 || p.Containers[0].ImageDigest == nil {
			t.Errorf("payload pod %+v", p)
		}
	}
}

func TestSyncFilterExcludes(t *testing.T) {
	c := NewClientWith(fake.NewClientset(clusterObjects()...), nil)
	inv, err := Sync(context.Background(), c, Filter{
		NamespaceExclude: []string{"kube-*"},
		LabelExclude:     []string{"app=ro"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ws := workloadIndex(inv)
	if got := ws["kube-system/DaemonSet/agent"].ExcludedBy; got != "namespace_exclude: kube-*" {
		t.Errorf("agent excluded by %q", got)
	}
	if got := ws["app/Rollout/ro"].ExcludedBy; got != "label_exclude: app=ro" {
		t.Errorf("rollout excluded by %q", got)
	}
	if got := ws["app/Deployment/web"].ExcludedBy; got != "" {
		t.Errorf("web excluded by %q", got)
	}
	ps := podIndex(inv)
	for _, k := range []string{"kube-system/agent-x", "app/ro-123-a", "app/ro-123-b"} {
		if _, ok := ps[k]; ok {
			t.Errorf("pod %s of an excluded workload collected", k)
		}
	}
	if _, ok := ps["app/web-abc-1"]; !ok {
		t.Error("pod of an included workload missing")
	}
}

func TestSyncForbiddenResources(t *testing.T) {
	cs := fake.NewClientset(clusterObjects()...)
	for _, res := range []string{"nodes", "jobs", "deployments", "namespaces"} {
		cs.PrependReactor("list", res, func(k8stesting.Action) (bool, k8sruntime.Object, error) {
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: res}, "", errors.New("denied"))
		})
	}
	inv, err := Sync(context.Background(), NewClientWith(cs, nil), Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Warnings) != 4 {
		t.Errorf("warnings %v", inv.Warnings)
	}
	ps := podIndex(inv)
	// Without Jobs the Job named by the pod is the top; without Deployments
	// the ReplicaSet's owner reference still names the Deployment.
	if p := ps["app/nightly-1-x"]; p.WorkloadKind != KindJob || p.WorkloadName != "nightly-1" {
		t.Errorf("nightly pod workload %s/%s", p.WorkloadKind, p.WorkloadName)
	}
	if p := ps["app/web-abc-1"]; p.WorkloadKind != KindDeployment || p.WorkloadName != "web" || p.Arch != "" {
		t.Errorf("web pod %+v", p)
	}
	if w := workloadIndex(inv)["app/Deployment/web"]; w.Replicas != 2 || w.Containers[0].Image != "nginx:1.27" {
		t.Errorf("web workload %+v", w)
	}
	if len(inv.Namespaces) != 2 {
		t.Errorf("namespaces derived from pods: %+v", inv.Namespaces)
	}
}

func TestSyncPodsForbidden(t *testing.T) {
	cs := fake.NewClientset()
	cs.PrependReactor("list", "pods", func(k8stesting.Action) (bool, k8sruntime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", errors.New("denied"))
	})
	if _, err := Sync(context.Background(), NewClientWith(cs, nil), Filter{}); err == nil {
		t.Fatal("no error")
	}
}

func TestWritableDirs(t *testing.T) {
	p := &corev1.Pod{Spec: corev1.PodSpec{
		Volumes: []corev1.Volume{
			{Name: "e1", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
			{Name: "e2", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}}},
			{Name: "cm", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{}}},
		},
		Containers: []corev1.Container{{Name: "c", VolumeMounts: []corev1.VolumeMount{
			{Name: "e1", MountPath: "/scratch"},
			{Name: "e2", MountPath: "/ro", ReadOnly: true},
			{Name: "e2", MountPath: "/sub", SubPath: "x"},
			{Name: "e2", MountPath: "/cache"},
			{Name: "cm", MountPath: "/etc/cfg"},
		}}},
	}}
	if got := writableDirs(p, &p.Spec.Containers[0]); !slices.Equal(got, []string{"/scratch", "/cache"}) {
		t.Errorf("writable dirs %v", got)
	}
}

func TestHostPathDirs(t *testing.T) {
	p := &corev1.Pod{Spec: corev1.PodSpec{
		Volumes: []corev1.Volume{
			{Name: "root", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/"}}},
			{Name: "logs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log"}}},
			{Name: "e1", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		},
		Containers: []corev1.Container{{Name: "c", VolumeMounts: []corev1.VolumeMount{
			{Name: "root", MountPath: "/host/", ReadOnly: true},
			{Name: "e1", MountPath: "/scratch"},
			{Name: "logs", MountPath: "/var/log/node", SubPath: "pods"},
		}}},
	}}
	if got := hostPathDirs(p, &p.Spec.Containers[0]); !slices.Equal(got, []string{"/host", "/var/log/node"}) {
		t.Errorf("host path dirs %v", got)
	}
}

func TestListAllPaging(t *testing.T) {
	pages := map[string]struct {
		items []int
		next  string
	}{"": {[]int{1, 2}, "a"}, "a": {[]int{3}, "b"}, "b": {[]int{4}, ""}}
	expired := true
	var seen []metav1.ListOptions
	got, err := listAll(context.Background(), func(_ context.Context, o metav1.ListOptions) ([]int, string, error) {
		seen = append(seen, o)
		if o.Continue == "b" && expired {
			expired = false
			return nil, "", apierrors.NewResourceExpired("expired")
		}
		if o.Limit == 0 {
			return []int{1, 2, 3, 4}, "", nil
		}
		p := pages[o.Continue]
		return p.items, p.next, nil
	})
	if err != nil || !slices.Equal(got, []int{1, 2, 3, 4}) {
		t.Fatalf("got %v err %v", got, err)
	}
	if seen[0].Limit != pageSize || seen[1].Continue != "a" || seen[len(seen)-1].Limit != 0 {
		t.Errorf("requests %+v", seen)
	}
}
