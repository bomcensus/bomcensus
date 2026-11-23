// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package kube

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
)

// Workload kinds produced by owner resolution. Owners of other kinds (custom
// resources, ReplicationController) are kept with the kind from the owner
// reference.
const (
	KindPod         = "Pod"
	KindDeployment  = "Deployment"
	KindReplicaSet  = "ReplicaSet"
	KindStatefulSet = "StatefulSet"
	KindDaemonSet   = "DaemonSet"
	KindJob         = "Job"
	KindCronJob     = "CronJob"
)

// Node labels read for the architecture and operating system.
const (
	labelArch = "kubernetes.io/arch"
	labelOS   = "kubernetes.io/os"
)

const (
	pageSize      = 500
	maxOwnerDepth = 16
)

// Inventory is a snapshot of one cluster after filtering.
type Inventory struct {
	CollectedAt   time.Time
	ServerVersion string
	Namespaces    []Namespace
	// Workloads holds every top-level controller, including excluded ones.
	Workloads []Workload
	// Pods holds the pods of included workloads only.
	Pods []Pod
	// Warnings lists resources that could not be read (missing RBAC, for
	// example) and how that limited the inventory.
	Warnings []string
}

type Namespace struct {
	Name        string
	Labels      map[string]string
	Annotations map[string]string
}

// Workload is a top-level controller, or a pod without owner.
type Workload struct {
	UID       string
	Namespace string
	Kind      string
	Name      string
	// Replicas is the desired count when the kind has one, otherwise the
	// number of pods seen.
	Replicas int
	// Labels and Annotations are those the filter was evaluated against: the
	// pod template's, overlaid with the controller's own metadata. For
	// owners that could not be read (custom resources) they come from the
	// first pod.
	Labels      map[string]string
	Annotations map[string]string
	// Containers are the regular containers of the pod template.
	Containers []TemplateContainer
	// ExcludedBy names the filter rule that excluded the workload.
	ExcludedBy string
}

type TemplateContainer struct {
	Name  string
	Image string
}

type Pod struct {
	UID          string
	Namespace    string
	Name         string
	WorkloadKind string
	WorkloadName string
	Node         string
	// OS and Arch come from the node labels; empty when the node could not
	// be read.
	OS         string
	Arch       string
	Phase      corev1.PodPhase
	StartedAt  time.Time
	Containers []Container
}

type Container struct {
	Name     string
	ImageRef string
	// ImageDigest is "sha256:<hex>" from the container status, or empty.
	ImageDigest string
	Ready       bool
	Running     bool
	StartedAt   time.Time
	// WritableDirs are mount paths of writable emptyDir volumes, candidates
	// for placing the probe.
	WritableDirs           []string
	ReadOnlyRootFilesystem bool
}

// NormalizeDigest extracts "sha256:<hex>" from a container status imageID
// ("docker-pullable://repo@sha256:…", "repo@sha256:…", "sha256:…",
// "docker://sha256:…"). It returns "" when there is no valid SHA-256 digest.
func NormalizeDigest(imageID string) string {
	i := strings.LastIndex(imageID, "sha256:")
	if i < 0 {
		return ""
	}
	hex := strings.ToLower(imageID[i+len("sha256:"):])
	if len(hex) != 64 {
		return ""
	}
	for _, c := range hex {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return ""
		}
	}
	return "sha256:" + hex
}

// object is a controller read from the API, reduced to what owner
// resolution needs.
type object struct {
	uid        types.UID
	kind, name string
	namespace  string
	owner      *metav1.OwnerReference
	labels     map[string]string
	annots     map[string]string
	replicas   *int
	template   *corev1.PodTemplateSpec
}

func newObject(kind string, m *metav1.ObjectMeta, replicas *int, tpl *corev1.PodTemplateSpec) *object {
	return &object{
		uid: m.UID, kind: kind, name: m.Name, namespace: m.Namespace,
		owner: ownerOf(m.OwnerReferences), labels: m.Labels, annots: m.Annotations,
		replicas: replicas, template: tpl,
	}
}

// ownerOf returns the controller reference, or the first owner.
func ownerOf(refs []metav1.OwnerReference) *metav1.OwnerReference {
	for i := range refs {
		if refs[i].Controller != nil && *refs[i].Controller {
			return &refs[i]
		}
	}
	if len(refs) > 0 {
		return &refs[0]
	}
	return nil
}

// isNodeOwner reports whether ref names a core Node. The kubelet sets it on
// the mirror pods of static pods (etcd, kube-apiserver, kube-proxy, ...).
// A node is not a controller, so such a pod is a workload of its own rather
// than one workload per node grouping every static pod on it.
func isNodeOwner(ref *metav1.OwnerReference) bool {
	return ref.Kind == "Node" && ref.APIVersion == "v1"
}

func replicasOf(p *int32, def int) *int {
	n := def
	if p != nil {
		n = int(*p)
	}
	return &n
}

type workloadKey struct{ namespace, kind, name string }

// top is the resolved top-level controller of a chain.
type top struct {
	key workloadKey
	uid types.UID
	// obj is the controller object when it was read; nil for owners that
	// were only seen in owner references.
	obj *object
	// tplObj is the highest object of the chain carrying a pod template.
	tplObj *object
}

type graph struct {
	byUID map[types.UID]*object
}

// resolve follows owner references from start (whose own owner is ref) to
// the top-level controller.
func (g *graph) resolve(namespace string, ref *metav1.OwnerReference) (top, bool) {
	var t top
	var tplObj *object
	for depth := 0; ref != nil && depth < maxOwnerDepth; depth++ {
		o, ok := g.byUID[ref.UID]
		if !ok || o.namespace != namespace {
			return top{key: workloadKey{namespace, ref.Kind, ref.Name}, uid: ref.UID, tplObj: tplObj}, true
		}
		if o.template != nil {
			tplObj = o
		}
		t = top{key: workloadKey{namespace, o.kind, o.name}, uid: o.uid, obj: o, tplObj: tplObj}
		ref = o.owner
	}
	return t, t.key.name != ""
}

type lister[T any] func(ctx context.Context, opts metav1.ListOptions) ([]T, string, error)

// listAll pages through a list. An expired continue token restarts the list
// once without paging.
func listAll[T any](ctx context.Context, list lister[T]) ([]T, error) {
	var out []T
	opts := metav1.ListOptions{Limit: pageSize}
	restarted := false
	for {
		items, cont, err := list(ctx, opts)
		if err != nil {
			if apierrors.IsResourceExpired(err) && opts.Continue != "" && !restarted {
				restarted = true
				out = out[:0]
				opts = metav1.ListOptions{}
				continue
			}
			return nil, err
		}
		out = append(out, items...)
		if cont == "" {
			return out, nil
		}
		opts.Continue = cont
	}
}

// Sync reads the inventory of the cluster and applies the filter.
//
// Pods must be listable; every other resource is optional and a failure to
// read it is recorded in Inventory.Warnings: without namespaces the list is
// derived from the pods, without nodes the architecture stays empty, and
// without a controller kind the resolution uses the owner reference naming
// it but cannot look further up (without Jobs a pod resolves to its Job, not
// the CronJob; without Deployments the Deployment is still named by its
// ReplicaSet but has no desired replica count or labels of its own).
func Sync(ctx context.Context, c *Client, f Filter) (*Inventory, error) {
	cf, err := compileFilter(f)
	if err != nil {
		return nil, err
	}
	inv := &Inventory{CollectedAt: time.Now().UTC()}
	warn := func(what string, err error) {
		inv.Warnings = append(inv.Warnings, fmt.Sprintf("%s: %v", what, err))
	}
	if v, err := c.Kube.Discovery().ServerVersion(); err != nil {
		warn("server version", err)
	} else {
		inv.ServerVersion = v.GitVersion
	}

	core, apps, batch := c.Kube.CoreV1(), c.Kube.AppsV1(), c.Kube.BatchV1()

	pods, err := listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]corev1.Pod, string, error) {
		l, err := core.Pods("").List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	})
	if err != nil {
		return nil, fmt.Errorf("kube: list pods: %w", err)
	}

	namespaces, err := listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]corev1.Namespace, string, error) {
		l, err := core.Namespaces().List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	})
	if err != nil {
		warn("list namespaces (derived from pods)", err)
		namespaces = nil
	}

	type nodeInfo struct{ os, arch string }
	nodes := map[string]nodeInfo{}
	if nl, err := listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]corev1.Node, string, error) {
		l, err := core.Nodes().List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	}); err != nil {
		warn("list nodes (architecture unknown)", err)
	} else {
		for _, n := range nl {
			ni := nodeInfo{os: n.Labels[labelOS], arch: n.Labels[labelArch]}
			if ni.os == "" {
				ni.os = n.Status.NodeInfo.OperatingSystem
			}
			if ni.arch == "" {
				ni.arch = n.Status.NodeInfo.Architecture
			}
			nodes[n.Name] = ni
		}
	}

	g := &graph{byUID: map[types.UID]*object{}}
	add := func(o *object) { g.byUID[o.uid] = o }
	var objects []*object
	collect := func(kind string, err error, objs []*object) {
		if err != nil {
			warn("list "+kind, err)
			return
		}
		for _, o := range objs {
			add(o)
			objects = append(objects, o)
		}
	}
	{
		l, err := listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]appsv1.Deployment, string, error) {
			r, err := apps.Deployments("").List(ctx, o)
			if err != nil {
				return nil, "", err
			}
			return r.Items, r.Continue, nil
		})
		var objs []*object
		for i := range l {
			x := &l[i]
			objs = append(objs, newObject(KindDeployment, &x.ObjectMeta, replicasOf(x.Spec.Replicas, 1), &x.Spec.Template))
		}
		collect("deployments", err, objs)
	}
	{
		l, err := listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]appsv1.ReplicaSet, string, error) {
			r, err := apps.ReplicaSets("").List(ctx, o)
			if err != nil {
				return nil, "", err
			}
			return r.Items, r.Continue, nil
		})
		var objs []*object
		for i := range l {
			x := &l[i]
			objs = append(objs, newObject(KindReplicaSet, &x.ObjectMeta, replicasOf(x.Spec.Replicas, 1), &x.Spec.Template))
		}
		collect("replicasets", err, objs)
	}
	{
		l, err := listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]appsv1.StatefulSet, string, error) {
			r, err := apps.StatefulSets("").List(ctx, o)
			if err != nil {
				return nil, "", err
			}
			return r.Items, r.Continue, nil
		})
		var objs []*object
		for i := range l {
			x := &l[i]
			objs = append(objs, newObject(KindStatefulSet, &x.ObjectMeta, replicasOf(x.Spec.Replicas, 1), &x.Spec.Template))
		}
		collect("statefulsets", err, objs)
	}
	{
		l, err := listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]appsv1.DaemonSet, string, error) {
			r, err := apps.DaemonSets("").List(ctx, o)
			if err != nil {
				return nil, "", err
			}
			return r.Items, r.Continue, nil
		})
		var objs []*object
		for i := range l {
			x := &l[i]
			n := int(x.Status.DesiredNumberScheduled)
			objs = append(objs, newObject(KindDaemonSet, &x.ObjectMeta, &n, &x.Spec.Template))
		}
		collect("daemonsets", err, objs)
	}
	{
		l, err := listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]batchv1.Job, string, error) {
			r, err := batch.Jobs("").List(ctx, o)
			if err != nil {
				return nil, "", err
			}
			return r.Items, r.Continue, nil
		})
		var objs []*object
		for i := range l {
			x := &l[i]
			objs = append(objs, newObject(KindJob, &x.ObjectMeta, nil, &x.Spec.Template))
		}
		collect("jobs", err, objs)
	}
	{
		l, err := listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]batchv1.CronJob, string, error) {
			r, err := batch.CronJobs("").List(ctx, o)
			if err != nil {
				return nil, "", err
			}
			return r.Items, r.Continue, nil
		})
		var objs []*object
		for i := range l {
			x := &l[i]
			objs = append(objs, newObject(KindCronJob, &x.ObjectMeta, nil, &x.Spec.JobTemplate.Spec.Template))
		}
		collect("cronjobs", err, objs)
	}

	type wl struct {
		w      *Workload
		pods   []*corev1.Pod
		tplObj *object
		obj    *object
	}
	wls := map[workloadKey]*wl{}
	get := func(t top) *wl {
		x := wls[t.key]
		if x == nil {
			x = &wl{w: &Workload{UID: string(t.uid), Namespace: t.key.namespace, Kind: t.key.kind, Name: t.key.name}}
			wls[t.key] = x
		}
		if x.obj == nil {
			x.obj = t.obj
		}
		if x.tplObj == nil {
			x.tplObj = t.tplObj
		}
		return x
	}
	// Controllers without pods are workloads too (a CronJob between runs,
	// a Deployment scaled to zero).
	for _, o := range objects {
		self := metav1.OwnerReference{Kind: o.kind, Name: o.name, UID: o.uid}
		if t, ok := g.resolve(o.namespace, &self); ok {
			get(t)
		}
	}
	slices.SortFunc(pods, func(a, b corev1.Pod) int {
		return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name))
	})
	podTop := make([]workloadKey, len(pods))
	for i := range pods {
		p := &pods[i]
		var t top
		ok := false
		if ref := ownerOf(p.OwnerReferences); ref != nil && !isNodeOwner(ref) {
			t, ok = g.resolve(p.Namespace, ref)
		}
		if !ok {
			t = top{key: workloadKey{p.Namespace, KindPod, p.Name}, uid: p.UID}
		}
		x := get(t)
		x.pods = append(x.pods, p)
		podTop[i] = t.key
	}

	for _, x := range wls {
		w := x.w
		var lbls, annots map[string]string
		switch {
		case x.obj != nil:
			if x.obj.template != nil {
				lbls = maps.Clone(x.obj.template.Labels)
				annots = maps.Clone(x.obj.template.Annotations)
			}
			lbls = overlay(lbls, x.obj.labels)
			annots = overlay(annots, x.obj.annots)
			if x.obj.replicas != nil {
				w.Replicas = *x.obj.replicas
			} else {
				w.Replicas = len(x.pods)
			}
		case len(x.pods) > 0:
			lbls = maps.Clone(x.pods[0].Labels)
			annots = maps.Clone(x.pods[0].Annotations)
			w.Replicas = len(x.pods)
			if w.Kind == KindPod {
				w.Replicas = 1
			}
		}
		w.Labels, w.Annotations = lbls, annots
		var spec *corev1.PodSpec
		switch {
		case x.tplObj != nil:
			spec = &x.tplObj.template.Spec
		case len(x.pods) > 0:
			spec = &x.pods[0].Spec
		}
		if spec != nil {
			for _, ct := range spec.Containers {
				w.Containers = append(w.Containers, TemplateContainer{Name: ct.Name, Image: ct.Image})
			}
		}
		w.ExcludedBy = cf.evaluate(w.Namespace, lbls, annots)
		inv.Workloads = append(inv.Workloads, *w)
	}
	slices.SortFunc(inv.Workloads, func(a, b Workload) int {
		return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Name, b.Name))
	})

	for i := range pods {
		x := wls[podTop[i]]
		if x.w.ExcludedBy != "" {
			continue
		}
		p := &pods[i]
		ni := nodes[p.Spec.NodeName]
		inv.Pods = append(inv.Pods, podFrom(p, x.w.Kind, x.w.Name, ni.os, ni.arch))
	}

	if namespaces == nil {
		seen := map[string]bool{}
		for _, p := range pods {
			if !seen[p.Namespace] {
				seen[p.Namespace] = true
				inv.Namespaces = append(inv.Namespaces, Namespace{Name: p.Namespace})
			}
		}
	} else {
		for _, n := range namespaces {
			inv.Namespaces = append(inv.Namespaces, Namespace{Name: n.Name, Labels: n.Labels, Annotations: n.Annotations})
		}
	}
	slices.SortFunc(inv.Namespaces, func(a, b Namespace) int { return cmp.Compare(a.Name, b.Name) })
	return inv, nil
}

func overlay(base, top map[string]string) map[string]string {
	if len(top) == 0 {
		return base
	}
	if base == nil {
		base = make(map[string]string, len(top))
	}
	maps.Copy(base, top)
	return base
}

func podFrom(p *corev1.Pod, kind, name, nodeOS, nodeArch string) Pod {
	out := Pod{
		UID: string(p.UID), Namespace: p.Namespace, Name: p.Name,
		WorkloadKind: kind, WorkloadName: name,
		Node: p.Spec.NodeName, OS: nodeOS, Arch: nodeArch, Phase: p.Status.Phase,
	}
	if p.Status.StartTime != nil {
		out.StartedAt = p.Status.StartTime.UTC()
	}
	for i := range p.Spec.Containers {
		out.Containers = append(out.Containers, containerFrom(p, &p.Spec.Containers[i]))
	}
	return out
}

func containerFrom(p *corev1.Pod, ct *corev1.Container) Container {
	c := Container{Name: ct.Name, ImageRef: ct.Image, WritableDirs: writableDirs(p, ct)}
	if sc := ct.SecurityContext; sc != nil && sc.ReadOnlyRootFilesystem != nil {
		c.ReadOnlyRootFilesystem = *sc.ReadOnlyRootFilesystem
	}
	if st := containerStatus(p, ct.Name); st != nil {
		c.ImageDigest = NormalizeDigest(st.ImageID)
		c.Ready = st.Ready
		if r := st.State.Running; r != nil {
			c.Running = true
			c.StartedAt = r.StartedAt.UTC()
		}
	}
	return c
}

func containerStatus(p *corev1.Pod, name string) *corev1.ContainerStatus {
	for i := range p.Status.ContainerStatuses {
		if p.Status.ContainerStatuses[i].Name == name {
			return &p.Status.ContainerStatuses[i]
		}
	}
	return nil
}

// writableDirs returns the mount paths of the container's writable emptyDir
// volumes, in spec order.
func writableDirs(p *corev1.Pod, ct *corev1.Container) []string {
	empty := map[string]bool{}
	for _, v := range p.Spec.Volumes {
		if v.EmptyDir != nil {
			empty[v.Name] = true
		}
	}
	var out []string
	for _, m := range ct.VolumeMounts {
		if empty[m.Name] && !m.ReadOnly && m.SubPath == "" && m.SubPathExpr == "" && strings.HasPrefix(m.MountPath, "/") {
			out = append(out, m.MountPath)
		}
	}
	return out
}

// Payload converts the inventory to the upload body of POST /k8s/inventory.
func (inv *Inventory) Payload(clusterID, jobID string) agentapi.K8sInventory {
	out := agentapi.K8sInventory{
		ClusterId:     clusterID,
		CollectedAt:   inv.CollectedAt,
		ServerVersion: inv.ServerVersion,
		Namespaces:    []agentapi.K8sNamespace{},
		Workloads:     []agentapi.K8sInventoryWorkload{},
		Pods:          []agentapi.K8sInventoryPod{},
	}
	if jobID != "" {
		out.JobId = &jobID
	}
	for _, n := range inv.Namespaces {
		out.Namespaces = append(out.Namespaces, agentapi.K8sNamespace{Name: n.Name, Labels: mapPtr(n.Labels), Annotations: mapPtr(n.Annotations)})
	}
	for _, w := range inv.Workloads {
		out.Workloads = append(out.Workloads, agentapi.K8sInventoryWorkload{
			Uid: strPtr(w.UID), Namespace: w.Namespace, Kind: w.Kind, Name: w.Name, Replicas: w.Replicas,
			Labels: mapPtr(w.Labels), Annotations: mapPtr(w.Annotations), ExcludedBy: strPtr(w.ExcludedBy),
		})
	}
	for _, p := range inv.Pods {
		ap := agentapi.K8sInventoryPod{
			Uid: strPtr(p.UID), Namespace: p.Namespace, Name: p.Name,
			WorkloadKind: p.WorkloadKind, WorkloadName: p.WorkloadName,
			Node: p.Node, Phase: podPhase(p.Phase), StartedAt: timePtr(p.StartedAt),
			Containers: []agentapi.K8sInventoryContainer{},
		}
		for _, c := range p.Containers {
			ready := c.Ready
			ap.Containers = append(ap.Containers, agentapi.K8sInventoryContainer{
				Name: c.Name, ImageRef: c.ImageRef, ImageDigest: strPtr(c.ImageDigest),
				Ready: &ready, StartedAt: timePtr(c.StartedAt),
			})
		}
		out.Pods = append(out.Pods, ap)
	}
	return out
}

func podPhase(p corev1.PodPhase) agentapi.K8sPodPhase {
	switch ph := agentapi.K8sPodPhase(p); ph {
	case agentapi.K8sPodPhaseRunning, agentapi.K8sPodPhasePending, agentapi.K8sPodPhaseSucceeded, agentapi.K8sPodPhaseFailed:
		return ph
	}
	return agentapi.K8sPodPhaseUnknown
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func mapPtr(m map[string]string) *map[string]string {
	if len(m) == 0 {
		return nil
	}
	return &m
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
