// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package kube

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	authv1 "k8s.io/api/authentication/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/sign/signtest"
)

// TestLive runs against a real cluster. It is opt-in:
//
//	BOMCENSUS_K8S_LIVE=1 BOMCENSUS_K8S_KUBECONFIG=/path/to/kubeconfig go test -run TestLive ./internal/scanner/kube
//
// It creates one namespace (removed at the end) with a busybox pod, an
// alpine deployment with two replicas, a pod without a shell, a pod with a
// read-only root file system, and two with a read-only root file system and
// a read-only /dev/shm, one of them with a writable emptyDir. Images are pulled by the cluster as usual
// (BOMCENSUS_K8S_IMAGE_BUSYBOX, _ALPINE and _NOSHELL override them).
func TestLive(t *testing.T) {
	if os.Getenv("BOMCENSUS_K8S_LIVE") != "1" {
		t.Skip("set BOMCENSUS_K8S_LIVE=1 and BOMCENSUS_K8S_KUBECONFIG to run")
	}
	kc, err := os.ReadFile(os.Getenv("BOMCENSUS_K8S_KUBECONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	images := map[string]string{"busybox": "busybox:1.37", "alpine": "alpine:3.22", "noshell": "registry.k8s.io/pause:3.10"}
	for k := range images {
		if v := os.Getenv("BOMCENSUS_K8S_IMAGE_" + strings.ToUpper(k)); v != "" {
			images[k] = v
		}
	}
	c, err := NewClient(Config{Kubeconfig: kc})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	suffix := make([]byte, 4)
	rand.Read(suffix)
	ns := "bomcensus-live-" + hex.EncodeToString(suffix)
	core := c.Kube.CoreV1()
	if _, err := core.Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		dctx, dcancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer dcancel()
		if err := core.Namespaces().Delete(dctx, ns, metav1.DeleteOptions{}); err != nil {
			t.Errorf("delete namespace %s: %v", ns, err)
		}
	})

	// maskShm mounts a read-only volume over /dev/shm, as on runtimes that
	// mount it noexec, so that a read-only root has no usable directory.
	maskShm := func(spec corev1.PodSpec) corev1.PodSpec {
		spec.Volumes = append(spec.Volumes, corev1.Volume{Name: "shm", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}}})
		spec.Containers[0].VolumeMounts = append(spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "shm", MountPath: "/dev/shm", ReadOnly: true})
		return spec
	}
	sleeper := func(name, image string, ro bool, emptyDir string) corev1.PodSpec {
		zero := int64(0)
		spec := corev1.PodSpec{
			TerminationGracePeriodSeconds: &zero,
			Containers: []corev1.Container{{
				Name: "main", Image: image, ImagePullPolicy: corev1.PullIfNotPresent,
				Command:         []string{"sleep", "3600"},
				SecurityContext: &corev1.SecurityContext{ReadOnlyRootFilesystem: &ro},
			}},
		}
		if strings.Contains(image, "pause") {
			spec.Containers[0].Command = nil
		}
		if emptyDir != "" {
			spec.Volumes = []corev1.Volume{{Name: "scratch", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}
			spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "scratch", MountPath: emptyDir}}
		}
		return spec
	}
	pods := map[string]corev1.PodSpec{
		"bb":     sleeper("bb", images["busybox"], false, ""),
		"nosh":   sleeper("nosh", images["noshell"], false, ""),
		"ro-shm": sleeper("ro-shm", images["alpine"], true, ""),
		"ro":     maskShm(sleeper("ro", images["alpine"], true, "")),
		"ro-ed":  maskShm(sleeper("ro-ed", images["alpine"], true, "/scratch")),
	}
	for name, spec := range pods {
		if _, err := core.Pods(ns).Create(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"app": name}}, Spec: spec}, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	two := int32(2)
	sel := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "alp"}}
	if _, err := c.Kube.AppsV1().Deployments(ns).Create(ctx, &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "alp"},
		Spec: appsv1.DeploymentSpec{Replicas: &two, Selector: sel, Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{Labels: sel.MatchLabels}, Spec: sleeper("alp", images["alpine"], false, ""),
		}},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Kube.BatchV1().CronJobs(ns).Create(ctx, &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{Name: "cj"},
		Spec: batchv1.CronJobSpec{Schedule: "0 0 1 1 *", JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{
			Spec: func() corev1.PodSpec {
				s := sleeper("cj", images["busybox"], false, "")
				s.RestartPolicy = corev1.RestartPolicyNever
				return s
			}(),
		}}}},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	// Wait until all seven pods run.
	var inv *Inventory
	deadline := time.Now().Add(4 * time.Minute)
	for {
		inv, err = Sync(ctx, c, Filter{NamespaceInclude: []string{ns}})
		if err != nil {
			t.Fatal(err)
		}
		running := 0
		for _, p := range inv.Pods {
			if p.Phase == corev1.PodRunning && len(p.Containers) == 1 && p.Containers[0].Running {
				running++
			}
		}
		if running == 7 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d of 7 pods running: %+v", running, inv.Pods)
		}
		time.Sleep(2 * time.Second)
	}
	t.Logf("server %s, %d workloads, %d pods, warnings %v", inv.ServerVersion, len(inv.Workloads), len(inv.Pods), inv.Warnings)

	ws := workloadIndex(inv)
	for _, k := range []string{"Pod/bb", "Pod/nosh", "Pod/ro", "Pod/ro-ed", "Pod/ro-shm", "Deployment/alp", "CronJob/cj"} {
		w, ok := ws[ns+"/"+k]
		if !ok || w.ExcludedBy != "" {
			t.Errorf("workload %s: %+v", k, w)
		}
	}
	if w := ws[ns+"/Deployment/alp"]; w.Replicas != 2 {
		t.Errorf("alp replicas %d", w.Replicas)
	}
	excluded := 0
	for _, w := range inv.Workloads {
		if w.Namespace != ns {
			if w.ExcludedBy != "namespace_include: no pattern matched" {
				t.Errorf("%s/%s/%s excluded by %q", w.Namespace, w.Kind, w.Name, w.ExcludedBy)
			}
			excluded++
		}
	}
	if excluded == 0 {
		t.Error("no workloads outside the test namespace were listed")
	}
	arch := ""
	for _, p := range inv.Pods {
		if p.Arch == "" || p.Containers[0].ImageDigest == "" {
			t.Errorf("pod %s: arch %q digest %q", p.Name, p.Arch, p.Containers[0].ImageDigest)
		}
		arch = p.Arch
	}

	tr := signtest.Install(t)
	probe := tr.SignELF(t, fakeProbeELF(t, arch))
	deps := Deps{
		ClusterID:  "live",
		Probe:      func(context.Context, string, string) ([]byte, error) { return probe, nil },
		Policy:     report.DefaultPolicy(),
		MaxRuntime: time.Minute,
	}

	targets := Plan(inv, nil, PlanOptions{})
	byPod := map[string]ExecTarget{}
	for _, tg := range targets {
		byPod[tg.Pod] = tg
		t.Logf("target %s/%s %v", tg.Pod, tg.Container, tg.Sections)
	}
	if len(targets) != 7 {
		t.Errorf("%d targets", len(targets))
	}

	var mu sync.Mutex
	results := map[string]Result{}
	err = RunPlan(ctx, targets, Limits{Total: 4, PerNode: 2, PerNamespace: 3},
		func(ctx context.Context, tg ExecTarget) (*report.Report, ContainerOutcome, error) {
			return CollectContainer(ctx, c, tg, deps)
		},
		func(r Result) {
			mu.Lock()
			defer mu.Unlock()
			results[r.Target.Pod] = r
			t.Logf("%s: %s %q dir=%s exit=%d took %v err=%v tail=%q", r.Target.Pod, r.Outcome.Coverage, r.Outcome.Reason,
				r.Outcome.Dir, r.Outcome.ExitCode, r.Outcome.Duration.Round(time.Millisecond), r.Err, r.Outcome.StderrTail)
		})
	if err != nil {
		t.Fatal(err)
	}

	alpFull, alpProc := 0, 0
	for pod, r := range results {
		switch {
		case pod == "bb":
			if r.Outcome.Coverage != agentapi.CoverageFull || r.Report == nil || r.Outcome.Dir != "/tmp" {
				t.Errorf("bb: %+v", r.Outcome)
			} else if s := r.Report.Subject.K8s; s.Namespace != ns || s.Pod != "bb" || s.Container != "main" || s.ImageDigest != byPod["bb"].ImageDigest || s.ClusterID != "live" {
				t.Errorf("bb subject %+v", s)
			}
		case strings.HasPrefix(pod, "alp-"):
			switch r.Outcome.Coverage {
			case agentapi.CoverageFull:
				alpFull++
			case agentapi.CoverageProcessOnly:
				alpProc++
			default:
				t.Errorf("%s: %+v", pod, r.Outcome)
			}
		case pod == "nosh":
			if r.Outcome.Coverage != agentapi.CoverageUnsupported || r.Outcome.Reason != "no shell in image" || r.Err != nil {
				t.Errorf("nosh: %+v %v", r.Outcome, r.Err)
			}
		case pod == "ro":
			if r.Outcome.Coverage != agentapi.CoverageFailed || !strings.HasPrefix(r.Outcome.Reason, "read-only root file system") {
				t.Errorf("ro: %+v", r.Outcome)
			}
		case pod == "ro-shm":
			// containerd mounts /dev/shm writable and executable.
			if r.Report == nil || r.Outcome.Dir != "/dev/shm" {
				t.Errorf("ro-shm: %+v", r.Outcome)
			}
		case pod == "ro-ed":
			if r.Report == nil || r.Outcome.Dir != "/scratch" {
				t.Errorf("ro-ed: %+v", r.Outcome)
			}
		}
	}
	if alpFull != 1 || alpProc != 1 {
		t.Errorf("alp: %d full, %d process only", alpFull, alpProc)
	}

	// listing shows what is left in a container's candidate directories
	// and its processes.
	leftovers := func(pod string) string {
		var out, errb bytes.Buffer
		err := c.Exec.Exec(ctx, ExecRequest{Namespace: ns, Pod: pod, Container: "main",
			Command: []string{"sh", "-c", "ls -a /tmp /dev/shm /scratch 2>/dev/null; ps -o pid,args 2>/dev/null || ps"}, Stdout: &out, Stderr: &errb})
		if err != nil {
			t.Errorf("list %s: %v %s", pod, err, errb.String())
		}
		return out.String()
	}
	for pod := range results {
		if pod == "nosh" || pod == "ro" {
			continue
		}
		if l := leftovers(pod); strings.Contains(l, ".bomcensus-") {
			t.Errorf("%s: leftovers after collection:\n%s", pod, l)
		}
	}

	t.Run("timeout cleans up", func(t *testing.T) {
		d := deps
		d.Policy.ExcludePaths = []string{"fake:sleep=120"}
		d.Timeout = 8 * time.Second
		_, o, err := CollectContainer(ctx, c, byPod["bb"], d)
		if err != nil || o.Coverage != agentapi.CoverageFailed || !strings.HasPrefix(o.Reason, "timeout") {
			t.Fatalf("outcome %+v err %v", o, err)
		}
		var l string
		if !waitFor(15*time.Second, func() bool { l = leftovers("bb"); return !strings.Contains(l, ".bomcensus-") }) {
			t.Errorf("leftovers after timeout:\n%s", l)
		}
	})

	t.Run("exec forbidden", func(t *testing.T) {
		limited := limitedKubeconfig(t, ctx, c, kc, ns)
		lc, err := NewClient(Config{Kubeconfig: limited})
		if err != nil {
			t.Fatal(err)
		}
		_, o, err := CollectContainer(ctx, lc, byPod["bb"], deps)
		if err != nil || o.Coverage != agentapi.CoverageFailed || o.Reason != "exec forbidden by RBAC" {
			t.Fatalf("outcome %+v err %v", o, err)
		}
	})
}

// limitedKubeconfig creates a service account that may read pods in ns but
// not exec, and returns a kubeconfig with its token.
func limitedKubeconfig(t *testing.T, ctx context.Context, c *Client, admin []byte, ns string) []byte {
	t.Helper()
	const name = "limited"
	if _, err := c.Kube.CoreV1().ServiceAccounts(ns).Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: name}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Kube.RbacV1().Roles(ns).Create(ctx, &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}}},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Kube.RbacV1().RoleBindings(ns).Create(ctx, &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: name, Namespace: ns}},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: name},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	tok, err := c.Kube.CoreV1().ServiceAccounts(ns).CreateToken(ctx, name, &authv1.TokenRequest{}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := clientcmd.Load(admin)
	if err != nil {
		t.Fatal(err)
	}
	kctx := cfg.Contexts[cfg.CurrentContext]
	cfg.AuthInfos = map[string]*clientcmdapi.AuthInfo{name: {Token: tok.Status.Token}}
	kctx.AuthInfo = name
	b, err := clientcmd.Write(*cfg)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
