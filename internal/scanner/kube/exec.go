// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package kube

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilexec "k8s.io/client-go/util/exec"

	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/report/reportapi"
	"github.com/bomcensus/bomcensus/internal/sign"
)

// Defaults for Deps.
const (
	DefaultMemoryLimitMB  = 128
	DefaultMaxRuntime     = 5 * time.Minute
	DefaultTransferGrace  = 2 * time.Minute
	DefaultMaxReportBytes = 64 << 20
	DefaultMaxProcs       = 1
	defaultStderrTail     = 4 << 10
	cleanupTimeout        = 30 * time.Second
)

// FullSections are collected from a container whose image content is not
// known yet. The containers section does not apply inside a container.
var FullSections = []string{report.SectionHost, report.SectionPackages, report.SectionArtifacts, report.SectionProcesses}

// baseDirs are tried for the probe before the container's emptyDir mounts.
var baseDirs = []string{"/tmp", "/dev/shm"}

// ProcessSections are collected from the other replicas.
var ProcessSections = []string{report.SectionProcesses}

// ExecTarget is one container to collect.
type ExecTarget struct {
	Namespace string
	Pod       string
	Container string
	// Node, OS and Arch come from the inventory. CollectContainer reads the
	// pod again and only uses Arch (and OS) when the node cannot be read.
	Node         string
	OS           string
	Arch         string
	WorkloadKind string
	WorkloadName string
	ImageRef     string
	ImageDigest  string
	// Sections to collect. Empty means FullSections.
	Sections []string
	// KnownDigests are the section digests the caller already has for this
	// container (report.Request.KnownDigests).
	KnownDigests map[string]string
	// GoSymbols is passed to the probe with the collection.
	GoSymbols *report.GoSymbolQuery
}

// TargetFromAPI converts a k8s_exec directive target.
func TargetFromAPI(t agentapi.K8sExecTarget) ExecTarget {
	out := ExecTarget{Namespace: t.Namespace, Pod: t.Pod, Container: t.Container}
	if t.ImageRef != nil {
		out.ImageRef = *t.ImageRef
	}
	if t.ImageDigest != nil {
		out.ImageDigest = *t.ImageDigest
	}
	for _, s := range t.Sections {
		out.Sections = append(out.Sections, string(s))
	}
	out.GoSymbols = reportapi.GoSymbolQueryPtr(t.GoSymbols)
	return out
}

// API converts the target to its directive form.
func (t ExecTarget) API() agentapi.K8sExecTarget {
	out := agentapi.K8sExecTarget{
		Namespace: t.Namespace, Pod: t.Pod, Container: t.Container,
		ImageRef: strPtr(t.ImageRef), ImageDigest: strPtr(t.ImageDigest),
		Sections: []agentapi.SectionName{},
	}
	for _, s := range t.Sections {
		out.Sections = append(out.Sections, agentapi.SectionName(s))
	}
	out.GoSymbols = reportapi.APIGoSymbolQueryPtr(t.GoSymbols)
	return out
}

// Deps carries what CollectContainer needs besides the target.
type Deps struct {
	ClusterID string
	// Probe returns the probe executable for the target platform ("linux",
	// "amd64"/"arm64"). The bytes are verified with sign.VerifyELF right
	// before they are sent.
	Probe func(ctx context.Context, goos, arch string) ([]byte, error)
	// Policy is passed to the probe. MaxRuntimeSeconds, MemoryLimitMB and
	// ScanContainers are overridden from the fields below.
	Policy report.Policy
	// MemoryLimitMB becomes GOMEMLIMIT of the probe. The probe shares the
	// container's memory limit, so this is kept small (ARCH 4.5).
	MemoryLimitMB int
	// MaxRuntime bounds the probe run (Policy.MaxRuntimeSeconds).
	MaxRuntime time.Duration
	// Timeout bounds the whole session including the transfer. Zero means
	// MaxRuntime + DefaultTransferGrace.
	Timeout time.Duration
	// MaxReportBytes bounds the encoded report read from stdout.
	MaxReportBytes int64
	// MaxProcs becomes GOMAXPROCS of the probe.
	MaxProcs int
	Logger   *slog.Logger
}

func (d Deps) withDefaults() Deps {
	if d.MemoryLimitMB <= 0 {
		d.MemoryLimitMB = DefaultMemoryLimitMB
	}
	if d.MaxRuntime <= 0 {
		d.MaxRuntime = DefaultMaxRuntime
	}
	if d.Timeout <= 0 {
		d.Timeout = d.MaxRuntime + DefaultTransferGrace
	}
	if d.MaxReportBytes <= 0 {
		d.MaxReportBytes = DefaultMaxReportBytes
	}
	if d.MaxProcs <= 0 {
		d.MaxProcs = DefaultMaxProcs
	}
	if d.Logger == nil {
		d.Logger = slog.New(slog.DiscardHandler)
	}
	return d
}

// ContainerOutcome describes how the collection of one container went.
type ContainerOutcome struct {
	// Coverage is full, partial, process_only, unsupported or failed.
	Coverage agentapi.Coverage
	Reason   string
	// Dir is the directory the probe ran from.
	Dir  string
	Arch string
	// ExitCode of the probe, -1 when it did not run to completion.
	ExitCode int
	// StderrTail is the end of the session's stderr without status lines.
	StderrTail string
	Duration   time.Duration
}

// Result converts the outcome to the per-container scan job result.
func (o ContainerOutcome) Result(t ExecTarget, reportID string) agentapi.ExecTargetResult {
	status := agentapi.ScanJobStatus("failed")
	switch o.Coverage {
	case agentapi.CoverageFull, agentapi.CoverageProcessOnly:
		status = "ok"
	case agentapi.CoveragePartial:
		status = "partial"
	}
	return agentapi.ExecTargetResult{
		Namespace: t.Namespace, Pod: t.Pod, Container: t.Container,
		Status: status, Coverage: o.Coverage, Reason: strPtr(o.Reason), ReportId: strPtr(reportID),
	}
}

// CollectContainer pipes the probe into one container over pods/exec and
// returns its report.
//
// A report is returned for coverage full, partial and process_only. For
// unsupported and failed the outcome carries the reason and err is nil: the
// container could not be collected, which is a result. err is non-nil only
// for problems on the scanner side (no probe, probe signature not valid,
// the caller's context ended); the outcome is then failed as well.
func CollectContainer(ctx context.Context, c *Client, t ExecTarget, d Deps) (*report.Report, ContainerOutcome, error) {
	d = d.withDefaults()
	start := time.Now()
	out := ContainerOutcome{ExitCode: -1}
	finish := func(cov agentapi.Coverage, reason string) ContainerOutcome {
		out.Coverage, out.Reason, out.Duration = cov, reason, time.Since(start)
		return out
	}
	if d.Probe == nil {
		return nil, finish(agentapi.CoverageFailed, "no probe source"), errors.New("kube: Deps.Probe is not set")
	}
	if c == nil || c.Kube == nil || c.Exec == nil {
		return nil, finish(agentapi.CoverageFailed, "no client"), errors.New("kube: client is not set")
	}

	pod, err := c.Kube.CoreV1().Pods(t.Namespace).Get(ctx, t.Pod, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		return nil, finish(agentapi.CoverageFailed, "pod not found"), nil
	case apierrors.IsForbidden(err):
		return nil, finish(agentapi.CoverageFailed, "reading the pod is forbidden by RBAC"), nil
	case err != nil:
		if ctx.Err() != nil {
			return nil, finish(agentapi.CoverageFailed, "canceled"), ctx.Err()
		}
		return nil, finish(agentapi.CoverageFailed, "read pod: "+err.Error()), nil
	}
	var spec *corev1.Container
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == t.Container {
			spec = &pod.Spec.Containers[i]
		}
	}
	if spec == nil {
		return nil, finish(agentapi.CoverageFailed, "container not found in pod"), nil
	}
	ct := containerFrom(pod, spec)
	if pod.Status.Phase != corev1.PodRunning || !ct.Running {
		return nil, finish(agentapi.CoverageFailed, "container not running"), nil
	}

	goos, arch := t.OS, t.Arch
	if pod.Spec.NodeName != "" {
		if n, err := c.Kube.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{}); err == nil {
			if a := n.Labels[labelArch]; a != "" {
				arch = a
			}
			if o := n.Labels[labelOS]; o != "" {
				goos = o
			}
		}
	}
	if goos == "" {
		goos = "linux"
	}
	if goos != "linux" {
		return nil, finish(agentapi.CoverageUnsupported, "operating system "+goos+" is not supported"), nil
	}

	// Fetch the probe before opening a session when the architecture is
	// known, so that a missing probe does not cost an exec.
	var probe []byte
	if arch != "" {
		if probe, err = d.Probe(ctx, goos, arch); err != nil {
			return nil, finish(agentapi.CoverageFailed, "no probe for "+goos+"/"+arch), fmt.Errorf("kube: probe %s/%s: %w", goos, arch, err)
		}
	}

	sections := t.Sections
	if len(sections) == 0 {
		sections = FullSections
	}
	req := report.Request{Sections: sections, KnownDigests: t.KnownDigests, Policy: d.Policy, GoSymbols: t.GoSymbols}
	req.Policy.MaxRuntimeSeconds = int(d.MaxRuntime / time.Second)
	req.Policy.MemoryLimitMB = d.MemoryLimitMB
	req.Policy.ScanContainers = false
	reqJSON, err := json.Marshal(req)
	if err != nil {
		return nil, finish(agentapi.CoverageFailed, "encode request"), fmt.Errorf("kube: encode request: %w", err)
	}

	nonce := make([]byte, 16)
	rand.Read(nonce)
	var verifyErr error
	params := sessionParams{
		nonce:     hex.EncodeToString(nonce),
		dirs:      append(slices.Clone(baseDirs), ct.WritableDirs...),
		memLimit:  strconv.Itoa(d.MemoryLimitMB) + "MiB",
		maxProcs:  d.MaxProcs,
		maxStdout: d.MaxReportBytes,
		tailBytes: defaultStderrTail,
		request:   reqJSON,
		probe: func(unameArch string) ([]byte, error) {
			data := probe
			if data == nil {
				arch = archFromUname(unameArch)
				if arch == "" {
					return nil, fmt.Errorf("unknown architecture %q", unameArch)
				}
				b, err := d.Probe(ctx, goos, arch)
				if err != nil {
					return nil, fmt.Errorf("probe %s/%s: %w", goos, arch, err)
				}
				data = b
			}
			if err := sign.VerifyELF(data); err != nil {
				verifyErr = err
				return nil, err
			}
			return data, nil
		},
	}

	sctx, cancel := context.WithTimeout(ctx, d.Timeout)
	res := runSession(sctx, c.Exec, t.Namespace, t.Pod, t.Container, params)
	timedOut := sctx.Err() != nil && ctx.Err() == nil
	cancel()

	out.Arch = arch
	out.StderrTail = res.tail
	if res.path != "" {
		out.Dir = res.path[:strings.LastIndexByte(res.path, '/')]
		if out.Dir == "" {
			out.Dir = "/"
		}
	}
	if res.exitSeen {
		out.ExitCode = res.exitCode
	}
	// The script removes its file on exit. Without the EXIT status line it
	// may not have run its trap, so clean up from a second session.
	if res.path != "" && !res.exitSeen {
		cleanup(ctx, c.Exec, t, res.pid, res.path, d.Logger)
	}

	log := d.Logger.With("namespace", t.Namespace, "pod", t.Pod, "container", t.Container)
	switch {
	case res.probeErr != nil:
		if verifyErr != nil {
			return nil, finish(agentapi.CoverageFailed, "probe signature verification failed"), fmt.Errorf("kube: probe signature: %w", verifyErr)
		}
		return nil, finish(agentapi.CoverageFailed, "no probe: "+res.probeErr.Error()), fmt.Errorf("kube: %w", res.probeErr)
	case ctx.Err() != nil:
		return nil, finish(agentapi.CoverageFailed, "canceled"), ctx.Err()
	case res.overflow:
		return nil, finish(agentapi.CoverageFailed, fmt.Sprintf("report larger than %d bytes", d.MaxReportBytes)), nil
	case timedOut:
		return nil, finish(agentapi.CoverageFailed, "timeout after "+d.Timeout.String()), nil
	case res.badToken != "":
		return nil, finish(agentapi.CoverageFailed, "unexpected status from container: "+res.badToken), nil
	case !res.started:
		cov, reason := classifyStartError(res.execErr)
		return nil, finish(cov, reason), nil
	case res.noTool != "":
		return nil, finish(agentapi.CoverageUnsupported, "image lacks "+res.noTool), nil
	case res.noDir:
		if ct.ReadOnlyRootFilesystem {
			return nil, finish(agentapi.CoverageFailed, "read-only root file system without a writable and executable mount"), nil
		}
		return nil, finish(agentapi.CoverageFailed, "no writable and executable directory"), nil
	case res.short:
		return nil, finish(agentapi.CoverageFailed, "probe transfer incomplete"), nil
	case !res.ready:
		return nil, finish(agentapi.CoverageFailed, "session ended before the probe started: "+errText(res.execErr)), nil
	case !res.exitSeen:
		return nil, finish(agentapi.CoverageFailed, "session ended while the probe ran: "+errText(res.execErr)), nil
	case res.exitCode != 0:
		return nil, finish(agentapi.CoverageFailed, "probe failed with exit code "+strconv.Itoa(res.exitCode)+lastLine(res.tail)), nil
	}

	r, err := report.Decode(bytes.NewReader(res.stdout))
	if err != nil {
		return nil, finish(agentapi.CoverageFailed, "invalid report: "+err.Error()), nil
	}
	r.Cache = nil
	r.Subject = &report.Subject{
		Kind: report.SubjectK8sContainer,
		K8s: &report.K8sSubject{
			ClusterID: d.ClusterID, Namespace: t.Namespace, Pod: t.Pod, Container: t.Container,
			ImageRef: ct.ImageRef, ImageDigest: ct.ImageDigest,
		},
	}
	scopeProcesses(r.Processes, &pod.Spec)
	cov, reason := coverageOf(r, sections)
	log.Debug("container collected", "coverage", cov, "dir", out.Dir, "duration", time.Since(start))
	return r, finish(cov, reason), nil
}

func cleanup(ctx context.Context, ex Executor, t ExecTarget, pid, path string, log *slog.Logger) {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	var stderr bytes.Buffer
	err := ex.Exec(cctx, ExecRequest{
		Namespace: t.Namespace, Pod: t.Pod, Container: t.Container,
		Command: []string{"sh", "-c", cleanupScript, "bomcensus", pid, path},
		Stderr:  &stderr,
	})
	if err != nil {
		log.Warn("probe cleanup failed; the next collection removes the file once it is an hour old",
			"namespace", t.Namespace, "pod", t.Pod, "container", t.Container, "path", path, "err", err)
	}
}

// classifyStartError maps an exec failure before the script printed
// anything.
func classifyStartError(err error) (agentapi.Coverage, string) {
	if err == nil {
		return agentapi.CoverageFailed, "session ended without status"
	}
	msg := strings.ToLower(err.Error())
	var ee utilexec.ExitError
	switch {
	case apierrors.IsForbidden(err) || strings.Contains(msg, "forbidden"):
		return agentapi.CoverageFailed, "exec forbidden by RBAC"
	case strings.Contains(msg, "executable file not found"), strings.Contains(msg, "no such file or directory"):
		return agentapi.CoverageUnsupported, "no shell in image"
	case errors.As(err, &ee) && (ee.ExitStatus() == 126 || ee.ExitStatus() == 127):
		return agentapi.CoverageUnsupported, "no shell in image"
	case strings.Contains(msg, "not running"), strings.Contains(msg, "not found"):
		return agentapi.CoverageFailed, "container not running"
	}
	return agentapi.CoverageFailed, "exec failed: " + err.Error()
}

func archFromUname(m string) string {
	switch strings.TrimSpace(m) {
	case "x86_64", "amd64":
		return "amd64"
	case "aarch64", "arm64", "armv8l", "armv8b":
		return "arm64"
	}
	return ""
}

func errText(err error) string {
	if err == nil {
		return "no error"
	}
	return err.Error()
}

func lastLine(tail string) string {
	if tail == "" {
		return ""
	}
	if i := strings.LastIndexByte(tail, '\n'); i >= 0 {
		tail = tail[i+1:]
	}
	return ": " + tail
}

func sectionMeta(r *report.Report, name string) *report.SectionMeta {
	switch name {
	case report.SectionHost:
		if r.Host != nil {
			return &r.Host.SectionMeta
		}
	case report.SectionPackages:
		if r.Packages != nil {
			return &r.Packages.SectionMeta
		}
	case report.SectionArtifacts:
		if r.Artifacts != nil {
			return &r.Artifacts.SectionMeta
		}
	case report.SectionProcesses:
		if r.Processes != nil {
			return &r.Processes.SectionMeta
		}
	case report.SectionContainers:
		if r.Containers != nil {
			return &r.Containers.SectionMeta
		}
	}
	return nil
}

// coverageOf derives the container coverage from the sections requested
// and what the probe reported for them.
func coverageOf(r *report.Report, sections []string) (agentapi.Coverage, string) {
	var notes []string
	for _, s := range sections {
		m := sectionMeta(r, s)
		switch {
		case m == nil:
			notes = append(notes, s+": missing")
		case m.Unchanged || m.Coverage == report.CoverageFull:
		default:
			n := s + ": " + string(m.Coverage)
			if m.Reason != "" {
				n += " (" + m.Reason + ")"
			}
			notes = append(notes, n)
		}
	}
	reason := strings.Join(notes, "; ")
	if slices.Equal(sections, ProcessSections) && sectionMeta(r, report.SectionProcesses) != nil {
		return agentapi.CoverageProcessOnly, reason
	}
	if len(notes) > 0 {
		return agentapi.CoveragePartial, reason
	}
	return agentapi.CoverageFull, ""
}
