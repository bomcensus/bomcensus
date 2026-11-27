// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package probe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bomcensus/bomcensus/internal/collect/artifact"
	"github.com/bomcensus/bomcensus/internal/collect/container"
	"github.com/bomcensus/bomcensus/internal/collect/hostinfo"
	"github.com/bomcensus/bomcensus/internal/collect/pkgdb"
	"github.com/bomcensus/bomcensus/internal/report"
)

const (
	defaultMaxContainers    = 32
	defaultContainerTimeout = 3 * time.Minute
	containerDigestVersion  = 1

	// imageScanMaxAge is how long the content read for an image is reused
	// by later runs. The containers section runs hourly by default; reading
	// every image again each time costs a full file system walk per image.
	// Content that is not part of the image (volumes seen through the
	// container root) can be this old in the report.
	imageScanMaxAge = 24 * time.Hour
	imageScanKey    = "probe.image.v2."
)

// imageScan is the content read for one image digest.
type imageScan struct {
	scope    report.ImageScope
	owner    *pkgdb.Index
	coverage report.Coverage
	reason   string
	// reused is set when the content comes from the cache; owner is then
	// built when a writable layer needs it.
	reused bool
}

// storedImageScan is an image scan kept in the cache. The scope is stored
// before the writable layer of its container is removed from it, since that
// layer is read again by every run.
type storedImageScan struct {
	Scope    report.ImageScope `json:"s"`
	Coverage report.Coverage   `json:"c"`
	Reason   string            `json:"r,omitempty"`
	// StartedAt identifies the run of the container the scope was read
	// from; after a restart its root is read again.
	StartedAt time.Time `json:"t"`
	// Activity is rootActivity at the time of the scan. The artifacts
	// depend on it (InUse, files of running packages).
	Activity string `json:"a"`
	// Detectors is the digest of the detector table of the scan.
	Detectors string `json:"dt,omitempty"`
}

// reuseImageScans fills scans with the stored image scans whose container
// is still running, unchanged since the scan, with the same executables
// running and the same archives open.
func (r *runner) reuseImageScans(sec *report.ContainersSection, scans map[string]*imageScan, running []artifact.RunningExe, open openFileIndex) {
	for i := range sec.Containers {
		ct := &sec.Containers[i]
		if !ct.Running || ct.InitPID <= 0 || ct.ImageDigest == "" || scans[ct.ImageDigest] != nil {
			continue
		}
		var st storedImageScan
		if !r.env.Cache.Value(imageScanKey+ct.ImageDigest, &st) ||
			st.Scope.Digest != ct.ImageDigest || st.Scope.FromContainer != ct.ID || !st.StartedAt.Equal(ct.StartedAt) ||
			st.Detectors != r.detectorsDigest {
			continue
		}
		if st.Activity != rootActivity(r.env.Proc, r.containerRoot(ct), running, open) {
			continue
		}
		scans[ct.ImageDigest] = &imageScan{scope: st.Scope, coverage: st.Coverage, reason: st.Reason, reused: true}
		sec.ImageScopes = append(sec.ImageScopes, st.Scope)
	}
}

// storeImageScan keeps a complete image scan for later runs. activity is
// rootActivity of the container root when the scan started.
func (r *runner) storeImageScan(ct *report.Container, img *imageScan, activity string) {
	if img.coverage == report.CoverageNone || activity == "" {
		return
	}
	r.env.Cache.SetValue(imageScanKey+ct.ImageDigest, storedImageScan{
		Scope: img.scope, Coverage: img.coverage, Reason: img.reason, StartedAt: ct.StartedAt, Activity: activity,
		Detectors: r.detectorsDigest,
	}, imageScanMaxAge)
}

func (r *runner) containerRoot(ct *report.Container) string {
	return filepath.Join(r.env.Proc, strconv.Itoa(ct.InitPID), "root")
}

// rootActivity summarizes what the artifact collector takes from the
// running processes for root: the executables of processes with that root
// directory and the archives open there.
func rootActivity(procDir, root string, running []artifact.RunningExe, open openFileIndex) string {
	rootFI, err := os.Stat(root)
	if err != nil {
		return ""
	}
	var items []string
	for _, p := range running {
		fi, err := os.Stat(filepath.Join(procDir, strconv.Itoa(p.PID), "root"))
		if err == nil && os.SameFile(fi, rootFI) {
			items = append(items, "x\x00"+p.State+"\x00"+p.Path)
		}
	}
	for p := range open.forRoot(root) {
		items = append(items, "o\x00"+p)
	}
	slices.Sort(items)
	items = slices.Compact(items)
	h := sha256.New()
	for _, it := range items {
		h.Write([]byte(it))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (r *runner) containers(scanContent bool, running []artifact.RunningExe, open openFileIndex) *report.ContainersSection {
	if r.expired() {
		return &report.ContainersSection{SectionMeta: r.skipped(false)}
	}
	var sec *report.ContainersSection
	if !r.bounded(func() { sec = container.Collect(r.ctx, r.env) }) {
		return &report.ContainersSection{SectionMeta: r.skipped(true)}
	}
	if sec == nil {
		return nil
	}
	sec.InventoryCoverage = sec.Coverage

	notScanned := ""
	switch {
	case !r.env.Policy.ScanContainers:
		notScanned = "content scanning is disabled by policy"
	case !scanContent:
		notScanned = "content not scanned: the probe cannot read other users' processes"
	}
	if notScanned != "" {
		for i := range sec.Containers {
			setCoverage(&sec.Containers[i], report.CoverageNone, notScanned)
		}
	} else {
		// The scan works on a copy, so that the inventory survives a scan
		// that has to be abandoned.
		base := *sec
		inventory := slices.Clone(sec.Containers)
		var interrupted bool
		if !r.bounded(func() { interrupted = r.scanContainers(sec, running, open) }) {
			out := base
			out.Containers = inventory
			for i := range out.Containers {
				setCoverage(&out.Containers[i], report.CoverageNone, "container content scan did not finish within the runtime limit")
			}
			out.ImageScopes = nil
			out.Coverage = worse(base.Coverage, report.CoveragePartial)
			out.Reason = joinReasons(base.Reason, "container content scan did not finish within the runtime limit")
			sec = &out
		} else if interrupted {
			sec.Coverage = worse(sec.Coverage, report.CoveragePartial)
			sec.Reason = joinReasons(sec.Reason, "runtime limit reached during the container content scan")
		}
	}

	for i := range sec.Containers {
		sec.Containers[i].InitPID = 0
		sec.Containers[i].UpperDir = ""
	}
	if d, err := containersDigest(sec); err == nil {
		sec.Digest = d
	} else {
		r.log.Warn("container digest", "err", err)
	}
	return sec
}

// scanContainers fills ImageScopes and the content coverage of every
// container. It reports whether the runtime limit cut it short.
func (r *runner) scanContainers(sec *report.ContainersSection, running []artifact.RunningExe, open openFileIndex) bool {
	maxScans := r.opts.MaxContainers
	if maxScans <= 0 {
		maxScans = defaultMaxContainers
	}
	perContainer := r.opts.ContainerTimeout
	if perContainer <= 0 {
		perContainer = defaultContainerTimeout
	}

	// Containers that were started first are scanned first, so that the
	// choice is stable between runs.
	order := make([]int, len(sec.Containers))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a, b int) int {
		return sec.Containers[a].StartedAt.Compare(sec.Containers[b].StartedAt)
	})

	scans := map[string]*imageScan{}
	r.reuseImageScans(sec, scans, running, open)
	scanned := 0
	interrupted := false
	for _, i := range order {
		ct := &sec.Containers[i]
		switch {
		case !ct.Running:
			setCoverage(ct, report.CoverageNone, "container is not running")
			continue
		case ct.InitPID <= 0:
			setCoverage(ct, report.CoverageNone, "init process of the container is unknown")
			continue
		case r.expired():
			interrupted = true
			setCoverage(ct, report.CoverageNone, "runtime limit reached before the container was scanned")
			continue
		}
		img := scans[ct.ImageDigest]
		needImage := img == nil && ct.ImageDigest != ""
		needUpper := ct.UpperDir != ""
		if (needImage || needUpper) && scanned >= maxScans {
			if img == nil {
				setCoverage(ct, report.CoverageNone, fmt.Sprintf("limit of %d scanned containers per run reached", maxScans))
				continue
			}
			needUpper = false
		}
		if needImage || needUpper {
			scanned++
		}

		ctx, cancel := context.WithTimeout(r.ctx, perContainer)
		root := r.containerRoot(ct)
		if needImage {
			activity := rootActivity(r.env.Proc, root, running, open)
			img = r.scanImage(ctx, ct, root, running, open)
			scans[ct.ImageDigest] = img
			if img.coverage != report.CoverageNone {
				sec.ImageScopes = append(sec.ImageScopes, img.scope)
			}
			if ctx.Err() == nil {
				r.storeImageScan(ct, img, activity)
			}
		}
		r.linkContainerPackages(ctx, root, img)
		source := img != nil && img.scope.FromContainer == ct.ID

		var cov report.Coverage
		var reasons []string
		switch {
		case img == nil && ct.Reason != "":
			// The inventory says why the digest is unknown.
			cov = report.CoverageNone
			reasons = append(reasons, "image content not scanned")
		case img == nil:
			cov = report.CoverageNone
			reasons = append(reasons, "image digest unknown; image content not scanned")
		default:
			cov = img.coverage
			reasons = appendReason(reasons, img.reason)
		}
		if needUpper {
			upperCov, upperReason := r.scanUpper(ctx, ct, root, img)
			if upperCov != report.CoverageFull {
				reasons = append(reasons, "writable layer: "+upperReason)
			}
			switch {
			case cov == report.CoverageNone && upperCov != report.CoverageNone:
				// Only the writable layer was read.
				cov = report.CoveragePartial
			case upperCov != report.CoverageFull:
				cov = worse(cov, report.CoveragePartial)
			}
			if source {
				dropRuntimeFromScope(sec, img, ct.RuntimeArtifacts)
			}
		} else if img != nil && !source && cov == report.CoverageFull {
			cov = report.CoveragePartial
			reasons = append(reasons, fmt.Sprintf("writable layer not found; only the image content read through container %s is covered", shortID(img.scope.FromContainer)))
		}
		if ctx.Err() != nil && r.ctx.Err() == nil {
			cov = worse(cov, report.CoveragePartial)
			reasons = append(reasons, fmt.Sprintf("scan stopped after %s", perContainer))
		}
		if r.ctx.Err() != nil {
			interrupted = true
		}
		cancel()
		setCoverage(ct, cov, strings.Join(reasons, "; "))
	}
	slices.SortFunc(sec.ImageScopes, func(a, b report.ImageScope) int { return strings.Compare(a.Digest, b.Digest) })
	return interrupted
}

// scanImage reads the software of one image through the root of a running
// container. Version commands are never run there; the artifact collector
// restricts itself to static extraction for roots other than "/".
func (r *runner) scanImage(ctx context.Context, ct *report.Container, root string, running []artifact.RunningExe, open openFileIndex) *imageScan {
	img := &imageScan{scope: report.ImageScope{Digest: ct.ImageDigest, FromContainer: ct.ID}}
	if _, err := os.ReadDir(root); err != nil {
		img.coverage = report.CoverageNone
		img.reason = "container root unreadable: " + errText(err)
		return img
	}
	env := r.env.WithRoot(root)
	host := hostinfo.Collect(ctx, env)
	if host != nil {
		osInfo := host.OS
		img.scope.OS = &osInfo
	}
	pkgs, ix := pkgdb.Collect(ctx, env)
	img.owner = ix
	// The container root is image content: it is walked whole whatever the
	// walk paths of the host are.
	in := artifact.Inputs{Owner: ix.Owner, Running: running, OpenFiles: open.forRoot(root), WalkPaths: []string{"/"},
		Detectors: r.detectors}
	arts := artifact.Collect(ctx, env, in)

	img.coverage = report.CoverageFull
	var reasons []string
	for _, s := range []struct {
		name string
		meta report.SectionMeta
	}{{"packages", pkgs.SectionMeta}, {"artifacts", arts.SectionMeta}} {
		img.coverage = worse(img.coverage, s.meta.Coverage)
		if s.meta.Reason != "" {
			reasons = append(reasons, s.name+": "+s.meta.Reason)
		}
	}
	if img.coverage == report.CoverageNone {
		img.coverage = report.CoveragePartial
	}
	img.reason = strings.Join(reasons, "; ")
	img.scope.Packages = pkgs.Packages
	img.scope.Artifacts = arts.Artifacts
	return img
}

// linkContainerPackages links the processes running in a container root to
// the packages of its image.
func (r *runner) linkContainerPackages(ctx context.Context, root string, img *imageScan) {
	if r.procs == nil || img == nil || ctx.Err() != nil {
		return
	}
	if img.owner == nil {
		if !img.reused {
			return
		}
		_, img.owner = pkgdb.Collect(ctx, r.env.WithRoot(root))
	}
	linkPackages(r.env.Proc, r.procs, root, img.owner.Owner)
}

// scanUpper reads the artifacts in the writable layer of a container. Paths
// are relative to the container root, root is the container root as the
// probe opens it.
func (r *runner) scanUpper(ctx context.Context, ct *report.Container, root string, img *imageScan) (report.Coverage, string) {
	dir := r.env.Path(ct.UpperDir)
	if _, err := os.ReadDir(dir); err != nil {
		return report.CoverageNone, "unreadable: " + errText(err)
	}
	if img != nil && img.reused && img.owner == nil {
		// The package database of a reused image is read from this
		// container; reading it is cheap next to walking the image.
		_, img.owner = pkgdb.Collect(ctx, r.env.WithRoot(root))
	}
	env := r.env.WithRoot(dir)
	in := artifact.Inputs{WalkPaths: []string{"/"}, Detectors: r.detectors}
	if img != nil && img.owner != nil {
		in.Owner = img.owner.Owner
	}
	sec := artifact.Collect(ctx, env, in)
	for i := range sec.Artifacts {
		sec.Artifacts[i].Layer = report.LayerRuntime
	}
	ct.RuntimeArtifacts = sec.Artifacts
	return sec.Coverage, sec.Reason
}

// dropRuntimeFromScope removes from the image scope the files that belong to
// the writable layer of the container the scope was read from, and marks the
// rest as image content.
func dropRuntimeFromScope(sec *report.ContainersSection, img *imageScan, runtime []report.Artifact) {
	paths := make(map[string]bool, len(runtime))
	for _, a := range runtime {
		paths[a.Path] = true
	}
	kept := img.scope.Artifacts[:0]
	for _, a := range img.scope.Artifacts {
		if paths[a.Path] {
			continue
		}
		a.Layer = report.LayerImage
		kept = append(kept, a)
	}
	img.scope.Artifacts = kept
	for i := range sec.ImageScopes {
		if sec.ImageScopes[i].Digest == img.scope.Digest {
			sec.ImageScopes[i].Artifacts = kept
		}
	}
}

// setCoverage sets the content coverage of a container. A reason the
// inventory gave (such as an image digest that could not be verified) is
// kept in front. It is called once per container.
func setCoverage(ct *report.Container, c report.Coverage, reason string) {
	ct.Coverage = c
	switch {
	case ct.Reason == "":
		ct.Reason = reason
	case reason != "":
		ct.Reason += "; " + reason
	}
	if c == report.CoverageFull {
		ct.Reason = ""
	}
}

var coverageRank = map[report.Coverage]int{report.CoverageFull: 0, report.CoveragePartial: 1, report.CoverageNone: 2}

// worse returns the lower of two coverages.
func worse(a, b report.Coverage) report.Coverage {
	if coverageRank[b] > coverageRank[a] {
		return b
	}
	return a
}

func appendReason(list []string, r string) []string {
	if r == "" {
		return list
	}
	return append(list, r)
}

func joinReasons(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

// errText drops the path from a *fs.PathError.
func errText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

type containersDigestBody struct {
	Version     int                 `json:"v"`
	Runtimes    []string            `json:"runtimes"`
	Containers  []report.Container  `json:"containers"`
	Images      []report.Image      `json:"images"`
	ImageScopes []report.ImageScope `json:"image_scopes"`
}

// containersDigest covers what is uploaded, including the image scopes and
// the per-container coverage the probe added.
func containersDigest(sec *report.ContainersSection) (string, error) {
	return report.Digest(containersDigestBody{
		Version:     containerDigestVersion,
		Runtimes:    sec.Runtimes,
		Containers:  sec.Containers,
		Images:      sec.Images,
		ImageScopes: sec.ImageScopes,
	})
}
