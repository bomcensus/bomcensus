// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package probe

import (
	"context"
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
)

// imageScan is the content read for one image digest.
type imageScan struct {
	scope    report.ImageScope
	owner    *pkgdb.Index
	coverage report.Coverage
	reason   string
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
		root := filepath.Join(r.env.Proc, strconv.Itoa(ct.InitPID), "root")
		if needImage {
			img = r.scanImage(ctx, ct, root, running, open)
			scans[ct.ImageDigest] = img
			if img.coverage != report.CoverageNone {
				sec.ImageScopes = append(sec.ImageScopes, img.scope)
			}
		}
		source := img != nil && img.scope.FromContainer == ct.ID

		var cov report.Coverage
		var reasons []string
		switch {
		case img == nil:
			cov = report.CoverageNone
			reasons = append(reasons, "image digest unknown; image content not scanned")
		default:
			cov = img.coverage
			reasons = appendReason(reasons, img.reason)
		}
		if needUpper {
			upperCov, upperReason := r.scanUpper(ctx, ct, img)
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
	in := artifact.Inputs{Owner: ix.Owner, Running: running, OpenFiles: open.forRoot(root)}
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

// scanUpper reads the artifacts in the writable layer of a container. Paths
// are relative to the container root.
func (r *runner) scanUpper(ctx context.Context, ct *report.Container, img *imageScan) (report.Coverage, string) {
	dir := r.env.Path(ct.UpperDir)
	if _, err := os.ReadDir(dir); err != nil {
		return report.CoverageNone, "unreadable: " + errText(err)
	}
	env := r.env.WithRoot(dir)
	var in artifact.Inputs
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

func setCoverage(ct *report.Container, c report.Coverage, reason string) {
	ct.Coverage = c
	ct.Reason = reason
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
