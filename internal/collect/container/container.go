// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

// Package container inventories the containers and images of a host from the
// state that Docker and containerd keep on disk. It never connects to a
// runtime socket and does not look inside containers; the probe scans a
// running container's root through Container.InitPID.
//
// Image digests are the digest the image was pulled by: the manifest list,
// OCI index or manifest digest (Docker's repo digest, containerd's image
// target, what Kubernetes shows as imageID). Only images that have none, such
// as images built locally with the Docker graph driver store, are reported by
// their config digest (the Docker image id). Containers and images use the
// same value, so Container.ImageDigest always matches an Image.Digest.
//
// A Docker container records the id of the image it was created from. A
// containerd container records only an image name, which follows the name
// when it is pulled again, so its digest is checked against the container's
// snapshot: the snapshot's parent is the chain id of the image's top layer.
// When no image with that chain id is in the store, or the check cannot be
// made, ImageDigest is left empty and Container.Reason says why. The probe
// then credits nothing to an image.
package container

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bomcensus/bomcensus/internal/collect"
	"github.com/bomcensus/bomcensus/internal/report"
)

// Runtime names used in ContainersSection.Runtimes and Container.Runtime.
const (
	RuntimeDocker     = "docker"
	RuntimeContainerd = "containerd"
)

// maxStateFile bounds the size of a JSON state file read into memory.
const maxStateFile = 8 << 20

// maxProblems is how many distinct problems a source reports in the reason.
const maxProblems = 4

const digestVersion = 1

// Collect reads the container runtime state of the host at env.Root. It
// returns nil when no runtime state exists. Unreadable state lowers the
// coverage and is explained in the reason.
func Collect(ctx context.Context, env *collect.Env) *report.ContainersSection {
	start := time.Now()
	c := &collector{
		ctx:      ctx,
		env:      env,
		log:      env.Log,
		images:   map[string]*report.Image{},
		runtimes: map[string]bool{},
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}

	dock := c.findDocker()
	roots := c.findContainerd(dock)
	for _, r := range roots {
		c.readContainerd(r)
	}
	if dock != nil {
		c.readDocker(dock, roots)
	}
	if len(c.sources) == 0 {
		return nil
	}

	sec := &report.ContainersSection{SectionMeta: report.SectionMeta{
		Coverage:    report.CoverageFull,
		CollectedAt: start.UTC(),
	}}
	for rt := range c.runtimes {
		sec.Runtimes = append(sec.Runtimes, rt)
	}
	sort.Strings(sec.Runtimes)
	sort.Slice(c.containers, func(i, j int) bool {
		a, b := c.containers[i], c.containers[j]
		if a.Runtime != b.Runtime {
			return a.Runtime < b.Runtime
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.ID < b.ID
	})
	sec.Containers = c.containers
	for _, img := range c.images {
		slices.Sort(img.RepoTags)
		img.RepoTags = slices.Compact(img.RepoTags)
		sec.Images = append(sec.Images, *img)
	}
	sort.Slice(sec.Images, func(i, j int) bool { return sec.Images[i].Digest < sec.Images[j].Digest })

	if d, err := sectionDigest(sec); err == nil {
		sec.Digest = d
	} else {
		c.log.Warn("container digest", "err", err)
	}

	sec.Coverage, sec.Reason = c.coverage()
	sec.DurationMs = time.Since(start).Milliseconds()
	return sec
}

type collector struct {
	ctx        context.Context
	env        *collect.Env
	log        *slog.Logger
	sources    []*source
	containers []report.Container
	images     map[string]*report.Image
	runtimes   map[string]bool
	cancelled  bool
}

// source is one runtime state directory. It tracks whether anything could be
// read and what could not.
type source struct {
	name     string
	read     bool
	problems []problem
}

type problem struct {
	what  string
	count int
}

func (c *collector) newSource(name string) *source {
	s := &source{name: name}
	c.sources = append(c.sources, s)
	return s
}

// fail records that something could not be read. Problems of the same kind
// are counted instead of listed.
func (s *source) fail(kind, logical string, err error) {
	for i := range s.problems {
		if strings.HasPrefix(s.problems[i].what, kind+" ") {
			s.problems[i].count++
			return
		}
	}
	s.problems = append(s.problems, problem{what: fmt.Sprintf("%s %s: %s", kind, logical, errText(err)), count: 1})
}

func (c *collector) coverage() (report.Coverage, string) {
	var reasons []string
	none := 0
	for _, s := range c.sources {
		if !s.read {
			none++
		}
		for i, p := range s.problems {
			if i == maxProblems {
				reasons = append(reasons, fmt.Sprintf("%s: %d more problems", s.name, len(s.problems)-maxProblems))
				break
			}
			r := s.name + ": " + p.what
			if p.count > 1 {
				r += fmt.Sprintf(" (and %d more)", p.count-1)
			}
			reasons = append(reasons, r)
		}
	}
	if c.cancelled {
		reasons = append(reasons, "collection interrupted")
	}
	switch {
	case none == len(c.sources):
		return report.CoverageNone, strings.Join(reasons, "; ")
	case len(reasons) > 0:
		return report.CoveragePartial, strings.Join(reasons, "; ")
	}
	return report.CoverageFull, ""
}

func (c *collector) done() bool {
	if c.ctx.Err() != nil {
		c.cancelled = true
		return true
	}
	return false
}

// image returns the entry for a digest, creating it.
func (c *collector) image(digest string) *report.Image {
	img := c.images[digest]
	if img == nil {
		img = &report.Image{Digest: digest}
		c.images[digest] = img
	}
	return img
}

func mergeImage(img *report.Image, tags []string, osName, arch string, size int64) {
	img.RepoTags = append(img.RepoTags, tags...)
	if img.OS == "" {
		img.OS = osName
	}
	if img.Arch == "" {
		img.Arch = arch
	}
	if img.Size == 0 {
		img.Size = size
	}
}

// ── file helpers ────────────────────────────────────────────────────────

// exists reports whether a logical path may exist. A permission error counts
// as existing: something is there that cannot be inspected.
func (c *collector) exists(logical string) bool {
	_, err := os.Lstat(c.env.Path(logical))
	return err == nil || !errors.Is(err, fs.ErrNotExist)
}

func (c *collector) readFile(logical string, limit int64) ([]byte, error) {
	f, err := c.env.Open(logical)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("larger than %d bytes", limit)
	}
	return data, nil
}

func (c *collector) readDir(logical string) ([]os.DirEntry, error) {
	return os.ReadDir(c.env.Path(logical))
}

// alive reports whether a process exists in the proc mount. Without a proc
// mount the runtime's state is trusted.
func (c *collector) alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	if c.env.Proc == "" {
		return true
	}
	_, err := os.Stat(filepath.Join(c.env.Proc, strconv.Itoa(pid)))
	return err == nil
}

// upperFromMountinfo returns the overlay upper directory of a process's root
// mount, as the host sees it.
func (c *collector) upperFromMountinfo(pid int) string {
	if pid <= 0 || c.env.Proc == "" {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(c.env.Proc, strconv.Itoa(pid), "mountinfo"))
	if err != nil {
		return ""
	}
	for line := range strings.Lines(string(data)) {
		pre, post, ok := strings.Cut(strings.TrimSpace(line), " - ")
		if !ok {
			continue
		}
		f := strings.Fields(pre)
		if len(f) < 5 || f[4] != "/" {
			continue
		}
		g := strings.Fields(post)
		if len(g) < 3 || g[0] != "overlay" {
			continue
		}
		for opt := range strings.SplitSeq(g[2], ",") {
			if v, ok := strings.CutPrefix(opt, "upperdir="); ok {
				return unescapeMountinfo(v)
			}
		}
	}
	return ""
}

// unescapeMountinfo decodes the octal escapes (\040 and friends) the kernel
// uses for white space and backslashes in mountinfo.
func unescapeMountinfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// errText drops the path from a *fs.PathError: reasons name the logical path
// themselves.
func errText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

func isNotExist(err error) bool { return errors.Is(err, fs.ErrNotExist) }

// safeName accepts a single path element written by a runtime.
func safeName(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\x00")
}

func joinLogical(elem ...string) string { return path.Join(elem...) }

// ── digest ──────────────────────────────────────────────────────────────

type digestBody struct {
	Version    int                `json:"v"`
	Runtimes   []string           `json:"runtimes"`
	Containers []report.Container `json:"containers"`
	Images     []report.Image     `json:"images"`
}

// sectionDigest covers what is uploaded. InitPID and UpperDir are probe
// hints and stay out.
func sectionDigest(sec *report.ContainersSection) (string, error) {
	body := digestBody{Version: digestVersion, Runtimes: sec.Runtimes, Images: sec.Images}
	body.Containers = make([]report.Container, 0, len(sec.Containers))
	for _, ct := range sec.Containers {
		ct.InitPID, ct.UpperDir = 0, ""
		body.Containers = append(body.Containers, ct)
	}
	return report.Digest(body)
}
