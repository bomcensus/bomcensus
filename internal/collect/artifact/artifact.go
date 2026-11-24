// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

// Package artifact finds software outside the package database: Java
// archives, Go binaries and files recognized by a known-software detector.
// Running executables that only an OS package accounts for are reported too,
// with just their owner, so that the package can be linked to its processes.
//
// The file system is walked once. Java archives and Go binaries are only
// parsed. Known software may have its version command run, in an isolated
// child process (see versionexec.go), when the policy allows it.
package artifact

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/bomcensus/bomcensus/internal/collect"
	"github.com/bomcensus/bomcensus/internal/report"
)

// RunningExe is the executable of a running process.
type RunningExe struct {
	PID  int
	Path string // logical path, without the " (deleted)" suffix
	// State is a report.Exe* value.
	State string
}

// Inputs are what other collectors already know.
type Inputs struct {
	// Owner returns the OS package that owns a logical path. May be nil.
	Owner func(path string) (pkg string, ok bool)
	// Running lists the executables of running processes. Processes whose
	// root directory is not env.Root (or cannot be checked) are ignored, so
	// that container processes are not attributed to the host.
	Running []RunningExe
	// OpenFiles maps a logical path to the open descriptors of processes
	// that hold it (jars in use). The path has no " (deleted)" suffix. May
	// be nil.
	OpenFiles map[string][]OpenRef
	// WalkPaths are the logical directories walked. Empty means no walk:
	// only Running and OpenFiles are inspected.
	WalkPaths []string
}

// OpenRef is an open file descriptor of a process.
type OpenRef struct {
	PID, FD int
}

// fileID identifies a file independently of its path.
type fileID struct {
	Dev, Ino uint64
}

func idOf(fi os.FileInfo) (fileID, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}, false
	}
	return fileID{Dev: uint64(st.Dev), Ino: st.Ino}, true
}

// collector holds the state of one run.
type collector struct {
	env       *collect.Env
	in        Inputs
	log       *slog.Logger
	detectors []*Detector
	limits    archiveLimits
	exec      execLimits
	// walkPaths are the logical directories the walk starts at, cleaned
	// and without nested duplicates.
	walkPaths []string
	// walked are the walk paths that could be opened.
	walked []string

	excludes []string
	mounts   *mountTable

	// runningByPath maps the path of a running, unmodified executable to
	// one of its processes.
	runningByPath map[string]int
	// seenExe holds the executables already inspected, so that a running
	// process is not inspected again through /proc.
	seenExe map[fileID]bool
	// seenJar holds the archives already inspected, so that an open jar is
	// not inspected again through /proc.
	seenJar map[fileID]bool
	// visitedDirs holds the mount roots already walked.
	visitedDirs map[fileID]bool

	out []report.Artifact
	st  stats
}

// stats counts what reduces coverage.
type stats struct {
	unreadableDirs  int
	unreadableFiles int
	tooDeep         int
	corruptArchives int
	limitHits       map[string]int
	cancelled       bool
	// rootErr is set when the inspected root cannot be opened; nothing of
	// the file system was seen then.
	rootErr error
}

// Collect inspects env.Root and returns the artifacts section: the
// executables and archives of running processes, and the files under
// in.WalkPaths.
func Collect(ctx context.Context, env *collect.Env, in Inputs) *report.ArtifactsSection {
	c := newCollector(env, in)
	return c.run(ctx)
}

func newCollector(env *collect.Env, in Inputs) *collector {
	log := env.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if env.Cache == nil {
		env = env.WithRoot(env.Root)
		env.Cache = collect.NewHashCache()
	}
	c := &collector{
		env:           env,
		in:            in,
		log:           log,
		detectors:     Detectors,
		limits:        defaultArchiveLimits,
		exec:          defaultExecLimits,
		walkPaths:     cleanWalkPaths(in.WalkPaths),
		runningByPath: map[string]int{},
		seenExe:       map[fileID]bool{},
		seenJar:       map[fileID]bool{},
		visitedDirs:   map[fileID]bool{},
		st:            stats{limitHits: map[string]int{}},
	}
	c.excludes = buildExcludes(env.Policy.ExcludePaths)
	return c
}

func (c *collector) run(ctx context.Context) *report.ArtifactsSection {
	start := time.Now()
	c.mounts = loadMounts(c.env)

	running := c.sameRoot(c.in.Running)
	for i := range running {
		running[i].Path = trimDeleted(running[i].Path)
	}
	slices.SortFunc(running, func(a, b RunningExe) int { return a.PID - b.PID })
	for _, r := range running {
		if r.State == report.ExeNormal && r.Path != "" {
			if _, ok := c.runningByPath[r.Path]; !ok {
				c.runningByPath[r.Path] = r.PID
			}
		}
	}

	if c.openRoot() {
		c.walk(ctx)
		c.inspectRunning(ctx, running)
		c.inspectOpenJars(ctx)
	}
	if ctx.Err() != nil {
		c.st.cancelled = true
	}

	sec := &report.ArtifactsSection{}
	sec.CollectedAt = start.UTC()
	sec.WalkPaths = c.walked
	sec.Artifacts = c.finish()
	sec.Coverage, sec.Reason = c.st.coverage()
	if d, err := report.Digest(sec.Artifacts); err == nil {
		sec.Digest = d
	} else {
		c.log.Warn("artifact digest", "err", err)
	}
	sec.DurationMs = time.Since(start).Milliseconds()
	return sec
}

// add records an artifact and fills what depends only on its path.
func (c *collector) add(a report.Artifact) {
	if c.in.Owner != nil {
		if pkg, ok := c.in.Owner(a.Path); ok {
			a.OwnerPackage = pkg
		}
	}
	if len(c.in.OpenFiles[a.Path]) > 0 {
		a.InUse = true
	}
	if _, ok := c.runningByPath[a.Path]; ok {
		a.InUse = true
	}
	c.out = append(c.out, a)
}

// finish sorts the artifacts and drops exact duplicates.
func (c *collector) finish() []report.Artifact {
	slices.SortFunc(c.out, compareArtifacts)
	return slices.CompactFunc(c.out, func(a, b report.Artifact) bool { return compareArtifacts(a, b) == 0 })
}

func compareArtifacts(a, b report.Artifact) int {
	for _, d := range [...]int{
		strings.Compare(a.Path, b.Path),
		slices.Compare(a.Nested, b.Nested),
		strings.Compare(a.Kind, b.Kind),
		strings.Compare(a.Detector, b.Detector),
		strings.Compare(a.Module, b.Module),
		strings.Compare(a.GroupID, b.GroupID),
		strings.Compare(a.Name, b.Name),
		strings.Compare(a.Version, b.Version),
		strings.Compare(a.SHA256, b.SHA256),
		strings.Compare(a.SHA1, b.SHA1),
	} {
		if d != 0 {
			return d
		}
	}
	return 0
}

func (s *stats) coverage() (report.Coverage, string) {
	if s.rootErr != nil {
		return report.CoverageNone, "cannot open the root directory: " + errnoText(s.rootErr)
	}
	var reasons []string
	if s.cancelled {
		reasons = append(reasons, "walk was cancelled before it finished")
	}
	if s.unreadableDirs > 0 {
		reasons = append(reasons, plural(s.unreadableDirs, "directory", "directories")+" could not be read")
	}
	if s.unreadableFiles > 0 {
		reasons = append(reasons, plural(s.unreadableFiles, "file", "files")+" could not be read")
	}
	if s.tooDeep > 0 {
		reasons = append(reasons, plural(s.tooDeep, "directory", "directories")+fmt.Sprintf(" deeper than %d levels skipped", maxWalkDepth))
	}
	if s.corruptArchives > 0 {
		reasons = append(reasons, plural(s.corruptArchives, "archive", "archives")+" could not be parsed")
	}
	kinds := make([]string, 0, len(s.limitHits))
	for k := range s.limitHits {
		kinds = append(kinds, k)
	}
	slices.Sort(kinds)
	for _, k := range kinds {
		reasons = append(reasons, fmt.Sprintf("archive %s limit reached in %s", k, plural(s.limitHits[k], "archive", "archives")))
	}
	if len(reasons) == 0 {
		return report.CoverageFull, ""
	}
	return report.CoveragePartial, strings.Join(reasons, "; ")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// parentDir returns the logical directory n levels above p.
func parentDir(p string, n int) string {
	for range n {
		p = path.Dir(p)
	}
	return p
}
