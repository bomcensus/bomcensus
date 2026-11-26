// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package artifact

import (
	"bytes"
	"context"
	"crypto/sha1"
	"debug/buildinfo"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/bomcensus/bomcensus/internal/collect"
	"github.com/bomcensus/bomcensus/internal/report"
)

// Cache keys. Bump the version when the cached shape or meaning changes.
const (
	cacheJar  = "artifact.jar.v1"
	cacheGo   = "artifact.go.v1"
	cacheSHA1 = "artifact.sha1"
)

var elfMagic = []byte("\x7fELF")

// visitFile inspects the regular file name in the directory dirfd, whose
// logical path is dir. The file is looked up relative to dirfd: the walk
// visits every file of the file system, and resolving each full path again
// costs more than the rest of the visit for most files.
func (c *collector) visitFile(ctx context.Context, dirfd int, dir, name string) {
	isJar := isArchiveName(name)
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return
	}
	executable := st.Mode&0o111 != 0
	if st.Mode&unix.S_IFMT != unix.S_IFREG || !isJar && !executable || st.Size < int64(len(elfMagic)) {
		return
	}
	logical := path.Join(dir, name)
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ELOOP) {
			c.st.unreadableFiles++
		}
		return
	}
	f := os.NewFile(uintptr(fd), c.env.Path(logical))
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return
	}
	// The file at the name must still be the one stat'ed above.
	if now, ok := fi.Sys().(*syscall.Stat_t); !ok || uint64(now.Dev) != st.Dev || now.Ino != st.Ino {
		return
	}
	if isJar {
		c.inspectJar(ctx, logical, f, fi)
		return
	}
	if !isELF(f) {
		return
	}
	_, running := c.runningByPath[logical]
	c.inspectELF(ctx, elfInput{logical: logical, file: f, fi: fi, mayExec: true, running: running})
}

func isELF(f *os.File) bool {
	var b [4]byte
	n, _ := f.ReadAt(b[:], 0)
	return n == 4 && bytes.Equal(b[:], elfMagic)
}

// hashes returns the SHA-256 (and SHA-1 if asked) of f through the cache.
func (c *collector) hashes(f *os.File, fi os.FileInfo, withSHA1 bool) (string, string) {
	var s256, s1 string
	if _, err := f.Seek(0, io.SeekStart); err == nil {
		if h, err := c.env.Cache.SHA256File(f); err == nil {
			s256 = h
		} else {
			c.log.Debug("hash", "path", f.Name(), "err", err)
		}
	}
	if !withSHA1 || fi.Size() > collect.MaxHashSize {
		return s256, ""
	}
	if c.env.Cache.Extra(fi, cacheSHA1, &s1) && s1 != "" {
		return s256, s1
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return s256, ""
	}
	h := sha1.New()
	if _, err := io.Copy(h, f); err != nil {
		return s256, ""
	}
	s1 = hex.EncodeToString(h.Sum(nil))
	c.env.Cache.SetExtra(fi, cacheSHA1, s1)
	return s256, s1
}

// inspectJar reports a Java archive, its nested archives and any archive
// detector that matches it.
func (c *collector) inspectJar(ctx context.Context, logical string, f *os.File, fi os.FileInfo) {
	if id, ok := idOf(fi); ok {
		c.seenJar[id] = true
	}
	var res jarResult
	if !c.env.Cache.Extra(fi, cacheJar, &res) {
		res = scanJar(ctx, f, fi.Size(), path.Base(logical), c.limits)
		if ctx.Err() != nil {
			return
		}
		c.env.Cache.SetExtra(fi, cacheJar, res)
	}
	s256, s1 := c.hashes(f, fi, true)
	for _, a := range res.Artifacts {
		a.Path = logical
		if len(a.Nested) == 0 {
			a.SHA256, a.SHA1, a.Size = s256, s1, fi.Size()
		}
		c.add(a)
	}
	for _, k := range res.Limits {
		c.st.limitHits[k]++
	}
	c.st.corruptArchives += res.Corrupt

	for _, d := range c.detectors {
		if d.Archive && d.matches(logical) {
			c.addSoftware(ctx, d, staticSource{logical: logical, file: f, size: fi.Size()}, fi, s256, false)
		}
	}
}

// elfInput is an executable to inspect.
type elfInput struct {
	logical string
	file    *os.File
	fi      os.FileInfo
	// mayExec is false for deleted and memfd executables.
	mayExec bool
	// running is true when a process executes this file as it is on disk
	// (report.ExeNormal), so that the file at the path is the one running.
	running bool
}

// inspectELF reports Go build info and known software of an executable.
func (c *collector) inspectELF(ctx context.Context, in elfInput) {
	if id, ok := idOf(in.fi); ok {
		c.seenExe[id] = true
	}
	gi := c.goInfo(in.file, in.fi)
	var s256 string
	hashed := false
	hash := func() string {
		if !hashed {
			s256, _ = c.hashes(in.file, in.fi, false)
			hashed = true
		}
		return s256
	}
	first := len(c.out)
	if gi != nil {
		c.addGo(in.logical, gi, hash(), in.fi.Size())
	}
	for _, d := range c.detectors {
		if d.Archive || !d.matches(in.logical) {
			continue
		}
		src := staticSource{logical: in.logical, file: in.file, size: in.fi.Size(), goInfo: gi}
		c.addSoftware(ctx, d, src, in.fi, hash(), in.mayExec && gi == nil)
	}
	// A running executable that nothing above recognized is still reported
	// when an OS package owns it: the server links the package to the
	// process through this artifact's path and hash.
	if len(c.out) == first && in.running && c.in.Owner != nil {
		if pkg, ok := c.in.Owner(in.logical); ok {
			c.add(report.Artifact{
				Kind:         report.ArtifactPackageFile,
				Path:         in.logical,
				Name:         pkg,
				Method:       report.MethodPackageDB,
				SHA256:       hash(),
				Size:         in.fi.Size(),
				OwnerPackage: pkg,
			})
		}
	}
}

// goInfo is the part of a Go binary's build info that is reported.
type goInfo struct {
	GoVersion string            `json:"g"`
	Path      string            `json:"p,omitempty"`
	Main      goMod             `json:"m"`
	Deps      []goMod           `json:"d,omitempty"`
	Settings  map[string]string `json:"s,omitempty"`
}

type goMod struct {
	Path    string `json:"p"`
	Version string `json:"v,omitempty"`
}

// goInfo reads the build info of f, through the cache. It returns nil for
// files that are not Go binaries.
func (c *collector) goInfo(f *os.File, fi os.FileInfo) *goInfo {
	var cached struct {
		Info *goInfo `json:"i"`
	}
	if c.env.Cache.Extra(fi, cacheGo, &cached) {
		return cached.Info
	}
	bi, err := buildinfo.Read(f)
	if err == nil {
		cached.Info = convertBuildInfo(bi)
	}
	c.env.Cache.SetExtra(fi, cacheGo, cached)
	return cached.Info
}

func convertBuildInfo(bi *buildinfo.BuildInfo) *goInfo {
	gi := &goInfo{
		GoVersion: bi.GoVersion,
		Path:      bi.Path,
		Main:      goMod{Path: bi.Main.Path, Version: bi.Main.Version},
		Settings:  map[string]string{},
	}
	for _, d := range bi.Deps {
		m := goMod{Path: d.Path, Version: d.Version}
		if r := d.Replace; r != nil {
			if r.Version != "" {
				m = goMod{Path: r.Path, Version: r.Version}
			} else {
				// Replaced by a local directory: the version is unknown.
				m.Version = ""
			}
		}
		gi.Deps = append(gi.Deps, m)
	}
	for _, s := range bi.Settings {
		gi.Settings[s.Key] = s.Value
	}
	return gi
}

func (c *collector) addGo(logical string, gi *goInfo, s256 string, size int64) {
	name := gi.Main.Path
	if name == "" {
		name = gi.Path
	}
	c.add(report.Artifact{
		Kind:      report.ArtifactGoBinary,
		Path:      logical,
		Name:      name,
		Version:   gi.Main.Version,
		GoVersion: gi.GoVersion,
		GOOS:      gi.Settings["GOOS"],
		GOARCH:    gi.Settings["GOARCH"],
		Module:    gi.Main.Path,
		Method:    report.MethodBuildInfo,
		SHA256:    s256,
		Size:      size,
	})
	for _, d := range gi.Deps {
		a := report.Artifact{
			Kind:    report.ArtifactGoModule,
			Path:    logical,
			Name:    d.Path,
			Module:  d.Path,
			Version: d.Version,
			Method:  report.MethodBuildInfo,
		}
		if d.Version != "" {
			a.PURL = "pkg:golang/" + d.Path + "@" + purlEscape(d.Version)
		}
		c.add(a)
	}
}

// addSoftware reports a detector match. The version comes from the version
// command when it may run and its output parses, else from static rules.
func (c *collector) addSoftware(ctx context.Context, d *Detector, src staticSource, fi os.FileInfo, s256 string, mayExec bool) {
	a := report.Artifact{
		Kind:     report.ArtifactSoftware,
		Path:     src.logical,
		Name:     d.Name,
		Detector: d.ID,
		Method:   report.MethodStatic,
		SHA256:   s256,
		Size:     src.size,
	}
	st, stOK := c.static(d, src, fi)

	var ex match
	exOK := false
	if mayExec && c.execAllowed(d) {
		res := c.versionCommand(ctx, d, src.logical, src.file, fi)
		if res.Ran && res.Output != nil {
			a.VersionOutput = res.Output
			ex, exOK = firstMatch(d.Parse, []byte(res.Output.Stdout+"\n"+res.Output.Stderr))
			exOK = exOK && d.accepts(ex)
		}
	}
	var m match
	switch {
	case exOK:
		a.Method = report.MethodExec
		m = ex
		if stOK && st.Version != ex.Version {
			a.StaticVersion = st.Version
		}
	case stOK:
		m = st
	}
	a.Version = m.Version
	a.Build = m.Build
	a.Name = cmpOr(m.Name, d.Name)
	a.PURL = expand(cmpOr(m.PURL, d.PURL), m.Version, purlEscape)
	a.CPE = expand(cmpOr(m.CPE, d.CPE), m.Version, cpeEscape)
	c.add(a)
}

// execAllowed applies the policy: version commands run only when enabled
// and only for files on the real root. Inside a container root seen through
// /proc/<pid>/root only static extraction is used.
func (c *collector) execAllowed(d *Detector) bool {
	return len(d.Exec) > 0 && c.env.Policy.ExecVersion && (c.env.Root == "/" || c.env.Root == "")
}

// inspectRunning inspects the executables of running processes that the
// walk did not see: deleted or replaced files, memfd executables and files
// in excluded directories.
func (c *collector) inspectRunning(ctx context.Context, running []RunningExe) {
	for _, r := range running {
		if ctx.Err() != nil {
			return
		}
		if r.Path == "" {
			continue
		}
		exe := filepath.Join(c.procDir(), strconv.Itoa(r.PID), "exe")
		info, err := os.Stat(exe)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		id, ok := idOf(info)
		if !ok || c.seenExe[id] {
			continue
		}
		f, err := os.Open(exe)
		if err != nil {
			continue
		}
		fi, err := f.Stat()
		if err == nil && fi.Mode().IsRegular() && isELF(f) {
			mayExec := r.State == report.ExeNormal || r.State == report.ExeReplaced
			first := len(c.out)
			c.inspectELF(ctx, elfInput{logical: r.Path, file: f, fi: fi, mayExec: mayExec, running: r.State == report.ExeNormal})
			// The path may hold another file or none; what was found here
			// is the binary in memory.
			for i := first; i < len(c.out); i++ {
				c.out[i].InUse = true
			}
		}
		c.seenExe[id] = true
		f.Close()
	}
}

// inspectOpenJars inspects the archives held open by running processes
// that the walk did not see: archives outside the walk paths, and deleted or
// replaced ones. They are read through the descriptor the process holds,
// which is the file in use even when the path now holds another or none.
func (c *collector) inspectOpenJars(ctx context.Context) {
	paths := make([]string, 0, len(c.in.OpenFiles))
	for p := range c.in.OpenFiles {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	for _, p := range paths {
		for _, ref := range c.in.OpenFiles[p] {
			if ctx.Err() != nil {
				return
			}
			if c.inspectOpenJar(ctx, p, ref) {
				break
			}
		}
	}
}

// inspectOpenJar inspects the archive open as ref, whose logical path is p.
// It reports whether the descriptor could be read.
func (c *collector) inspectOpenJar(ctx context.Context, p string, ref OpenRef) bool {
	fdPath := filepath.Join(c.procDir(), strconv.Itoa(ref.PID), "fd", strconv.Itoa(ref.FD))
	f, err := os.Open(fdPath)
	if err != nil {
		return false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	if id, ok := idOf(fi); ok && c.seenJar[id] {
		return true
	}
	first := len(c.out)
	c.inspectJar(ctx, p, f, fi)
	for i := first; i < len(c.out); i++ {
		c.out[i].InUse = true
	}
	return true
}

func (c *collector) procDir() string {
	if c.env.Proc == "" {
		return "/proc"
	}
	return c.env.Proc
}

// sameRoot keeps the processes whose root directory is the inspected root,
// so that processes of containers are not attributed to the host.
func (c *collector) sameRoot(running []RunningExe) []RunningExe {
	root, err := os.Stat(c.env.Path("/"))
	if err != nil {
		return nil
	}
	var out []RunningExe
	for _, r := range running {
		pr, err := os.Stat(filepath.Join(c.procDir(), strconv.Itoa(r.PID), "root"))
		if err == nil && os.SameFile(pr, root) {
			out = append(out, r)
		}
	}
	return out
}

// trimDeleted removes the suffix the kernel appends to deleted paths.
func trimDeleted(p string) string {
	return strings.TrimSuffix(p, " (deleted)")
}
