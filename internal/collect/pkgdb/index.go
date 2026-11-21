// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pkgdb

import (
	"bytes"
	"context"
	"hash/maphash"
	"log/slog"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/bomcensus/bomcensus/internal/collect"
)

// maxIndexFiles bounds the number of files in an Index. An entry costs about
// 20 bytes: paths are kept as 64-bit hashes, not as strings.
const maxIndexFiles = 2_000_000

type sourceKind int

const (
	srcDpkgInfo sourceKind = iota + 1
	srcDpkgStatusD
	srcRPM
	srcAPK
)

type indexSource struct {
	kind sourceKind
	path string
}

// Index maps files to the packages that own them. It is built on the first
// call to Owner from the databases Collect read, and is safe for concurrent
// use. A nil Index owns nothing.
type Index struct {
	ctx context.Context
	env *collect.Env
	log *slog.Logger

	srcs []indexSource
	// installed holds the dpkg packages that are present, so that file lists
	// of removed packages are ignored. statusD maps a status.d file name to
	// its package.
	installed map[string]bool
	statusD   map[string]string

	once     sync.Once
	mu       sync.Mutex // guards res after the build
	res      *resolver
	seed     maphash.Seed
	files    map[uint64]uint32
	names    []string
	nameID   map[string]uint32
	complete bool
}

func newIndex(ctx context.Context, env *collect.Env) *Index {
	// The build happens later, possibly after the caller's context for
	// Collect is gone. It is bounded by maxIndexFiles instead.
	ix := &Index{ctx: context.WithoutCancel(ctx), env: env, log: env.Log}
	if ix.log == nil {
		ix.log = slog.New(slog.DiscardHandler)
	}
	return ix
}

func (ix *Index) addSource(s indexSource) {
	for _, x := range ix.srcs {
		if x == s {
			return
		}
	}
	ix.srcs = append(ix.srcs, s)
}

func (ix *Index) addInstalled(name string) {
	if ix.installed == nil {
		ix.installed = map[string]bool{}
	}
	ix.installed[name] = true
}

func (ix *Index) addStatusDName(file, pkg string) {
	if ix.statusD == nil {
		ix.statusD = map[string]string{}
	}
	ix.statusD[file] = pkg
}

// Owner returns the name of the package that owns the file at the absolute
// logical path p. Symlinked directories are resolved inside the inspected
// root, so "/bin/sh" and "/usr/bin/sh" give the same answer on a merged-/usr
// system.
func (ix *Index) Owner(p string) (pkg string, ok bool) {
	if ix == nil || !path.IsAbs(p) {
		return "", false
	}
	ix.once.Do(ix.build)
	if len(ix.files) == 0 {
		return "", false
	}
	p = path.Clean(p)
	dir, base := path.Split(p)
	if base == "" {
		return "", false
	}
	ix.mu.Lock()
	cd := ix.res.dir(path.Clean(dir))
	ix.mu.Unlock()
	id, ok := ix.files[ix.hash(cd, base)]
	if !ok {
		return "", false
	}
	return ix.names[id], true
}

// Complete reports whether every file list was read. It builds the index if
// that has not happened yet.
func (ix *Index) Complete() bool {
	if ix == nil {
		return false
	}
	ix.once.Do(ix.build)
	return ix.complete
}

func (ix *Index) hash(dir, base string) uint64 {
	var h maphash.Hash
	h.SetSeed(ix.seed)
	h.WriteString(dir)
	if dir != "/" {
		h.WriteByte('/')
	}
	h.WriteString(base)
	return h.Sum64()
}

func (ix *Index) build() {
	ix.seed = maphash.MakeSeed()
	ix.res = newResolver(ix.env)
	ix.files = map[uint64]uint32{}
	ix.nameID = map[string]uint32{}
	ix.complete = true
	for _, s := range ix.srcs {
		if !ix.complete && len(ix.files) >= maxIndexFiles {
			break
		}
		var ok bool
		switch s.kind {
		case srcDpkgInfo:
			ok = ix.buildDpkgInfo(s.path)
		case srcDpkgStatusD:
			ok = ix.buildStatusD(s.path)
		case srcRPM:
			ok = ix.buildRPM(s.path)
		case srcAPK:
			ok = ix.buildAPK(s.path)
		}
		if !ok {
			ix.complete = false
		}
	}
	ix.nameID = nil
	ix.installed = nil
	ix.statusD = nil
	ix.log.Debug("package file index built", "files", len(ix.files), "packages", len(ix.names), "complete", ix.complete)
}

// add records one file. It returns false when the index is full or the
// context is done.
func (ix *Index) add(pkg, p string) bool {
	if len(ix.files) >= maxIndexFiles {
		ix.complete = false
		return false
	}
	if len(ix.files)%8192 == 0 && ix.ctx.Err() != nil {
		ix.complete = false
		return false
	}
	if !path.IsAbs(p) {
		return true
	}
	p = path.Clean(p)
	dir, base := path.Split(p)
	if base == "" {
		return true
	}
	h := ix.hash(ix.res.dir(path.Clean(dir)), base)
	if _, dup := ix.files[h]; dup {
		return true // shared file; the first owner wins
	}
	id, ok := ix.nameID[pkg]
	if !ok {
		id = uint32(len(ix.names))
		ix.names = append(ix.names, pkg)
		ix.nameID[pkg] = id
	}
	ix.files[h] = id
	return true
}

// buildDpkgInfo reads /var/lib/dpkg/info/<pkg>[:<arch>].list. Directory
// entries are skipped when the next line lies inside them; dpkg lists a
// directory before its contents.
func (ix *Index) buildDpkgInfo(dir string) bool {
	ents, err := os.ReadDir(ix.env.Path(dir))
	if err != nil {
		return notExist(err) && len(ix.installed) == 0
	}
	ok := true
	for _, e := range ents {
		name, found := strings.CutSuffix(e.Name(), ".list")
		if !found {
			continue
		}
		pkg, _, _ := strings.Cut(name, ":")
		if ix.installed != nil && !ix.installed[pkg] {
			continue
		}
		f, err := os.Open(ix.env.Path(path.Join(dir, e.Name())))
		if err != nil {
			ok = false
			continue
		}
		lr := newLineReader(f)
		var prev string
		full := false
		for {
			line, more := lr.next()
			if !more {
				break
			}
			cur := string(line)
			if prev != "" && prev != "/." && !(strings.HasPrefix(cur, prev) && len(cur) > len(prev) && cur[len(prev)] == '/') {
				if !ix.add(pkg, prev) {
					full = true
					break
				}
			}
			prev = cur
		}
		if !full && prev != "" && prev != "/." {
			full = !ix.add(pkg, prev)
		}
		if lr.err != nil || lr.long {
			ok = false
		}
		f.Close()
		if full {
			return false
		}
	}
	return ok
}

// buildStatusD reads the distroless <pkg>.md5sums files: "<md5>  <path>"
// with paths relative to the root.
func (ix *Index) buildStatusD(dir string) bool {
	ents, err := os.ReadDir(ix.env.Path(dir))
	if err != nil {
		return false
	}
	ok := true
	for _, e := range ents {
		file, found := strings.CutSuffix(e.Name(), ".md5sums")
		if !found {
			continue
		}
		pkg := ix.statusD[file]
		if pkg == "" {
			continue
		}
		f, err := os.Open(ix.env.Path(path.Join(dir, e.Name())))
		if err != nil {
			ok = false
			continue
		}
		lr := newLineReader(f)
		for {
			line, more := lr.next()
			if !more {
				break
			}
			_, rel, found := bytes.Cut(line, []byte("  "))
			if !found || len(rel) == 0 {
				continue
			}
			if !ix.add(pkg, "/"+strings.TrimPrefix(string(rel), "/")) {
				f.Close()
				return false
			}
		}
		if lr.err != nil || lr.long {
			ok = false
		}
		f.Close()
	}
	return ok
}

func (ix *Index) buildRPM(p string) bool {
	ok := true
	full := false
	format, skipped, err := eachRPMBlob(ix.ctx, ix.env, p, func(blob []byte) bool {
		h, err := parseRPMHeader(blob, fileTags)
		if err != nil {
			ok = false
			return true
		}
		name, files, err := rpmFiles(h)
		if err != nil {
			ok = false
		}
		for _, f := range files {
			if !ix.add(cleanString(name), f) {
				full = true
				return false
			}
		}
		return true
	})
	return format != "" && err == nil && skipped == 0 && ok && !full
}

func (ix *Index) buildAPK(p string) bool {
	f, err := os.Open(ix.env.Path(p))
	if err != nil {
		return false
	}
	defer f.Close()
	full := false
	err = parseAPKFiles(ix.ctx, f, func(pkg, file string) bool {
		if !ix.add(pkg, file) {
			full = true
			return false
		}
		return true
	})
	return err == nil && !full
}
