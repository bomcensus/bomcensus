// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pkgdb

import (
	"io/fs"
	"os"
	"path"

	"github.com/bomcensus/bomcensus/internal/collect"
)

const (
	// maxSymlinkHops bounds symlink resolution, like the kernel's ELOOP limit.
	maxSymlinkHops = 40
	// maxDirMemo bounds the number of resolved directories kept in memory.
	maxDirMemo = 500_000
)

// resolver maps logical paths to their canonical spelling inside env.Root.
// Symlinks are followed component by component and absolute targets are
// interpreted relative to the inspected root, so a container root never
// escapes to the host. It is not safe for concurrent use.
type resolver struct {
	env  *collect.Env
	memo map[string]string
}

func newResolver(env *collect.Env) *resolver {
	return &resolver{env: env, memo: map[string]string{}}
}

// dir returns the canonical form of an absolute, clean directory path.
// Components that do not exist are kept as they are.
func (r *resolver) dir(d string) string {
	return r.walk(d, 0)
}

func (r *resolver) walk(d string, hops int) string {
	if d == "/" || d == "" || d == "." {
		return "/"
	}
	if v, ok := r.memo[d]; ok {
		return v
	}
	parent := r.walk(path.Dir(d), hops)
	cand := path.Join(parent, path.Base(d))
	res := cand
	fi, err := os.Lstat(r.env.Path(cand))
	if err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		if hops >= maxSymlinkHops {
			return cand
		}
		target, err := os.Readlink(r.env.Path(cand))
		if err == nil && target != "" {
			if !path.IsAbs(target) {
				target = path.Join(parent, target)
			}
			res = r.walk(path.Clean(target), hops+1)
		}
	}
	if len(r.memo) < maxDirMemo {
		r.memo[d] = res
	}
	return res
}

// file returns the canonical form of an absolute path, following a symlink
// in the last component as well.
func (r *resolver) file(p string) string {
	p = path.Clean(p)
	if p == "/" {
		return p
	}
	return r.walk(p, 0)
}

// stat stats a canonical logical path.
func (r *resolver) stat(canonical string) (fs.FileInfo, error) {
	return os.Stat(r.env.Path(canonical))
}
