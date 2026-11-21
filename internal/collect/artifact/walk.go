// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package artifact

import (
	"bufio"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/bomcensus/bomcensus/internal/collect"
)

// maxWalkDepth bounds the directory nesting the walk descends into.
const maxWalkDepth = 256

// readDirBatch is how many directory entries are held at once.
const readDirBatch = 256

// builtinExcludes are never walked. Container storage is scanned through
// each container's own root instead.
var builtinExcludes = []string{
	"/proc",
	"/sys",
	"/dev",
	"/run",
	"/var/lib/docker",
	"/var/lib/containerd",
	"/var/lib/containers",
	"/var/lib/kubelet/pods",
}

// skippedFSTypes are pseudo, remote and cluster file systems. FUSE file
// systems are skipped as a whole because most of them are remote.
var skippedFSTypes = map[string]bool{
	// pseudo
	"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true, "cgroup": true, "cgroup2": true,
	"securityfs": true, "debugfs": true, "tracefs": true, "pstore": true, "bpf": true, "configfs": true,
	"fusectl": true, "mqueue": true, "hugetlbfs": true, "autofs": true, "binfmt_misc": true,
	"efivarfs": true, "rpc_pipefs": true, "nsfs": true, "selinuxfs": true, "nfsd": true,
	// remote and cluster
	"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "smbfs": true, "ncpfs": true, "afs": true,
	"ceph": true, "glusterfs": true, "9p": true, "lustre": true, "gpfs": true, "beegfs": true,
	"ocfs2": true, "gfs2": true, "davfs": true, "coda": true, "orangefs": true, "virtiofs": true,
	"fuse": true, "fuseblk": true,
}

// skippedFSMagic is the statfs(2) f_type of the same file systems, used when
// no mount table is available.
var skippedFSMagic = map[int64]bool{
	0x9fa0:     true, // proc
	0x62656572: true, // sysfs
	0x1cd1:     true, // devpts
	0x27e0eb:   true, // cgroup
	0x63677270: true, // cgroup2
	0x64626720: true, // debugfs
	0x74726163: true, // tracefs
	0x73636673: true, // securityfs
	0xcafe4a11: true, // bpf
	0x6165676c: true, // pstore
	0x6969:     true, // nfs
	0x517b:     true, // smb
	0xff534d42: true, // cifs
	0xfe534d42: true, // smb2
	0x65735546: true, // fuse
	0x00c36400: true, // ceph
	0x73757245: true, // coda
	0x5346414f: true, // afs
	0x01021997: true, // 9p
	0x0bd00bd0: true, // lustre
	0x47504653: true, // gpfs
}

func skipFSType(t string) bool {
	return skippedFSTypes[t] || strings.HasPrefix(t, "fuse.")
}

// buildExcludes returns the cleaned excluded logical paths.
func buildExcludes(extra []string) []string {
	out := slices.Clone(builtinExcludes)
	for _, p := range extra {
		if p == "" || !strings.HasPrefix(p, "/") {
			continue
		}
		out = append(out, path.Clean(p))
	}
	return out
}

// excluded reports whether the logical directory p is excluded. Entries are
// path prefixes; an entry with glob characters is matched with path.Match.
func (c *collector) excluded(p string) bool {
	for _, e := range c.excludes {
		if strings.ContainsAny(e, "*?[") {
			if ok, _ := path.Match(e, p); ok {
				return true
			}
			continue
		}
		if p == e || (e != "/" && strings.HasPrefix(p, e+"/")) {
			return true
		}
	}
	return false
}

// mount is one line of a mountinfo file.
type mount struct {
	id         int
	majorMinor string
	root       string
	point      string // logical mount point
	fsType     string
}

// mountTable holds the mount points of the inspected root.
type mountTable struct {
	byPoint map[string]mount
	// duplicates are bind mounts whose content is reachable through another
	// mount of the same file system.
	duplicates map[string]bool
}

// loadMounts reads the mount table that applies to env.Root: the probe's own
// for the host, the process's for a container root under /proc/<pid>/root.
// It returns nil when neither applies; the walk then relies on statfs.
func loadMounts(env *collect.Env) *mountTable {
	proc := env.Proc
	if proc == "" {
		proc = "/proc"
	}
	var file string
	switch root := strings.TrimSuffix(env.Root, "/"); {
	case root == "":
		file = filepath.Join(proc, "self", "mountinfo")
	case strings.HasPrefix(root, proc+"/") && strings.HasSuffix(root, "/root"):
		pid := strings.TrimSuffix(strings.TrimPrefix(root, proc+"/"), "/root")
		if _, err := strconv.Atoi(pid); err != nil {
			return nil
		}
		file = filepath.Join(proc, pid, "mountinfo")
	default:
		return nil
	}
	f, err := os.Open(file)
	if err != nil {
		return nil
	}
	defer f.Close()
	return parseMountinfo(f)
}

func parseMountinfo(r io.Reader) *mountTable {
	t := &mountTable{byPoint: map[string]mount{}, duplicates: map[string]bool{}}
	var all []mount
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		// 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
		fields := strings.Fields(sc.Text())
		sep := slices.Index(fields, "-")
		if sep < 6 || sep+1 >= len(fields) {
			continue
		}
		id, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		m := mount{
			id:         id,
			majorMinor: fields[2],
			root:       unescapeMount(fields[3]),
			point:      unescapeMount(fields[4]),
			fsType:     fields[sep+1],
		}
		all = append(all, m)
		// A later mount on the same point hides the earlier one.
		t.byPoint[m.point] = m
	}
	for _, e := range all {
		if e.root == "/" || t.byPoint[e.point].id != e.id {
			continue
		}
		for _, o := range all {
			if o.id == e.id || o.majorMinor != e.majorMinor || skipFSType(o.fsType) ||
				t.byPoint[o.point].id != o.id || under(o.point, e.point) {
				continue
			}
			if o.root == "/" || strings.HasPrefix(e.root, o.root+"/") || (o.root == e.root && o.id < e.id) {
				t.duplicates[e.point] = true
				break
			}
		}
	}
	return t
}

// under reports whether p is q or inside q.
func under(p, q string) bool {
	return p == q || q == "/" || strings.HasPrefix(p, q+"/")
}

// unescapeMount decodes the octal escapes used in mountinfo (\040 for space).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// walk visits every directory under walkStart once.
func (c *collector) walk(ctx context.Context) {
	c.walkDir(ctx, c.walkStart, 0, true, 0)
}

func (c *collector) walkDir(ctx context.Context, logical string, parentDev uint64, top bool, depth int) {
	if ctx.Err() != nil {
		return
	}
	if depth > maxWalkDepth {
		c.st.tooDeep++
		return
	}
	real := c.env.Path(logical)
	open := real
	if top && logical == "/" && !strings.HasSuffix(open, "/") {
		// The inspected root itself may be a symbolic link, such as
		// /proc/<pid>/root of a container; the trailing slash makes the
		// open follow it. Everything below is opened with O_NOFOLLOW.
		open += "/"
	}
	fd, err := syscall.Open(open, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		if top {
			c.st.rootErr = err
			return
		}
		if !errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ELOOP) && !errors.Is(err, syscall.ENOTDIR) {
			c.st.unreadableDirs++
		}
		return
	}
	dir := os.NewFile(uintptr(fd), real)
	defer func() {
		if dir != nil {
			dir.Close()
		}
	}()
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		c.st.unreadableDirs++
		return
	}
	dev := uint64(st.Dev)
	if !top && !c.enterMount(fd, logical, dev, parentDev) {
		return
	}
	id := fileID{Dev: dev, Ino: st.Ino}
	if top || dev != parentDev || c.mounts != nil && c.mounts.byPoint[logical].id != 0 {
		if c.visitedDirs[id] {
			return
		}
		c.visitedDirs[id] = true
	}

	var subdirs []string
	for {
		ents, err := dir.ReadDir(readDirBatch)
		for _, ent := range ents {
			child := path.Join(logical, ent.Name())
			switch t := ent.Type(); {
			case t.IsDir():
				if !c.excluded(child) {
					subdirs = append(subdirs, ent.Name())
				}
			case t.IsRegular():
				c.visitFile(ctx, child, ent)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			c.st.unreadableDirs++
			break
		}
		if ctx.Err() != nil {
			return
		}
	}
	dir.Close()
	dir = nil

	slices.Sort(subdirs)
	for _, name := range subdirs {
		c.walkDir(ctx, path.Join(logical, name), dev, false, depth+1)
	}
}

// enterMount decides whether a directory that may be a mount point is
// walked. Pseudo and remote file systems and duplicate bind mounts are not.
func (c *collector) enterMount(fd int, logical string, dev, parentDev uint64) bool {
	if c.mounts != nil {
		if m, ok := c.mounts.byPoint[logical]; ok {
			return !skipFSType(m.fsType) && !c.mounts.duplicates[logical]
		}
	}
	if dev == parentDev {
		return true
	}
	var sfs syscall.Statfs_t
	if err := syscall.Fstatfs(fd, &sfs); err != nil {
		return false
	}
	return !skippedFSMagic[int64(sfs.Type)]
}

// errnoText is the error without the path of a *fs.PathError.
func errnoText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}
