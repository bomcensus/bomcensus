// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package integrity

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/bomcensus/bomcensus/internal/collect"
	"github.com/bomcensus/bomcensus/internal/collect/pkgdb"
	"github.com/bomcensus/bomcensus/internal/report"
)

// DefaultReadMBps is the read rate when the query sets none.
const DefaultReadMBps = 20

const (
	// pressureEvery is how often host pressure is checked while reading.
	pressureEvery = 2 * time.Second
	// pressurePause is how long to wait before checking a busy host again.
	pressurePause = 15 * time.Second
	readBufSize   = 256 << 10
	maxReason     = 2048
)

// Options replace the host checks and the clock in tests. Zero values use
// the real ones.
type Options struct {
	Now                func() time.Time
	Sleep              func(context.Context, time.Duration) bool
	HostBusy           func() bool
	PackageManagerBusy func() bool
}

func (o *Options) fill(env *collect.Env) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = sleepCtx
	}
	if o.HostBusy == nil {
		proc := env.Proc
		if proc == "" {
			proc = "/proc"
		}
		o.HostBusy = func() bool { return hostBusy(proc) }
	}
	if o.PackageManagerBusy == nil {
		root := env.Root
		if root == "" {
			root = "/"
		}
		o.PackageManagerBusy = func() bool { return packageManagerBusy(root) }
	}
}

// Check runs one chunk of an integrity pass: it checks packages after
// q.Cursor in key order until deadline. A package is either checked whole
// or left for the next chunk.
func Check(ctx context.Context, env *collect.Env, q report.IntegrityQuery, deadline time.Time, o Options) *report.IntegritySection {
	o.fill(env)
	start := o.Now()
	rate := q.MaxReadMBps
	if rate <= 0 {
		rate = DefaultReadMBps
	}
	c := &checker{
		env:      env,
		q:        q,
		o:        o,
		deadline: deadline,
		cache:    loadCache(q.Cache, start),
		lim:      newLimiter(int64(rate)<<20, o.Now, o.Sleep),
		match:    newMatcher(q.ExcludePaths),
		seen:     map[string]bool{},
		sec: &report.IntegritySection{
			PassID:           q.PassID,
			Cursor:           q.Cursor,
			UTCOffsetSeconds: utcOffset(env, start),
		},
	}
	sec := c.sec
	finish := func() *report.IntegritySection {
		sec.CollectedAt = start.UTC()
		sec.DurationMs = o.Now().Sub(start).Milliseconds()
		sec.Cache = c.cache.marshal()
		return sec
	}
	if o.PackageManagerBusy() {
		c.busy()
		return finish()
	}

	c.exp = pkgdb.ReadExpected(ctx, env)
	c.problems = append(c.problems, c.exp.Problems...)
	done := c.run(ctx)
	if len(sec.Findings) > 0 {
		c.recheck(ctx)
	}
	// A package manager that started meanwhile may have changed files under
	// the check: the chunk is repeated.
	if o.PackageManagerBusy() {
		c.busy()
		return finish()
	}
	sec.PassDone = done
	if done {
		sec.Cursor = ""
	}
	if sec.Unreadable > 0 {
		c.problems = append(c.problems, fmt.Sprintf("%d files could not be read", sec.Unreadable))
	}
	switch {
	case len(c.problems) == 0:
		sec.Coverage = report.CoverageFull
	case len(c.exp.Databases) == 0:
		sec.Coverage = report.CoverageNone
	default:
		sec.Coverage = report.CoveragePartial
	}
	if len(c.problems) > 0 {
		sec.Reason = strings.ToValidUTF8(strings.Join(c.problems, "; "), "")
		if len(sec.Reason) > maxReason {
			sec.Reason = strings.ToValidUTF8(sec.Reason[:maxReason], "")
		}
	}
	return finish()
}

type checker struct {
	env      *collect.Env
	q        report.IntegrityQuery
	o        Options
	deadline time.Time
	exp      *pkgdb.Expected
	cache    *cache
	lim      *limiter
	match    *matcher
	sec      *report.IntegritySection
	problems []string
	// seen holds the opened paths of files already checked in this chunk;
	// a file shared by several packages is checked once.
	seen         map[string]bool
	lastPressure time.Time
}

// busy turns the section into "nothing checked, try again".
func (c *checker) busy() {
	*c.sec = report.IntegritySection{
		PassID:           c.q.PassID,
		Cursor:           c.q.Cursor,
		UTCOffsetSeconds: c.sec.UTCOffsetSeconds,
	}
	c.sec.Coverage = report.CoverageNone
	c.sec.Reason = "a package manager is running; the chunk is repeated later"
}

func (c *checker) stopped(ctx context.Context) bool {
	return ctx.Err() != nil || !c.o.Now().Before(c.deadline)
}

// pkgResult collects one package; it is merged only when the package was
// checked whole.
type pkgResult struct {
	checked, excluded, unreadable int64
	findings                      []report.IntegrityFinding
	seen                          []string
}

// run checks packages after the cursor. It reports whether the last
// package was reached.
func (c *checker) run(ctx context.Context) bool {
	sec := c.sec
	for _, p := range c.exp.Packages {
		key := p.Key()
		if c.q.Cursor != "" && key <= c.q.Cursor {
			continue
		}
		if c.stopped(ctx) || len(sec.Findings) >= report.MaxIntegrityFindings {
			return false
		}
		files, excluded, err := c.exp.Files(p)
		if err != nil {
			c.problem(key + ": " + err.Error())
		}
		r := &pkgResult{excluded: int64(excluded)}
		complete := true
		for _, f := range files {
			if !c.checkFile(ctx, p, f, r) {
				complete = false
				break
			}
		}
		if !complete {
			return false
		}
		sec.Packages++
		sec.Checked += r.checked
		sec.Excluded += r.excluded
		sec.Unreadable += r.unreadable
		sec.Findings = append(sec.Findings, r.findings...)
		for _, s := range r.seen {
			c.seen[s] = true
		}
		sec.Cursor = key
	}
	return true
}

func (c *checker) problem(msg string) {
	if len(c.problems) < 64 {
		c.problems = append(c.problems, msg)
	}
}

// checkFile checks one file. It returns false when the chunk has to stop.
func (c *checker) checkFile(ctx context.Context, p *pkgdb.ExpectedPackage, f pkgdb.ExpectedFile, r *pkgResult) bool {
	if c.match.match(f.Path) {
		r.excluded++
		return true
	}
	real, link := c.exp.Resolve(f.Path)
	if f.MaySymlink && link {
		r.excluded++
		return true
	}
	if c.seen[real] {
		return true
	}
	r.seen = append(r.seen, real)
	finding := func(status string) report.IntegrityFinding {
		return report.IntegrityFinding{
			PkgType: p.Type, Package: p.Name, Version: p.Version, Arch: p.Arch,
			Path: f.Path, Status: status, Algo: f.Algo, Expected: f.Digest,
		}
	}

	fh, err := os.Open(real)
	if err != nil {
		switch {
		case errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR):
			if f.MissingOK {
				r.excluded++
			} else {
				r.findings = append(r.findings, finding(report.IntegrityMissing))
			}
		default:
			r.unreadable++
		}
		return true
	}
	defer fh.Close()
	fi, err := fh.Stat()
	if err != nil {
		r.unreadable++
		return true
	}
	if !fi.Mode().IsRegular() {
		fd := finding(report.IntegrityModified)
		fd.Mtime, fd.Ctime = fi.ModTime().UTC(), ctimeOf(fi)
		r.findings = append(r.findings, fd)
		r.checked++
		return true
	}
	if fi.Size() > collect.MaxHashSize {
		r.excluded++
		return true
	}
	key, keyed := statKeyOf(fi)
	if keyed && !c.q.FullRehash {
		if d, ok := c.cache.get(key, f.Algo); ok && hex.EncodeToString(d) == f.Digest {
			r.checked++
			return true
		}
	}
	sums, err := c.hash(ctx, fh, f.Algo)
	if err != nil {
		if c.stopped(ctx) {
			return false
		}
		r.unreadable++
		return true
	}
	dropCache(fh)
	if hex.EncodeToString(sums[0]) == f.Digest {
		if keyed {
			c.cache.put(key, f.Algo, sums[0])
		}
		r.checked++
		return true
	}

	// Different: read once more for the SHA-256, and to make sure the
	// actual digest belongs to one consistent read.
	fd := finding(report.IntegrityModified)
	algos := []string{f.Algo}
	if f.Algo != pkgdb.AlgoSHA256 {
		algos = append(algos, pkgdb.AlgoSHA256)
	}
	if _, err := fh.Seek(0, io.SeekStart); err != nil {
		r.unreadable++
		return true
	}
	sums, err = c.hash(ctx, fh, algos...)
	if err != nil {
		if c.stopped(ctx) {
			return false
		}
		r.unreadable++
		return true
	}
	dropCache(fh)
	fd.Actual = hex.EncodeToString(sums[0])
	if fd.Actual == f.Digest {
		// Changed back between the two reads.
		r.checked++
		return true
	}
	if len(sums) > 1 {
		fd.ActualSHA256 = hex.EncodeToString(sums[1])
	}
	fd.Size = fi.Size()
	fd.Mtime, fd.Ctime = fi.ModTime().UTC(), ctimeOf(fi)
	r.findings = append(r.findings, fd)
	r.checked++
	return true
}

var errStopped = errors.New("integrity: stopped")

// hash reads f to the end and returns its digest in each algorithm.
func (c *checker) hash(ctx context.Context, f *os.File, algos ...string) ([][]byte, error) {
	hs := make([]hash.Hash, len(algos))
	ws := make([]io.Writer, len(algos))
	for i, a := range algos {
		h := newHash(a)
		if h == nil {
			return nil, fmt.Errorf("integrity: unknown algorithm %q", a)
		}
		hs[i], ws[i] = h, h
	}
	w := io.MultiWriter(ws...)
	buf := make([]byte, readBufSize)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
			if !c.lim.wait(ctx, n) || !c.pace(ctx) {
				return nil, errStopped
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	out := make([][]byte, len(hs))
	for i, h := range hs {
		out[i] = h.Sum(nil)
	}
	return out, nil
}

// pace waits while the host is busy. It returns false when the chunk has
// to stop.
func (c *checker) pace(ctx context.Context) bool {
	now := c.o.Now()
	if now.Sub(c.lastPressure) < pressureEvery {
		return !c.stopped(ctx)
	}
	c.lastPressure = now
	for c.o.HostBusy() {
		wait := min(pressurePause, c.deadline.Sub(c.o.Now()))
		if wait <= 0 || !c.o.Sleep(ctx, wait) {
			return false
		}
	}
	return !c.stopped(ctx)
}

func newHash(algo string) hash.Hash {
	switch algo {
	case pkgdb.AlgoMD5:
		return md5.New()
	case pkgdb.AlgoSHA1:
		return sha1.New()
	case pkgdb.AlgoSHA256:
		return sha256.New()
	case pkgdb.AlgoSHA384:
		return sha512.New384()
	case pkgdb.AlgoSHA512:
		return sha512.New()
	}
	return nil
}

// recheck reads the databases again and drops findings of packages that
// were upgraded or removed while the chunk ran: their files may have been
// read half way through the change.
func (c *checker) recheck(ctx context.Context) {
	now := pkgdb.ReadExpected(ctx, c.env)
	versions := map[string]map[string]bool{}
	for _, p := range now.Packages {
		k := p.Type + "/" + p.Name + "/" + p.Arch
		if versions[k] == nil {
			versions[k] = map[string]bool{}
		}
		versions[k][p.Version] = true
	}
	kept := c.sec.Findings[:0]
	for _, f := range c.sec.Findings {
		if versions[f.PkgType+"/"+f.Package+"/"+f.Arch][f.Version] {
			kept = append(kept, f)
		}
	}
	c.sec.Findings = kept
}

func ctimeOf(fi os.FileInfo) time.Time {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return time.Unix(st.Ctim.Sec, st.Ctim.Nsec).UTC()
	}
	return time.Time{}
}

// utcOffset returns the inspected host's UTC offset at t, from its
// /etc/localtime. A host root without one uses the probe's own zone.
func utcOffset(env *collect.Env, t time.Time) int {
	if b, err := os.ReadFile(env.Path("/etc/localtime")); err == nil {
		if loc, err := time.LoadLocationFromTZData("host", b); err == nil {
			_, off := t.In(loc).Zone()
			return off
		}
	}
	if env.Root == "" || env.Root == "/" {
		_, off := t.Zone()
		return off
	}
	return 0
}
