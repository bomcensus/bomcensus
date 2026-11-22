// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package updater installs verified bomcensus releases on a Linux or Windows
// host and rolls back versions that do not come up.
//
// Install directory (written only by the updater):
//
//	<install>/versions/<version>/   files of one installed version
//	<install>/current               link to versions/<version>: a symlink on
//	                                Linux, a directory junction on Windows
//	<install>/state.json            State, readable by the agent
//	<install>/updater.lock          held while an updater runs
//
// On Windows the executables carry the ".exe" suffix, as in the bundle.
//
// Spool directory (written by the agent, read by the updater):
//
//	bomcensus-<version>.tar         release bundle to install
//	confirm-<version>               the pending version works
//	rollback                        abort the pending version
//
// <version> is a semantic version without a "v" prefix. Other names are left
// alone, so a writer should create a file under another name (for example
// .bomcensus-<version>.tar.part) and rename it when it is complete: a
// truncated bundle is rejected and deleted.
//
// Nothing the agent says is trusted. Every bundle is verified completely
// with release.Open; the updater only switches to version directories whose
// files still match the hashes it recorded when it installed them.
package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/bomcensus/bomcensus/internal/release"
	"github.com/bomcensus/bomcensus/internal/sign"
)

// Names inside the install directory.
const (
	versionsDir = "versions"
	currentName = "current"
	stateName   = "state.json"
	lockName    = "updater.lock"
)

// Names inside the spool directory.
const (
	bundlePrefix  = "bomcensus-"
	bundleSuffix  = ".tar"
	confirmPrefix = "confirm-"
	// RollbackName is the spool file that requests a rollback of the
	// pending version.
	RollbackName = "rollback"
)

// AgentName is the executable every installed version must contain, without
// the ".exe" suffix it has on Windows (see ExeName).
const AgentName = "bomcensus-agent"

// agentBaseNames are the files of an agent installation. A release bundle
// holds every file of a platform; the others are verified with the bundle
// but not installed.
var agentBaseNames = []string{AgentName, "bomcensus-probe", "bomcensus-updater"}

// otherBaseNames are bundle files an agent does not use. They may be present
// in version directories installed by earlier versions or by an installer
// and are ignored there.
var otherBaseNames = []string{"bomcensus-scanner"}

// ExeName returns the file name of executable name on the running operating
// system: name plus ".exe" on Windows.
func ExeName(name string) string { return release.ExeName(runtime.GOOS, name) }

// hostOS selects the platform files of a bundle. A variable so that tests
// can install Windows bundles on another system.
var hostOS = runtime.GOOS

func nameSet(goos string, names []string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[release.ExeName(goos, n)] = true
	}
	return m
}

// Defaults for BootCheck.
const (
	DefaultMaxAttempts    = 3
	DefaultPendingTimeout = 30 * time.Minute
)

// maxFileSize bounds a file read back from a version directory.
const maxFileSize = 256 << 20

// ErrLocked means another updater holds the install directory lock.
var ErrLocked = errors.New("updater: install directory is locked by another updater")

// BundleName returns the spool file name for a release bundle.
func BundleName(version string) string { return bundlePrefix + version + bundleSuffix }

// ConfirmName returns the spool file name that confirms a pending version.
func ConfirmName(version string) string { return confirmPrefix + version }

// IsSpoolEntry reports whether Apply acts on a spool file of this name.
func IsSpoolEntry(name string) bool {
	k, _ := parseSpoolName(name)
	return k != spoolIgnored
}

type spoolKind int

const (
	spoolIgnored spoolKind = iota
	spoolRollback
	spoolConfirm
	spoolRelease
)

// parseSpoolName classifies a spool file name and returns the version it
// names, if any.
func parseSpoolName(name string) (spoolKind, string) {
	switch {
	case name == RollbackName:
		return spoolRollback, ""
	case strings.HasPrefix(name, confirmPrefix):
		if v := name[len(confirmPrefix):]; sign.ValidVersion(v) {
			return spoolConfirm, v
		}
	case strings.HasPrefix(name, bundlePrefix) && strings.HasSuffix(name, bundleSuffix):
		if v := name[len(bundlePrefix) : len(name)-len(bundleSuffix)]; sign.ValidVersion(v) {
			return spoolRelease, v
		}
	}
	return spoolIgnored, ""
}

// Options configures Apply and BootCheck.
type Options struct {
	// InstallDir is the install directory (normally /opt/bomcensus).
	InstallDir string
	// Arch is the architecture to install; default runtime.GOARCH. The
	// operating system is always the one the updater runs on.
	Arch string
	// Logger receives structured logs; default discards them.
	Logger *slog.Logger
	// Now returns the current time; default time.Now.
	Now func() time.Time
	// LockWait is how long to wait for the install directory lock.
	LockWait time.Duration
}

// BootLimits configures BootCheck.
type BootLimits struct {
	// MaxAttempts is the number of starts a pending version gets; default
	// DefaultMaxAttempts.
	MaxAttempts int
	// PendingTimeout is how long a version may stay pending; default
	// DefaultPendingTimeout.
	PendingTimeout time.Duration
}

// Result summarises what a run did.
type Result struct {
	// Installed is the version installed and switched to.
	Installed string
	// Confirmed is the version whose pending mark was cleared.
	Confirmed string
	// RolledBack is the version that was rolled back.
	RolledBack string
	// Rejected lists spool entries that were refused.
	Rejected []Rejected
}

// Rejected is a refused spool entry.
type Rejected struct {
	Name   string
	Reason string
}

// Apply processes every entry of spoolDir: confirmations, a rollback request,
// then release bundles. A rejected entry is logged and, if it is a regular
// file, deleted; it does not stop the run. The error is non-nil only for
// operational failures such as a lock held by another updater or an install
// directory that cannot be written.
func Apply(ctx context.Context, opts Options, spoolDir string) (*Result, error) {
	if spoolDir == "" {
		return nil, errors.New("updater: spool directory is required")
	}
	s, err := openSession(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer s.close()
	spool, err := os.OpenRoot(spoolDir)
	if err != nil {
		return nil, fmt.Errorf("updater: open spool: %w", err)
	}
	defer spool.Close()
	names, err := readDirNames(spool, ".")
	if err != nil {
		return nil, fmt.Errorf("updater: read spool: %w", err)
	}

	res := &Result{}
	var bundles []spoolBundle
	var confirms []spoolBundle
	rollback := false
	for _, n := range names {
		switch k, v := parseSpoolName(n); k {
		case spoolRollback:
			rollback = true
		case spoolConfirm:
			confirms = append(confirms, spoolBundle{n, v})
		case spoolRelease:
			bundles = append(bundles, spoolBundle{n, v})
		}
	}

	for _, c := range confirms {
		if err := s.handleConfirm(spool, c, res); err != nil {
			return res, err
		}
	}
	if rollback {
		if err := s.handleRollback(spool, res); err != nil {
			return res, err
		}
	}
	// Highest first: once it is installed the others are not newer and are
	// discarded without installing versions that would never run.
	slices.SortStableFunc(bundles, func(a, b spoolBundle) int {
		c, _ := sign.CompareVersions(b.version, a.version)
		return c
	})
	for _, b := range bundles {
		if err := s.applyBundle(ctx, spool, b, res); err != nil {
			return res, err
		}
	}
	if res.Installed != "" {
		s.cleanup()
	}
	return res, nil
}

// BootCheck counts a start attempt of the pending version and rolls back to
// the previous version when the attempts exceed limits.MaxAttempts or the
// version has been pending longer than limits.PendingTimeout.
func BootCheck(ctx context.Context, opts Options, limits BootLimits) (*Result, error) {
	return checkPending(ctx, opts, limits, true)
}

// ExpirePending applies the limits of BootCheck without counting a start:
// it rolls back a pending version that has been pending longer than
// limits.PendingTimeout. The Windows updater service calls it while the
// agent runs, because there no unit runs a boot check before each start.
func ExpirePending(ctx context.Context, opts Options, limits BootLimits) (*Result, error) {
	return checkPending(ctx, opts, limits, false)
}

// Cleanup removes version directories other than the current and the
// previous one, and temporary files of interrupted runs. Apply does this
// after an install. On Windows the files of a running executable cannot be
// removed, so the updater service calls Cleanup again when it starts.
func Cleanup(ctx context.Context, opts Options) error {
	s, err := openSession(ctx, opts)
	if err != nil {
		return err
	}
	defer s.close()
	if s.st.Current != "" {
		s.cleanup()
	}
	return nil
}

func checkPending(ctx context.Context, opts Options, limits BootLimits, count bool) (*Result, error) {
	if limits.MaxAttempts <= 0 {
		limits.MaxAttempts = DefaultMaxAttempts
	}
	if limits.PendingTimeout <= 0 {
		limits.PendingTimeout = DefaultPendingTimeout
	}
	s, err := openSession(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer s.close()
	res := &Result{}
	if s.st.Pending == nil {
		return res, nil
	}
	next := s.st
	if count {
		next = s.st.clone()
		next.Pending.Attempts++
		if err := s.commit(next); err != nil {
			return res, err
		}
	}
	p := next.Pending
	if count {
		s.log.Info("boot check", "version", p.Version, "attempts", p.Attempts, "since", p.Since)
	}
	var reason string
	if p.Attempts > limits.MaxAttempts {
		reason = fmt.Sprintf("%d start attempts exceed the limit of %d", p.Attempts, limits.MaxAttempts)
	} else if age := s.now().Sub(p.Since); age > limits.PendingTimeout {
		reason = fmt.Sprintf("pending for %s, limit is %s", age.Round(time.Second), limits.PendingTimeout)
	}
	if reason == "" {
		return res, nil
	}
	failed := next.Current
	ok, err := s.rollback(reason)
	if err != nil {
		return res, err
	}
	if ok {
		res.RolledBack = failed
	}
	return res, nil
}

// Status returns the recorded state of installDir. Without a state.json it
// returns the state derived from the current link. It takes no lock.
func Status(ctx context.Context, installDir string) (*State, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(installDir)
	if err != nil {
		return nil, fmt.Errorf("updater: open install directory: %w", err)
	}
	defer root.Close()
	abs, err := filepath.Abs(installDir)
	if err != nil {
		return nil, fmt.Errorf("updater: %w", err)
	}
	st, _, err := readState(root, abs)
	if err != nil {
		return nil, fmt.Errorf("updater: %w", err)
	}
	return st, nil
}

// Current returns the version the current link of installDir points to and
// the absolute path of its directory, or "" when there is no link. Reading
// the link once and using the returned directory avoids the transient ENOENT
// that a path walk through current/ can hit while the link is replaced.
func Current(ctx context.Context, installDir string) (version, dir string, err error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	abs, err := filepath.Abs(installDir)
	if err != nil {
		return "", "", fmt.Errorf("updater: %w", err)
	}
	root, err := os.OpenRoot(abs)
	if err != nil {
		return "", "", fmt.Errorf("updater: open install directory: %w", err)
	}
	defer root.Close()
	v, err := currentFromLink(root, abs)
	if err != nil {
		return "", "", fmt.Errorf("updater: %w", err)
	}
	if v == "" {
		return "", "", nil
	}
	return v, filepath.Join(abs, versionsDir, v), nil
}

type spoolBundle struct {
	name    string
	version string
}

type session struct {
	root       *os.Root
	installAbs string
	lock       *os.File
	goos       string
	arch       string
	// agentFiles and otherFiles are agentBaseNames and otherBaseNames as
	// file names of goos; agentExe is the agent executable.
	agentFiles map[string]bool
	otherFiles map[string]bool
	agentExe   string
	log        *slog.Logger
	now        func() time.Time
	st         *State
}

func openSession(ctx context.Context, opts Options) (*session, error) {
	if opts.InstallDir == "" {
		return nil, errors.New("updater: install directory is required")
	}
	s := &session{goos: hostOS, arch: opts.Arch, log: opts.Logger, now: opts.Now}
	if s.arch == "" {
		s.arch = runtime.GOARCH
	}
	s.agentFiles = nameSet(s.goos, agentBaseNames)
	s.otherFiles = nameSet(s.goos, otherBaseNames)
	s.agentExe = release.ExeName(s.goos, AgentName)
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.now == nil {
		s.now = time.Now
	}
	abs, err := filepath.Abs(opts.InstallDir)
	if err != nil {
		return nil, fmt.Errorf("updater: %w", err)
	}
	s.installAbs = abs
	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, fmt.Errorf("updater: open install directory: %w", err)
	}
	s.root = root
	lock, err := lockFile(ctx, root, opts.LockWait)
	if err != nil {
		root.Close()
		if errors.Is(err, ErrLocked) {
			return nil, err
		}
		return nil, fmt.Errorf("updater: %w", err)
	}
	s.lock = lock
	if err := s.load(); err != nil {
		s.close()
		return nil, fmt.Errorf("updater: %w", err)
	}
	return s, nil
}

func (s *session) close() {
	if s.lock != nil {
		s.lock.Close()
	}
	s.root.Close()
}

func (s *session) load() error {
	st, exists, err := readState(s.root, s.installAbs)
	if err != nil {
		return err
	}
	s.st = st
	if !exists {
		// Bootstrapped by an installer: adopt the running version if its
		// executables pass code signature verification, so that a rollback
		// to it is possible.
		if st.Current != "" {
			in, err := s.adopt(st.Current)
			if err != nil {
				s.log.Warn("current version not adopted; rollback to it will be refused", "version", st.Current, "error", err)
			} else {
				st.Installed[st.Current] = in
				s.log.Info("adopted current version", "version", st.Current, "files", len(in.Files))
			}
		}
		return nil
	}
	return s.reconcile()
}

// reconcile repairs a current link that disagrees with state.json, which
// happens when a run stopped between writing the state and switching the
// link.
func (s *session) reconcile() error {
	if s.st.Current == "" {
		return nil
	}
	link, err := currentFromLink(s.root, s.installAbs)
	if err == nil && link == s.st.Current {
		return nil
	}
	if verr := s.verifyInstalled(s.st.Current); verr != nil {
		s.log.Error("current link disagrees with the state and the recorded version does not verify", "link", link, "state", s.st.Current, "error", verr)
		return nil
	}
	s.log.Warn("repairing current link", "link", link, "state", s.st.Current, "link_error", err)
	return s.switchCurrent(s.st.Current)
}

func readState(root *os.Root, installAbs string) (*State, bool, error) {
	f, err := openRegular(root, stateName)
	if errors.Is(err, fs.ErrNotExist) {
		cur, err := currentFromLink(root, installAbs)
		if err != nil {
			return nil, false, err
		}
		return &State{SchemaVersion: StateSchemaVersion, Current: cur, Installed: map[string]Installed{}}, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read %s: %w", stateName, err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return nil, false, fmt.Errorf("read %s: %w", stateName, err)
	}
	st, err := decodeState(b)
	if err != nil {
		return nil, false, err
	}
	if st.Installed == nil {
		st.Installed = map[string]Installed{}
	}
	return st, true, nil
}

// currentFromLink returns the version the current link points to, or ""
// when there is no link. It reads the link; it never follows it.
func currentFromLink(root *os.Root, installAbs string) (string, error) {
	target, err := readCurrentLink(root, installAbs)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read %s link: %w", currentName, err)
	}
	t := target
	if filepath.IsAbs(t) {
		rel, err := filepath.Rel(installAbs, filepath.Clean(t))
		if err != nil {
			return "", fmt.Errorf("%s link points outside the install directory: %q", currentName, target)
		}
		t = rel
	}
	t = path.Clean(filepath.ToSlash(t))
	dir, v, ok := strings.Cut(t, "/")
	if !ok || dir != versionsDir || !sign.ValidVersion(v) {
		return "", fmt.Errorf("%s link has an unexpected target %q", currentName, target)
	}
	return v, nil
}

func (s *session) commit(next *State) error {
	b, err := encodeState(next)
	if err != nil {
		return err
	}
	tmp := ".state.json.tmp-" + randSuffix()
	if err := writeFileSync(s.root, tmp, b, 0o644); err != nil {
		s.root.Remove(tmp)
		return fmt.Errorf("updater: write %s: %w", stateName, err)
	}
	if err := renameRetry(s.root, tmp, stateName); err != nil {
		s.root.Remove(tmp)
		return fmt.Errorf("updater: write %s: %w", stateName, err)
	}
	if err := syncDir(s.root, "."); err != nil {
		return fmt.Errorf("updater: %w", err)
	}
	s.st = next
	return nil
}

// switchCurrent points the current link at versions/<v> so that a reader
// always sees one complete target (see replaceCurrentLink).
func (s *session) switchCurrent(v string) error {
	if err := replaceCurrentLink(s.root, s.installAbs, v); err != nil {
		return err
	}
	if err := syncDir(s.root, "."); err != nil {
		return fmt.Errorf("updater: %w", err)
	}
	return nil
}

func (s *session) reject(spool *os.Root, res *Result, name, reason string, args ...any) {
	s.log.Warn("spool entry rejected", append([]any{"name", name, "reason", reason}, args...)...)
	res.Rejected = append(res.Rejected, Rejected{Name: name, Reason: reason})
	s.removeSpool(spool, name)
}

func (s *session) removeSpool(spool *os.Root, name string) {
	if err := spool.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.log.Error("cannot delete spool entry", "name", name, "error", err)
	}
}

// checkSpoolEntry reports whether name is a regular file. Other entries are
// refused and left in place.
func (s *session) checkSpoolEntry(spool *os.Root, res *Result, name string) bool {
	f, err := openRegular(spool, name)
	if err != nil {
		s.log.Warn("spool entry refused", "name", name, "error", err)
		res.Rejected = append(res.Rejected, Rejected{Name: name, Reason: err.Error()})
		return false
	}
	f.Close()
	return true
}

func (s *session) handleConfirm(spool *os.Root, c spoolBundle, res *Result) error {
	if !s.checkSpoolEntry(spool, res, c.name) {
		return nil
	}
	p := s.st.Pending
	if p == nil || !sameVersion(p.Version, c.version) {
		s.log.Info("confirmation does not match a pending version", "version", c.version)
		s.removeSpool(spool, c.name)
		return nil
	}
	next := s.st.clone()
	next.Pending = nil
	if err := s.commit(next); err != nil {
		return err
	}
	s.log.Info("version confirmed", "version", c.version, "attempts", p.Attempts)
	res.Confirmed = p.Version
	s.removeSpool(spool, c.name)
	return nil
}

func (s *session) handleRollback(spool *os.Root, res *Result) error {
	if !s.checkSpoolEntry(spool, res, RollbackName) {
		return nil
	}
	failed := s.st.Current
	ok, err := s.rollback("requested through the spool")
	if err != nil {
		return err
	}
	if ok {
		res.RolledBack = failed
	}
	s.removeSpool(spool, RollbackName)
	return nil
}

func (s *session) applyBundle(ctx context.Context, spool *os.Root, b spoolBundle, res *Result) error {
	f, err := openRegular(spool, b.name)
	if err != nil {
		s.log.Warn("spool entry refused", "name", b.name, "error", err)
		res.Rejected = append(res.Rejected, Rejected{Name: b.name, Reason: err.Error()})
		return nil
	}
	bundle, err := release.Open(ctx, f, s.now())
	f.Close()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.reject(spool, res, b.name, "invalid bundle", "error", err)
		return nil
	}
	v := bundle.Version()
	if v != b.version {
		s.reject(spool, res, b.name, "file name does not match the manifest version", "manifest_version", v)
		return nil
	}
	if s.st.isFailed(v) {
		s.reject(spool, res, b.name, "version was rolled back before", "version", v)
		return nil
	}
	if cur := s.st.Current; cur != "" && !sign.Newer(v, cur) {
		s.reject(spool, res, b.name, "version is not newer than the current version", "version", v, "current", cur)
		return nil
	}
	files := bundle.Files(s.goos, s.arch)
	if len(files) == 0 {
		s.reject(spool, res, b.name, "bundle has no files for this platform", "platform", s.goos+"/"+s.arch)
		return nil
	}
	files = slices.DeleteFunc(files, func(f release.File) bool { return !s.agentFiles[f.Name] })
	if !slices.ContainsFunc(files, func(f release.File) bool { return f.Name == s.agentExe }) {
		s.reject(spool, res, b.name, "bundle has no "+s.agentExe+" for this platform", "platform", s.goos+"/"+s.arch)
		return nil
	}
	if err := s.install(v, files, bundle.ManifestBytes()); err != nil {
		return err
	}
	res.Installed = v
	s.removeSpool(spool, b.name)
	return nil
}

func (s *session) install(v string, files []release.File, manifest []byte) error {
	if err := s.root.MkdirAll(versionsDir, 0o755); err != nil {
		return fmt.Errorf("updater: create %s: %w", versionsDir, err)
	}
	tmp := versionsDir + "/.tmp-" + randSuffix()
	if err := mkdirMode(s.root, tmp, 0o755); err != nil {
		return fmt.Errorf("updater: create %s: %w", tmp, err)
	}
	done := false
	defer func() {
		if !done {
			s.root.RemoveAll(tmp)
		}
	}()
	sums := make(map[string]string, len(files))
	for _, f := range files {
		if err := writeFileSync(s.root, tmp+"/"+f.Name, f.Data, 0o755); err != nil {
			return fmt.Errorf("updater: write %s: %w", f.Name, err)
		}
		d := sha256.Sum256(f.Data)
		sums[f.Name] = hex.EncodeToString(d[:])
	}
	if err := syncDir(s.root, tmp); err != nil {
		return fmt.Errorf("updater: %w", err)
	}
	dst := versionsDir + "/" + v
	// A leftover directory for a version newer than the current one is not
	// in the state and carries no meaning.
	if _, err := s.root.Lstat(dst); err == nil {
		if err := s.root.RemoveAll(dst); err != nil {
			return fmt.Errorf("updater: remove stale %s: %w", dst, err)
		}
	}
	if err := renameRetry(s.root, tmp, dst); err != nil {
		return fmt.Errorf("updater: install %s: %w", dst, err)
	}
	done = true
	if err := syncDir(s.root, versionsDir); err != nil {
		return fmt.Errorf("updater: %w", err)
	}

	now := s.now().UTC()
	prev := s.st.Current
	if p := s.st.Pending; p != nil && p.Version == s.st.Current {
		// The current version never confirmed: keep the last confirmed one
		// as the rollback target.
		prev = s.st.Previous
	}
	ms := sha256.Sum256(manifest)
	next := s.st.clone()
	next.Current = v
	next.Previous = prev
	next.Pending = &Pending{Version: v, Since: now}
	next.Installed[v] = Installed{Source: SourceBundle, InstalledAt: now, ManifestSHA256: hex.EncodeToString(ms[:]), Files: sums}
	for k := range next.Installed {
		if k != v && k != prev {
			delete(next.Installed, k)
		}
	}
	next.Failed = slices.DeleteFunc(next.Failed, func(f Failed) bool { return !sign.Newer(f.Version, v) })
	// State first: if the link switch does not happen, reconcile repairs it
	// on the next run.
	if err := s.commit(next); err != nil {
		return err
	}
	if err := s.switchCurrent(v); err != nil {
		return err
	}
	s.log.Info("version installed", "version", v, "previous", prev, "files", len(files))
	return nil
}

// rollback switches current back to the previous version. It returns false
// when the rollback is refused; the error is only for operational failures.
func (s *session) rollback(reason string) (bool, error) {
	st := s.st
	if st.Pending == nil {
		s.log.Warn("rollback refused: no version is pending", "current", st.Current)
		return false, nil
	}
	if st.Previous == "" {
		s.log.Error("rollback refused: no previous version", "current", st.Current, "reason", reason)
		return false, nil
	}
	if err := s.verifyInstalled(st.Previous); err != nil {
		s.log.Error("rollback refused: previous version does not verify", "previous", st.Previous, "reason", reason, "error", err)
		return false, nil
	}
	failed := st.Current
	next := st.clone()
	next.Current = st.Previous
	next.Previous = ""
	next.Pending = nil
	delete(next.Installed, failed)
	next.Failed = append(next.Failed, Failed{Version: failed, At: s.now().UTC(), Reason: reason})
	if len(next.Failed) > maxFailed {
		next.Failed = next.Failed[len(next.Failed)-maxFailed:]
	}
	if err := s.commit(next); err != nil {
		return false, err
	}
	if err := s.switchCurrent(next.Current); err != nil {
		return false, err
	}
	if err := s.root.RemoveAll(versionsDir + "/" + failed); err != nil {
		s.log.Error("cannot remove failed version", "version", failed, "error", err)
	}
	s.log.Warn("rolled back", "failed", failed, "current", next.Current, "reason", reason)
	return true, nil
}

// verifyInstalled checks that versions/<v> is a directory this updater
// recorded and that it holds exactly the recorded agent files with the
// recorded hashes. Other bundle files (otherBaseNames), recorded or not, are
// ignored: the agent never runs them.
func (s *session) verifyInstalled(v string) error {
	in, ok := s.st.Installed[v]
	if !ok {
		return fmt.Errorf("version %s was not installed by this updater", v)
	}
	dir := versionsDir + "/" + v
	fi, err := s.root.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	names, err := readDirNames(s.root, dir)
	if err != nil {
		return err
	}
	recorded := 0
	for name := range in.Files {
		if s.agentFiles[name] {
			recorded++
		}
	}
	if recorded == 0 {
		return fmt.Errorf("no agent files recorded for %s", dir)
	}
	present := 0
	for _, name := range names {
		if s.otherFiles[name] {
			continue
		}
		want, ok := in.Files[name]
		if !ok || !s.agentFiles[name] {
			return fmt.Errorf("%s: unexpected entry %q", dir, name)
		}
		present++
		got, err := s.hashFile(dir + "/" + name)
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("%s/%s: SHA-256 differs from the recorded value", dir, name)
		}
	}
	if present != recorded {
		return fmt.Errorf("%s holds %d of %d recorded agent files", dir, present, recorded)
	}
	return nil
}

func (s *session) hashFile(name string) (string, error) {
	f, err := openRegular(s.root, name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxFileSize)); err != nil {
		return "", fmt.Errorf("read %s: %w", name, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// adopt verifies the files of a version directory that was not installed by
// this updater: each agent file must be an executable of this operating
// system and architecture with a valid code signature. Other bundle files
// are ignored and not recorded.
func (s *session) adopt(v string) (Installed, error) {
	dir := versionsDir + "/" + v
	fi, err := s.root.Lstat(dir)
	if err != nil {
		return Installed{}, err
	}
	if !fi.IsDir() {
		return Installed{}, fmt.Errorf("%s is not a directory", dir)
	}
	names, err := readDirNames(s.root, dir)
	if err != nil {
		return Installed{}, err
	}
	sums := make(map[string]string, len(names))
	for _, name := range names {
		if s.otherFiles[name] {
			continue
		}
		if !s.agentFiles[name] {
			return Installed{}, fmt.Errorf("%s: unexpected entry %q", dir, name)
		}
		data, err := s.readFile(dir + "/" + name)
		if err != nil {
			return Installed{}, err
		}
		if err := release.VerifyCode(s.goos, data, s.arch); err != nil {
			return Installed{}, fmt.Errorf("%s/%s: %w", dir, name, err)
		}
		d := sha256.Sum256(data)
		sums[name] = hex.EncodeToString(d[:])
	}
	if _, ok := sums[s.agentExe]; !ok {
		return Installed{}, fmt.Errorf("%s has no %s", dir, s.agentExe)
	}
	return Installed{Source: SourceAdopted, InstalledAt: s.now().UTC(), Files: sums}, nil
}

func (s *session) readFile(name string) ([]byte, error) {
	f, err := openRegular(s.root, name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	if len(data) > maxFileSize {
		return nil, fmt.Errorf("%s exceeds %d bytes", name, maxFileSize)
	}
	return data, nil
}

// cleanup removes everything in versions/ except the current and the
// previous version, and temporary files left in the install directory by an
// interrupted run.
func (s *session) cleanup() {
	if top, err := readDirNames(s.root, "."); err == nil {
		for _, n := range top {
			if strings.HasPrefix(n, ".current.tmp-") || strings.HasPrefix(n, ".state.json.tmp-") {
				s.root.Remove(n)
			}
		}
	}
	names, err := readDirNames(s.root, versionsDir)
	if err != nil {
		s.log.Error("cannot list versions", "error", err)
		return
	}
	for _, n := range names {
		if n == s.st.Current || n == s.st.Previous {
			continue
		}
		if err := s.root.RemoveAll(versionsDir + "/" + n); err != nil {
			s.log.Error("cannot remove old version", "name", n, "error", err)
			continue
		}
		s.log.Info("removed old version", "name", n)
	}
}

func readDirNames(root *os.Root, name string) ([]string, error) {
	d, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	slices.Sort(names)
	return names, nil
}

func sameVersion(a, b string) bool {
	c, err := sign.CompareVersions(a, b)
	return err == nil && c == 0
}
