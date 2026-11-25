// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package update is the agent side of automatic updates (ARCH 6.4,
// SECURITY §5.2): it asks the server for the deployed version, downloads a
// newer release bundle into the update spool for the updater, starts the
// updater when no service runs it (systemd units on Linux; on Windows the
// bomcensus-updater service always does), confirms a pending version after
// the first successful poll and re-executes the agent when the current link
// points to another version. It never installs anything itself.
package update

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/bomcensus/bomcensus/internal/agent/core"
	"github.com/bomcensus/bomcensus/internal/agent/state"

	"github.com/bomcensus/bomcensus/agentproto/dto"
	"github.com/bomcensus/bomcensus/internal/platform/paths"
	"github.com/bomcensus/bomcensus/internal/sign"
	"github.com/bomcensus/bomcensus/internal/updater"
)

// DefaultSpool is the default update spool directory of this system.
var DefaultSpool = paths.UpdateSpoolDir()

// Defaults.
const (
	// UpdaterName is the updater executable inside a version directory,
	// without the ".exe" suffix it has on Windows.
	UpdaterName = "bomcensus-updater"
	// SystemdEnv is set by the systemd units when a path unit runs the
	// updater and a unit before the agent runs boot-check.
	SystemdEnv   = "BOMCENSUS_UPDATER"
	SystemdValue = "systemd"
	// maxBundle bounds a download without a size from the server.
	maxBundle = 1 << 30
)

// ReexecError asks the caller to replace the process with Path.
type ReexecError struct {
	Path    string
	Version string
}

func (e *ReexecError) Error() string {
	return fmt.Sprintf("version %s is current, restarting from %s", e.Version, e.Path)
}

// Options configures a Manager.
type Options struct {
	InstallDir string
	SpoolDir   string
	// Version is the running version.
	Version string
	// Systemd is true when a service runs the updater: the systemd units
	// on Linux. On Windows it is always treated as true, because there the
	// bomcensus-updater service runs the updater and the agent's account
	// cannot write the install directory.
	Systemd bool
	// Executable is the running binary (default os.Executable()).
	Executable string
	// RunUpdater runs the updater with args; nil runs
	// <current>/bomcensus-updater as a child.
	RunUpdater func(ctx context.Context, args ...string) error
	// WatchInterval is how often the current link is checked (default 10 s).
	WatchInterval time.Duration
	// DefaultCheckInterval is used until the server sends one (default 1 h).
	DefaultCheckInterval time.Duration
	// PendingTimeout is how long the running version may stay pending
	// before the agent asks the updater for a rollback (default
	// updater.DefaultPendingTimeout, the boot-check limit).
	PendingTimeout time.Duration
	Logger         *slog.Logger
	Now            func() time.Time
}

// Manager runs the update flow.
type Manager struct {
	o   Options
	log *slog.Logger

	mu        sync.Mutex
	interval  time.Duration
	confirmed bool
	rollback  bool
	message   string
}

// DeriveInstallDir returns <install> when exe is <install>/versions/<v>/<name>
// or, on Windows, <install>/current/<name>. The second form is how a Windows
// service started through the current junction sees its executable, because
// filepath.EvalSymlinks does not resolve junctions.
func DeriveInstallDir(exe string) (string, bool) {
	return deriveInstallDir(runtime.GOOS, exe)
}

func deriveInstallDir(goos, exe string) (string, bool) {
	dir := filepath.Dir(exe)
	v := filepath.Base(dir)
	parent := filepath.Dir(dir)
	if goos == "windows" && v == "current" && parent != dir {
		return parent, true
	}
	if filepath.Base(parent) != "versions" || !sign.ValidVersion(v) {
		return "", false
	}
	return filepath.Dir(parent), true
}

// New returns a manager. InstallDir must be set.
func New(o Options) (*Manager, error) {
	if o.InstallDir == "" {
		return nil, errors.New("update: install directory is required")
	}
	if o.SpoolDir == "" {
		o.SpoolDir = DefaultSpool
	}
	if o.WatchInterval <= 0 {
		o.WatchInterval = 10 * time.Second
	}
	if o.DefaultCheckInterval <= 0 {
		o.DefaultCheckInterval = time.Hour
	}
	if o.PendingTimeout <= 0 {
		o.PendingTimeout = updater.DefaultPendingTimeout
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if runtime.GOOS == "windows" {
		o.Systemd = true
	}
	if o.Executable == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, err
		}
		o.Executable = exe
	}
	if abs, err := filepath.EvalSymlinks(o.Executable); err == nil {
		o.Executable = abs
	}
	m := &Manager{o: o, log: o.Logger, interval: o.DefaultCheckInterval}
	if m.o.RunUpdater == nil {
		m.o.RunUpdater = m.execUpdater
	}
	return m, nil
}

// Attach registers the manager's tasks and hooks on rt.
func (m *Manager) Attach(rt *core.Runtime) {
	rt.OnConfig(func(_ context.Context, cfg dto.AgentConfig) {
		if cfg.UpdateCheckIntervalMinutes > 0 {
			m.setInterval(time.Duration(cfg.UpdateCheckIntervalMinutes) * time.Minute)
		}
	})
	rt.OnPoll(m.confirm)
	rt.OnStatus(func(ctx context.Context, req *dto.PollRequest) { req.Update = m.Status(ctx) })
	rt.AddTask(core.Task{
		Name:      "update check",
		Interval:  m.checkInterval,
		Immediate: true,
		Run:       func(ctx context.Context) error { return m.Check(ctx, rt) },
	})
	rt.AddTask(core.Task{
		Name:     "current version watch",
		Interval: func() time.Duration { return m.o.WatchInterval },
		Run: func(ctx context.Context) error {
			m.expirePending(ctx)
			if re := m.Changed(ctx); re != nil {
				rt.Stop(re)
			}
			return nil
		},
	})
}

func (m *Manager) setInterval(d time.Duration) {
	m.mu.Lock()
	m.interval = d
	m.mu.Unlock()
}

func (m *Manager) checkInterval() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.interval
}

// BootCheck runs "bomcensus-updater boot-check" unless systemd does, and
// reports a version change the updater made (rollback).
func (m *Manager) BootCheck(ctx context.Context) *ReexecError {
	if !m.o.Systemd {
		if err := m.o.RunUpdater(ctx, "boot-check", "--install", m.o.InstallDir); err != nil {
			m.log.Warn("updater boot-check failed", "error", err)
		}
	}
	return m.Changed(ctx)
}

// Changed reports when the current link points to another version than the
// running binary.
func (m *Manager) Changed(ctx context.Context) *ReexecError {
	v, dir, err := updater.Current(ctx, m.o.InstallDir)
	if err != nil {
		m.log.Warn("read current version", "error", err)
		return nil
	}
	if v == "" || v == m.o.Version || dir == filepath.Dir(m.o.Executable) {
		return nil
	}
	return &ReexecError{Path: filepath.Join(dir, updater.ExeName(updater.AgentName)), Version: v}
}

// Status describes the update state for the poll request.
func (m *Manager) Status(ctx context.Context) dto.UpdateStatus {
	out := dto.UpdateStatus{State: dto.UpdateStateUpToDate}
	st, err := updater.Status(ctx, m.o.InstallDir)
	if err != nil {
		msg := err.Error()
		out.Message = &msg
		return out
	}
	if st.Previous != "" {
		p := st.Previous
		out.PreviousVersion = &p
	}
	switch {
	case st.Pending != nil:
		out.State = dto.UpdateStatePending
	case m.spooled():
		out.State = dto.UpdateStateUpdating
	case len(st.Failed) > 0 && sign.Newer(st.Failed[len(st.Failed)-1].Version, m.o.Version):
		out.State = dto.UpdateStateRolledBack
		msg := fmt.Sprintf("version %s was rolled back: %s", st.Failed[len(st.Failed)-1].Version, st.Failed[len(st.Failed)-1].Reason)
		out.Message = &msg
	}
	m.mu.Lock()
	if m.message != "" && out.Message == nil {
		msg := m.message
		out.Message = &msg
	}
	m.mu.Unlock()
	return out
}

func (m *Manager) spooled() bool {
	des, err := os.ReadDir(m.o.SpoolDir)
	if err != nil {
		return false
	}
	for _, de := range des {
		if n := de.Name(); strings.HasPrefix(n, "bomcensus-") && strings.HasSuffix(n, ".tar") {
			return true
		}
	}
	return false
}

// confirm writes the confirmation of a pending version after the first
// successful signed poll of that version.
func (m *Manager) confirm(ctx context.Context) {
	m.mu.Lock()
	done := m.confirmed
	m.mu.Unlock()
	if done {
		return
	}
	st, err := updater.Status(ctx, m.o.InstallDir)
	if err != nil {
		m.log.Warn("read update state", "error", err)
		return
	}
	if st.Pending == nil {
		m.mu.Lock()
		m.confirmed = true
		m.mu.Unlock()
		return
	}
	if c, err := sign.CompareVersions(st.Pending.Version, m.o.Version); err != nil || c != 0 {
		return
	}
	if err := m.writeSpool(updater.ConfirmName(m.o.Version), []byte(m.o.Version+"\n")); err != nil {
		m.log.Error("write update confirmation", "error", err)
		return
	}
	m.mu.Lock()
	m.confirmed = true
	m.mu.Unlock()
	m.log.Info("confirmed pending version", "version", m.o.Version)
	m.apply(ctx)
}

// expirePending requests a rollback when the running version is still
// pending after PendingTimeout. boot-check enforces the same limit, but only
// at start: a new version that keeps running without ever reaching the
// server would otherwise stay unconfirmed until the next restart.
func (m *Manager) expirePending(ctx context.Context) {
	m.mu.Lock()
	done := m.confirmed || m.rollback
	m.mu.Unlock()
	if done {
		return
	}
	st, err := updater.Status(ctx, m.o.InstallDir)
	if err != nil || st.Pending == nil {
		return
	}
	if c, err := sign.CompareVersions(st.Pending.Version, m.o.Version); err != nil || c != 0 {
		return
	}
	age := m.o.Now().Sub(st.Pending.Since)
	if age <= m.o.PendingTimeout {
		return
	}
	m.log.Warn("pending version was not confirmed in time, requesting rollback",
		"version", m.o.Version, "pending_for", age.Round(time.Second), "limit", m.o.PendingTimeout)
	if err := m.writeSpool(updater.RollbackName, nil); err != nil {
		m.log.Error("write rollback request", "error", err)
		return
	}
	m.mu.Lock()
	m.rollback = true
	m.mu.Unlock()
	m.apply(ctx)
}

func (m *Manager) writeSpool(name string, data []byte) error {
	if err := os.MkdirAll(m.o.SpoolDir, 0o750); err != nil {
		return err
	}
	return state.WriteFileAtomic(filepath.Join(m.o.SpoolDir, name), data, 0o640)
}

// apply starts the updater unless a systemd path unit does.
func (m *Manager) apply(ctx context.Context) {
	if m.o.Systemd {
		return
	}
	if err := m.o.RunUpdater(ctx, "apply", "--spool", m.o.SpoolDir, "--install", m.o.InstallDir); err != nil {
		m.log.Warn("updater apply failed", "error", err)
	}
}

// Check asks the server for the deployed version and downloads it when it
// is newer than the running one.
func (m *Manager) Check(ctx context.Context, rt *core.Runtime) error {
	params := dto.CheckUpdateParams{Os: dto.TargetOs(runtime.GOOS), Arch: dto.TargetArch(runtime.GOARCH)}
	uc, err := rt.API().CheckUpdate(ctx, params)
	if err != nil {
		return fmt.Errorf("update check: %w", err)
	}
	if uc.CheckIntervalMinutes > 0 {
		m.setInterval(time.Duration(uc.CheckIntervalMinutes) * time.Minute)
	}
	if uc.TargetVersion == nil {
		return nil
	}
	target := *uc.TargetVersion
	if !sign.Newer(target, m.o.Version) {
		// Equal, older (never downgrade) or unparsable.
		return nil
	}
	st, err := updater.Status(ctx, m.o.InstallDir)
	if err != nil {
		return err
	}
	if st.Current == target {
		return nil
	}
	for _, f := range st.Failed {
		if f.Version == target {
			m.setMessage(fmt.Sprintf("version %s was rolled back before; not installing it again", target))
			return nil
		}
	}
	if uc.Manifest == nil || uc.ManifestSignature == nil {
		return errors.New("update check: no manifest for the deployed version")
	}
	man, err := sign.VerifyManifest(*uc.Manifest, *uc.ManifestSignature, m.o.Now())
	if err != nil {
		m.setMessage("manifest of " + target + " does not verify")
		return fmt.Errorf("update check: %w", err)
	}
	if man.Version != target {
		return fmt.Errorf("update check: manifest is for %s, not %s", man.Version, target)
	}
	if len(man.FilesFor(runtime.GOOS, runtime.GOARCH)) == 0 {
		return fmt.Errorf("update check: release %s has no files for %s/%s", target, runtime.GOOS, runtime.GOARCH)
	}
	name := updater.BundleName(target)
	if _, err := os.Stat(filepath.Join(m.o.SpoolDir, name)); err != nil {
		var size int64
		if uc.BundleSize != nil {
			size = *uc.BundleSize
		}
		if err := m.download(ctx, rt, target, size); err != nil {
			return err
		}
		m.log.Info("release downloaded", "version", target)
	}
	m.setMessage("")
	m.apply(ctx)
	if re := m.Changed(ctx); re != nil {
		rt.Stop(re)
	}
	return nil
}

func (m *Manager) setMessage(s string) {
	m.mu.Lock()
	m.message = s
	m.mu.Unlock()
}

// download stores the bundle under a temporary name and renames it to the
// name the updater picks up only when it is complete.
func (m *Manager) download(ctx context.Context, rt *core.Runtime, version string, size int64) error {
	if err := os.MkdirAll(m.o.SpoolDir, 0o750); err != nil {
		return fmt.Errorf("update spool: %w", err)
	}
	params := dto.DownloadUpdateBundleParams{Os: dto.TargetOs(runtime.GOOS), Arch: dto.TargetArch(runtime.GOARCH)}
	resp, err := rt.API().DownloadUpdateBundle(ctx, version, params)
	if err != nil {
		return fmt.Errorf("download %s: %w", version, err)
	}
	defer resp.Body.Close()
	limit := int64(maxBundle)
	if size > 0 {
		limit = size
	}
	part := filepath.Join(m.o.SpoolDir, "."+updater.BundleName(version)+".part")
	f, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return fmt.Errorf("download %s: %w", version, err)
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(part)
		}
	}()
	n, err := io.Copy(f, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return fmt.Errorf("download %s: %w", version, err)
	}
	if n > limit || (size > 0 && n != size) {
		return fmt.Errorf("download %s: got %d bytes, want %d", version, n, size)
	}
	if err := f.Chmod(0o640); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(part, filepath.Join(m.o.SpoolDir, updater.BundleName(version))); err != nil {
		return fmt.Errorf("download %s: %w", version, err)
	}
	ok = true
	if d, err := os.Open(m.o.SpoolDir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// execUpdater runs <current>/bomcensus-updater as a child.
func (m *Manager) execUpdater(ctx context.Context, args ...string) error {
	_, dir, err := updater.Current(ctx, m.o.InstallDir)
	if err != nil {
		return err
	}
	if dir == "" {
		return errors.New("no current version")
	}
	path := filepath.Join(dir, updater.ExeName(UpdaterName))
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s not found", path)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		m.log.Info("updater output", "command", args[0], "output", strings.TrimSpace(string(out)))
	}
	if err != nil {
		return fmt.Errorf("%s %s: %w", path, args[0], err)
	}
	return nil
}
