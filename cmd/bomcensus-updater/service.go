// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/bomcensus/bomcensus/internal/platform/paths"
	"github.com/bomcensus/bomcensus/internal/updater"
)

// The resident updater of the Windows service. On Linux systemd units do the
// same work: a path unit starts "apply" when the spool changes and a unit
// before the agent runs "boot-check". On Windows one service does both:
//
//   - At start, before it reports RUNNING, it runs the boot check and removes
//     old version directories. The agent service depends on it, so at boot
//     the agent starts only after that.
//   - Every poll interval it runs apply when the spool holds an entry for it.
//   - While a version is pending it counts each new process of the agent
//     service as a start (the boot check that Linux runs before every agent
//     start) and rolls back a version that stays pending too long.
//   - When the current version changed (install or rollback), it restarts
//     the agent service and then exits with a failure status. The service
//     manager restarts the updater through its recovery actions, from the
//     current link, so the updater of the new version takes over.

// errSwitched ends the service after the current version changed.
var errSwitched = errors.New("current version changed; exiting so that the service manager starts the updater of that version")

// agentService is the part of the service manager the updater uses.
type agentService interface {
	// PID returns the process ID of the agent service, 0 when it does not run.
	PID() (uint32, error)
	// Restart restarts the agent service if it runs.
	Restart(ctx context.Context) error
}

type watcher struct {
	opts   updater.Options
	spool  string
	limits updater.BootLimits
	agent  agentService
	log    *slog.Logger
	now    func() time.Time

	// cur is the current version last read; curOK is false until a read
	// succeeded.
	cur   string
	curOK bool

	agentPID uint32
	// counted is set when the boot check at start counted the agent start
	// that follows it.
	counted  bool
	switched bool
	// expireRefused is the pending version whose timeout rollback was
	// refused (no previous version, or one that does not verify). It is not
	// tried again on every poll.
	expireRefused *updater.Pending
	// refused holds spool entries Apply refused and left in place, with
	// their modification time. They do not start Apply again until they
	// change.
	refused map[string]time.Time
}

// current returns the current version; ok is false when it cannot be read.
func (w *watcher) current(ctx context.Context) (v string, ok bool) {
	v, _, err := updater.Current(ctx, w.opts.InstallDir)
	if err != nil {
		w.log.Warn("read current version", "error", err)
		return "", false
	}
	return v, true
}

// changed reads the current version and reports whether it differs from
// the one read last. A failed read is not a change and keeps the last one.
func (w *watcher) changed(ctx context.Context) bool {
	v, ok := w.current(ctx)
	if !ok {
		return false
	}
	was := w.curOK && v != w.cur
	w.cur, w.curOK = v, true
	return was
}

// start runs before the service reports RUNNING.
//
// At boot the agent service has not started yet (it depends on this
// service): the boot check counts the start that follows. When the agent
// already runs, its process was counted when it started, unless a version
// was just installed and nothing has counted a start of it yet (the
// updater that installed it restarted the agent and exited). Counting it
// again on every updater restart would roll back a version that never
// failed.
func (w *watcher) start(ctx context.Context) error {
	w.cur, w.curOK = w.current(ctx)
	pid, err := w.agent.PID()
	if err != nil {
		w.log.Warn("query agent service", "error", err)
	}
	count := pid == 0
	if !count {
		st, err := updater.Status(ctx, w.opts.InstallDir)
		if err != nil {
			w.log.Warn("read install state", "error", err)
		}
		count = err == nil && st.Pending != nil && st.Pending.Attempts == 0
	}
	var res *updater.Result
	if count {
		res, err = updater.BootCheck(ctx, w.opts, w.limits)
	} else {
		res, err = updater.ExpirePending(ctx, w.opts, w.limits)
	}
	if err != nil {
		return err
	}
	if res.RolledBack != "" {
		w.log.Warn("boot check rolled back", "version", res.RolledBack)
	}
	if err := updater.Cleanup(ctx, w.opts); err != nil {
		w.log.Warn("cleanup", "error", err)
	}
	w.agentPID = pid
	w.counted = pid == 0
	w.switched = w.changed(ctx)
	return nil
}

// run polls until ctx ends or the current version changes.
func (w *watcher) run(ctx context.Context, interval time.Duration) error {
	if w.switched {
		return w.afterSwitch(ctx)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := w.tick(ctx); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func (w *watcher) tick(ctx context.Context) error {
	if !w.curOK {
		w.cur, w.curOK = w.current(ctx)
	}
	if w.spoolHasWork() {
		res, err := updater.Apply(ctx, w.opts, w.spool)
		switch {
		case ctx.Err() != nil:
			return nil
		case errors.Is(err, updater.ErrLocked):
			w.log.Info("install directory is locked by another updater; trying again")
		case err != nil:
			w.log.Error("apply", "error", err)
		default:
			w.log.Info("spool processed", "installed", res.Installed, "confirmed", res.Confirmed, "rolled_back", res.RolledBack, "rejected", len(res.Rejected))
		}
		if res != nil {
			w.noteRefused(res.Rejected)
		}
	}
	w.watchAgent(ctx)
	if ctx.Err() != nil {
		return nil
	}
	if w.changed(ctx) {
		return w.afterSwitch(ctx)
	}
	return nil
}

// watchAgent counts new agent processes while a version is pending and
// enforces the pending timeout.
func (w *watcher) watchAgent(ctx context.Context) {
	pid, err := w.agent.PID()
	if err != nil {
		w.log.Warn("query agent service", "error", err)
		return
	}
	started := pid != 0 && pid != w.agentPID
	w.agentPID = pid
	if started && w.counted {
		w.counted = false
		started = false
	}
	st, err := updater.Status(ctx, w.opts.InstallDir)
	if err != nil {
		w.log.Warn("read install state", "error", err)
		return
	}
	if st.Pending == nil {
		return
	}
	var res *updater.Result
	expire := false
	switch {
	case started:
		res, err = updater.BootCheck(ctx, w.opts, w.limits)
	case w.now().Sub(st.Pending.Since) > w.limits.PendingTimeout:
		if w.expireRefused != nil && samePending(w.expireRefused, st.Pending) {
			return
		}
		expire = true
		res, err = updater.ExpirePending(ctx, w.opts, w.limits)
	default:
		return
	}
	if err != nil {
		if ctx.Err() == nil {
			w.log.Error("check pending version", "error", err)
		}
		return
	}
	if res.RolledBack != "" {
		w.log.Warn("rolled back", "version", res.RolledBack)
	} else if expire {
		// The updater logged why. A first install without a previous
		// version stays pending until the agent confirms it.
		p := *st.Pending
		w.expireRefused = &p
	}
}

func samePending(a, b *updater.Pending) bool {
	return a.Version == b.Version && a.Since.Equal(b.Since)
}

// spoolHasWork reports whether the spool holds an entry for Apply that it
// has not refused before in its current form.
func (w *watcher) spoolHasWork() bool {
	des, err := os.ReadDir(w.spool)
	if err != nil {
		w.log.Warn("read spool", "error", err)
		return false
	}
	work := false
	seen := make(map[string]bool, len(w.refused))
	for _, de := range des {
		name := de.Name()
		if !updater.IsSpoolEntry(name) {
			continue
		}
		if t, ok := w.refused[name]; ok {
			seen[name] = true
			if fi, err := de.Info(); err == nil && fi.ModTime().Equal(t) {
				continue
			}
		}
		work = true
	}
	for name := range w.refused {
		if !seen[name] {
			delete(w.refused, name)
		}
	}
	return work
}

// noteRefused records the rejected entries that Apply left in the spool.
func (w *watcher) noteRefused(rejected []updater.Rejected) {
	for _, r := range rejected {
		fi, err := os.Lstat(filepath.Join(w.spool, r.Name))
		if err != nil {
			continue
		}
		if w.refused == nil {
			w.refused = make(map[string]time.Time)
		}
		w.refused[r.Name] = fi.ModTime()
	}
}

func (w *watcher) afterSwitch(ctx context.Context) error {
	cur, _ := w.current(ctx)
	w.log.Info("current version changed, restarting the agent service", "current", cur)
	if err := w.agent.Restart(ctx); err != nil {
		w.log.Error("restart agent service", "error", err)
	}
	return errSwitched
}

// serviceConfig is what the service command parsed.
type serviceConfig struct {
	install, spool string
	agentService   string
	interval       time.Duration
	limits         updater.BootLimits
	lockWait       time.Duration
}

func runServiceCmd(_ context.Context, args []string, _, stderr io.Writer) error {
	fs := newFlagSet("service", "[--install DIR] [--spool DIR] [--agent-service NAME]", stderr)
	var c serviceConfig
	fs.StringVar(&c.install, "install", defaultInstall, "install `directory`")
	fs.StringVar(&c.spool, "spool", defaultSpool, "update spool `directory`")
	fs.StringVar(&c.agentService, "agent-service", paths.AgentService, "`name` of the agent service")
	fs.DurationVar(&c.interval, "poll", 5*time.Second, "how often the spool and the agent service are checked")
	fs.IntVar(&c.limits.MaxAttempts, "max-attempts", updater.DefaultMaxAttempts, "starts a pending version gets before it is rolled back")
	fs.DurationVar(&c.limits.PendingTimeout, "pending-timeout", updater.DefaultPendingTimeout, "how long a version may stay unconfirmed")
	fs.DurationVar(&c.lockWait, "lock-wait", 30*time.Second, "how long to wait for another updater to finish")
	if err := parse(fs, args); err != nil {
		return err
	}
	if c.interval <= 0 || c.limits.MaxAttempts < 1 || c.limits.PendingTimeout <= 0 {
		fs.Usage()
		return fmt.Errorf("%w: --poll, --max-attempts and --pending-timeout must be positive", errUsage)
	}
	return runService(c, stderr)
}
