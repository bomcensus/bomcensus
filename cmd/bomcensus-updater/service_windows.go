// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/bomcensus/bomcensus/internal/platform/winsvc"
	"github.com/bomcensus/bomcensus/internal/updater"
)

const serviceName = "bomcensus-updater"

type scmAgent struct{ c *winsvc.Control }

func (a scmAgent) PID() (uint32, error) { return a.c.PID() }

func (a scmAgent) Restart(ctx context.Context) error { return a.c.Restart(ctx, 2*time.Minute) }

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

func runService(c serviceConfig, stderr io.Writer) error {
	if !winsvc.IsService() {
		fmt.Fprintln(stderr, "bomcensus-updater: the service command runs only under the service control manager; see deploy/windows/install.ps1")
		return errUsage
	}
	var logw io.WriteCloser = nopCloser{stderr}
	if el, err := winsvc.EventLog(serviceName); err == nil {
		logw = el
	}
	defer logw.Close()
	log := newLogger(logw)
	agent := &winsvc.Control{Name: c.agentService}
	defer agent.Close()
	w := &watcher{
		opts:   updater.Options{InstallDir: c.install, Logger: log, LockWait: c.lockWait},
		spool:  c.spool,
		limits: c.limits,
		agent:  scmAgent{agent},
		log:    log,
		now:    time.Now,
	}
	err := winsvc.Run(serviceName, w.start, func(ctx context.Context) error { return w.run(ctx, c.interval) })
	switch {
	case errors.Is(err, errSwitched):
		log.Info("exiting to run the updater of the current version")
	case err != nil:
		log.Error("service stopped", "error", err)
	}
	return err
}
