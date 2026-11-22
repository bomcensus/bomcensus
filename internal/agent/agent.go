// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package agent is the host agent: it enrolls, keeps the connection to the
// server through internal/agent/core, collects sections on schedule or on
// request by invoking the probe, uploads the reports and drives automatic
// updates. It runs as any user and performs no privileged operation.
package agent

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/bomcensus/bomcensus/internal/agent/core"
	"github.com/bomcensus/bomcensus/internal/agent/probeexec"
	"github.com/bomcensus/bomcensus/internal/agent/state"
	"github.com/bomcensus/bomcensus/internal/agent/update"
	"github.com/bomcensus/bomcensus/internal/collect"
	"github.com/bomcensus/bomcensus/internal/collect/hostinfo"
	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/link"
	"github.com/bomcensus/bomcensus/internal/pki"
	"github.com/bomcensus/bomcensus/internal/platform/paths"
	"github.com/bomcensus/bomcensus/internal/version"
)

// Options configures Run.
type Options struct {
	StateDir string
	// InstallDir is the install directory. Empty derives it from the
	// executable path (<install>/versions/<v>/bomcensus-agent); when that
	// fails updates are disabled.
	InstallDir string
	// DisableUpdates turns the update flow off.
	DisableUpdates bool
	// UpdateSpool is the update spool directory (default update.DefaultSpool).
	UpdateSpool string
	// Systemd is true when systemd units run the updater (BOMCENSUS_UPDATER=systemd).
	Systemd bool
	// RunUpdater replaces running the updater executable.
	RunUpdater func(ctx context.Context, args ...string) error
	// UpdateWatchInterval is how often the current link is checked.
	UpdateWatchInterval time.Duration
	// UpdatePendingTimeout is how long a new version may run unconfirmed
	// before the agent requests a rollback (default: the boot-check limit).
	UpdatePendingTimeout time.Duration

	// Probe replaces the probe invocation; nil uses probeexec with
	// ProbeSocket, ProbePath and ProbeEnv.
	Probe       Prober
	ProbeSocket string
	ProbePath   string
	ProbeEnv    []string

	// Version defaults to version.Version.
	Version string
	Logger  *slog.Logger
	// Executable is the running binary (default os.Executable()).
	Executable string
	// Runtime tunes the core; its State, Kind, Version and Logger are set
	// by Run.
	Runtime core.Options
}

func (o *Options) defaults() {
	if o.StateDir == "" {
		o.StateDir = state.DefaultDir
	}
	if o.Version == "" {
		o.Version = version.Version
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Executable == "" {
		if exe, err := os.Executable(); err == nil {
			o.Executable = exe
		}
	}
}

// Run runs the agent until ctx ends (nil) or until it must re-execute
// itself after an update (*update.ReexecError). A pending enrollment is
// resumed.
func Run(ctx context.Context, o Options) error {
	o.defaults()
	log := o.Logger

	var um *update.Manager
	if !o.DisableUpdates {
		install := o.InstallDir
		if install == "" {
			if d, ok := update.DeriveInstallDir(o.Executable); ok {
				install = d
			}
		}
		if install == "" {
			log.Info("automatic updates disabled: the agent does not run from an install directory", "executable", o.Executable)
		} else {
			m, err := update.New(update.Options{
				InstallDir:     install,
				SpoolDir:       o.UpdateSpool,
				Version:        o.Version,
				Systemd:        o.Systemd,
				Executable:     o.Executable,
				RunUpdater:     o.RunUpdater,
				WatchInterval:  o.UpdateWatchInterval,
				PendingTimeout: o.UpdatePendingTimeout,
				Logger:         log,
			})
			if err != nil {
				return err
			}
			if re := m.BootCheck(ctx); re != nil {
				return re
			}
			um = m
		}
	}

	st, err := state.OpenAs(o.StateDir, paths.AgentService)
	if err != nil {
		return err
	}
	defer st.Close()

	ropts := o.Runtime
	ropts.State, ropts.Kind, ropts.Version, ropts.Logger = st, core.KindAgent, o.Version, log
	rt, err := core.New(ropts)
	if err != nil {
		if errors.Is(err, state.ErrNotEnrolled) {
			return errors.New("not enrolled; run 'bomcensus-agent enroll' first")
		}
		return err
	}
	probe := o.Probe
	if probe == nil {
		probe = &probeexec.Invoker{Socket: o.ProbeSocket, Path: o.ProbePath, Env: o.ProbeEnv, Logger: log}
	}
	if _, err := newCollector(rt, probe, log); err != nil {
		return err
	}
	if um != nil {
		um.Attach(rt)
	}
	return rt.Run(ctx)
}

// EnrollOptions configures Enroll.
type EnrollOptions struct {
	StateDir      string
	ServerURL     string
	Token         string
	ConnectMode   string
	ListenAddress string
	ServerName    string
	TLSMode       string
	// ExtraRootsFile holds PEM CA certificates trusted in addition to the
	// OS store in the system TLS mode.
	ExtraRootsFile string
	Version        string
	Logger         *slog.Logger
	OnListening    func(net.Addr)
	Runtime        core.Options
}

// Enroll enrolls the agent and waits for approval.
func Enroll(ctx context.Context, o EnrollOptions) error {
	if o.StateDir == "" {
		o.StateDir = state.DefaultDir
	}
	if o.Version == "" {
		o.Version = version.Version
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	mode, err := link.ParseTLSMode(o.TLSMode)
	if err != nil {
		return err
	}
	extra, err := loadRoots(o.ExtraRootsFile)
	if err != nil {
		return err
	}
	st, err := state.OpenAs(o.StateDir, paths.AgentService)
	if err != nil {
		return err
	}
	defer st.Close()
	_, err = core.Enroll(ctx, core.EnrollOptions{
		State:         st,
		Kind:          core.KindAgent,
		Version:       o.Version,
		Token:         o.Token,
		ServerURL:     o.ServerURL,
		ServerName:    o.ServerName,
		ConnectMode:   o.ConnectMode,
		ListenAddress: o.ListenAddress,
		TLSMode:       mode,
		ExtraRoots:    extra,
		Host:          HostFacts(ctx),
		Logger:        o.Logger,
		OnListening:   o.OnListening,
		Runtime:       o.Runtime,
	})
	return err
}

func loadRoots(path string) ([]*x509.Certificate, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	return pki.ParseCertificatesPEM(b)
}

// HostFacts describes the host for the enrollment request.
func HostFacts(ctx context.Context) agentapi.HostFacts {
	h := hostinfo.Collect(ctx, collect.NewEnv())
	if h == nil {
		name, _ := os.Hostname()
		return agentapi.HostFacts{Hostname: name, Os: agentapi.OsRelease{Family: runtime.GOOS}}
	}
	str := func(s string) *string {
		if s = strings.TrimSpace(s); s == "" {
			return nil
		}
		return &s
	}
	return agentapi.HostFacts{
		Hostname:  h.Hostname,
		MachineId: str(h.MachineID),
		Kernel:    str(h.Kernel),
		Arch:      h.Arch,
		Os: agentapi.OsRelease{
			Family:     h.OS.Family,
			Id:         str(h.OS.ID),
			IdLike:     str(h.OS.IDLike),
			Name:       str(h.OS.Name),
			Version:    str(h.OS.Version),
			VersionId:  str(h.OS.VersionID),
			Codename:   str(h.OS.Codename),
			PrettyName: str(h.OS.PrettyName),
		},
	}
}
