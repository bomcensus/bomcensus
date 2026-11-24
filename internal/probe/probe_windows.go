// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package probe

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/bomcensus/bomcensus/internal/collect"
	"github.com/bomcensus/bomcensus/internal/collect/hostinfo"
	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/version"
)

// notCollectedReason is the reason of every section other than host.
const notCollectedReason = "not implemented on Windows"

// Run answers a request on Windows: the host section is collected, every
// other requested section is present with coverage none and
// notCollectedReason, so that the server records it as not collected and
// keeps what it already has. Options.Root and Options.Proc are ignored.
func Run(ctx context.Context, req report.Request, opts Options) (*report.Report, error) {
	start := time.Now()
	log := opts.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	want, err := wantedSections(req, log)
	if err != nil {
		return nil, err
	}
	if opts.ProcessLimits {
		applyProcessLimits(req.Policy, log)
	}
	limit := DefaultMaxRuntime
	if req.Policy.MaxRuntimeSeconds > 0 {
		limit = time.Duration(req.Policy.MaxRuntimeSeconds) * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()

	var priv report.Privilege
	if opts.Privilege != nil {
		priv = *opts.Privilege
	} else {
		priv = DetectPrivilege()
	}
	log.Info("collection started", "sections", strings.Join(want.list(), ","), "privilege", priv.Level)

	rep := &report.Report{
		SchemaVersion: report.SchemaVersion,
		ProbeVersion:  version.Version,
		CollectedAt:   start.UTC(),
		Privilege:     priv,
	}
	if want[report.SectionHost] {
		env := collect.NewEnv()
		env.Log = log
		rep.Host = hostinfo.Collect(runCtx, env)
	}
	none := func() report.SectionMeta {
		return report.SectionMeta{Coverage: report.CoverageNone, Reason: notCollectedReason, CollectedAt: time.Now().UTC()}
	}
	if want[report.SectionPackages] {
		rep.Packages = &report.PackagesSection{SectionMeta: none()}
	}
	if want[report.SectionArtifacts] {
		rep.Artifacts = &report.ArtifactsSection{SectionMeta: none()}
	}
	if want[report.SectionProcesses] {
		rep.Processes = &report.ProcessesSection{SectionMeta: none()}
	}
	if want[report.SectionContainers] {
		rep.Containers = &report.ContainersSection{SectionMeta: none()}
	}
	if req.GoSymbols != nil {
		rep.GoSymbols = answerGoSymbols(runCtx, req.GoSymbols, func(container string) (fileOpener, string) {
			if container != "" {
				return nil, "containers are not read on Windows"
			}
			return os.Open, ""
		})
	}
	applyKnownDigests(rep, req.KnownDigests)
	// Nothing is hashed yet; the cache comes back empty, as on Linux when
	// no file was read.
	if raw, err := collect.LoadHashCache(req.Cache).Marshal(); err == nil {
		rep.Cache = raw
	}
	log.Info("collection finished", "duration", time.Since(start).Round(time.Millisecond).String())
	return rep, nil
}
