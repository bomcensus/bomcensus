// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package agentapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bomcensus/bomcensus/agentproto"
	"github.com/bomcensus/bomcensus/agentproto/dto"
	"github.com/bomcensus/bomcensus/internal/pki"
	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/server/dispatch"
	"github.com/bomcensus/bomcensus/internal/server/integritysvc"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// SettingCollectPolicy is the settings key of the collection policy sent
// to agents. Its value is a CollectPolicy document.
const SettingCollectPolicy = "collect_policy"

// CollectPolicy is the JSON document stored under SettingCollectPolicy.
// Absent fields take the defaults.
type CollectPolicy struct {
	// SectionIntervals are seconds per section; 0 disables a section.
	SectionIntervals struct {
		Host       *int `json:"host,omitempty"`
		Packages   *int `json:"packages,omitempty"`
		Artifacts  *int `json:"artifacts,omitempty"`
		Processes  *int `json:"processes,omitempty"`
		Containers *int `json:"containers,omitempty"`
	} `json:"section_intervals"`
	Policy *dto.Policy `json:"policy,omitempty"`
}

// Default section intervals in seconds.
const (
	DefaultHostInterval       = 24 * 3600
	DefaultPackagesInterval   = 24 * 3600
	DefaultArtifactsInterval  = 24 * 3600
	DefaultProcessesInterval  = 10 * 60
	DefaultContainersInterval = 3600
)

// maxDirectivesPerPoll bounds one poll response.
const maxDirectivesPerPoll = 50

func intervalOr(v *int, def int) int {
	if v == nil || *v < 0 {
		return def
	}
	return *v
}

func defaultPolicy() dto.Policy {
	p := report.DefaultPolicy()
	return dto.Policy{ExecVersion: p.ExecVersion, CollectCmdline: p.CollectCmdline, ScanContainers: p.ScanContainers}
}

// agentConfig builds the configuration part of a poll response for agent
// a. Walk paths come from the agent's detect directories only.
func (h *Handlers) agentConfig(ctx context.Context, a store.Agent, bundleSerial int64) (dto.AgentConfig, error) {
	var cp CollectPolicy
	raw, err := h.st.GetSetting(ctx, SettingCollectPolicy)
	switch {
	case err == nil:
		if err := json.Unmarshal(raw, &cp); err != nil {
			h.log.WarnContext(ctx, "invalid collect policy setting; using defaults", "error", err)
			cp = CollectPolicy{}
		}
	case !errors.Is(err, store.ErrNotFound):
		return dto.AgentConfig{}, fmt.Errorf("collect policy: %w", err)
	}
	us, err := h.st.GetUpdateSettings(ctx)
	if err != nil {
		return dto.AgentConfig{}, fmt.Errorf("update settings: %w", err)
	}
	interval := us.CheckIntervalMinutes
	if interval < 1 {
		interval = store.DefaultUpdateCheckIntervalMinutes
	}
	si := cp.SectionIntervals
	cfg := dto.AgentConfig{
		SectionIntervals: dto.SectionIntervals{
			Host:       intervalOr(si.Host, DefaultHostInterval),
			Packages:   intervalOr(si.Packages, DefaultPackagesInterval),
			Artifacts:  intervalOr(si.Artifacts, DefaultArtifactsInterval),
			Processes:  intervalOr(si.Processes, DefaultProcessesInterval),
			Containers: intervalOr(si.Containers, DefaultContainersInterval),
		},
		Policy:                     defaultPolicy(),
		UpdateCheckIntervalMinutes: interval,
		TrustBundleSerial:          bundleSerial,
	}
	if cp.Policy != nil {
		cfg.Policy = *cp.Policy
	}
	cfg.Policy.WalkPaths = nil
	if a.Kind == store.AgentKindAgent && len(a.DetectPaths) > 0 {
		paths := slices.Clone(a.DetectPaths)
		cfg.Policy.WalkPaths = &paths
	}
	if a.Kind == store.AgentKindAgent && a.HasFeature(store.FeatureIntegrity) {
		cfg.Integrity = h.integrityConfig(ctx, a)
	}
	return cfg, nil
}

// integrityConfig is the agent's integrity configuration. A policy that
// cannot be read turns the passes off rather than failing the poll.
func (h *Handlers) integrityConfig(ctx context.Context, a store.Agent) *dto.IntegrityConfig {
	p, err := integritysvc.Load(ctx, h.st)
	if err != nil {
		h.log.WarnContext(ctx, "integrity policy unreadable; passes are off", "error", err)
		p, a.Integrity = integritysvc.DefaultPolicy(), store.IntegrityOff
	}
	excl := slices.Clone(p.ExcludePaths)
	return &dto.IntegrityConfig{
		Enabled:        integritysvc.Enabled(a.Integrity, p.Agents),
		WindowStart:    p.WindowStart,
		WindowEnd:      p.WindowEnd,
		IntervalDays:   p.IntervalDays,
		MaxReadMbps:    p.MaxReadMBps,
		FullRehashDays: p.FullRehashDays,
		ExcludePaths:   &excl,
	}
}

func validPoll(b *dto.PollRequest) bool {
	return b.Os.Valid() && b.Arch.Valid() && b.ConnectMode.Valid() && b.TlsMode.Valid() &&
		b.Privilege.Level.Valid() && b.Update.State.Valid()
}

// Poll implements agentproto.API: it stores the reported status,
// acknowledges directives and waits up to the poll timeout for pending
// directives.
func (h *Handlers) Poll(ctx context.Context, body *dto.PollRequest) (*dto.PollResult, error) {
	a, err := h.caller(ctx, "Poll")
	if err != nil {
		return nil, err
	}
	if body == nil || !validPoll(body) {
		return nil, apiError(http.StatusBadRequest, agentproto.CodeInvalidRequest, "invalid poll request")
	}
	remote := agentproto.PeerFrom(ctx).RemoteAddr
	now := h.now().UTC()

	status := store.AgentPollStatus{
		Hostname:           a.Hostname,
		Version:            body.Version,
		OS:                 string(body.Os),
		Arch:               string(body.Arch),
		ConnectMode:        store.ConnectMode(body.ConnectMode),
		ListenAddress:      a.ListenAddress,
		TLSMode:            store.TLSVerifyMode(body.TlsMode),
		ObservedIssuer:     h.observedIssuer(body.ObservedServerCert),
		Privilege:          store.Privilege(body.Privilege.Level),
		ExecHelper:         body.Privilege.ExecHelper != nil && *body.Privilege.ExecHelper,
		Address:            a.Address,
		TrustBundleVersion: body.TrustBundleSerial,
		UpdateState:        store.UpdateState(body.Update.State),
		UpdateMessage:      updateMessage(body.Update.Message),
		Features:           knownFeatures(body.Features),
		SeenAt:             now,
		DetectorsDigest:    detectorsDigest(body.DetectorsDigest),
	}
	if remote.IsValid() {
		status.Address = remote.String()
	}
	if err := h.st.UpdateAgentPoll(ctx, a.ID, status); err != nil {
		return nil, fmt.Errorf("update agent status: %w", err)
	}
	if body.AckedDirectives != nil && len(*body.AckedDirectives) > 0 {
		if _, err := h.st.AckDirectives(ctx, a.ID, *body.AckedDirectives, now); err != nil {
			return nil, fmt.Errorf("ack directives: %w", err)
		}
	}

	bundle, err := h.enroll.TrustBundle(ctx)
	if err != nil {
		return nil, err
	}
	// The configuration follows the features of this poll.
	a.Features = status.Features
	cfg, err := h.agentConfig(ctx, a, bundle.Serial)
	if err != nil {
		return nil, err
	}
	table, err := h.detectorTable(ctx, &cfg, body.DetectorsDigest)
	if err != nil {
		return nil, err
	}
	extra, err := h.computedDirectives(ctx, a.ID, body, bundle.Serial, now)
	if err != nil {
		return nil, err
	}

	directives, err := h.waitDirectives(ctx, a.ID, len(extra) > 0)
	if err != nil {
		return nil, err
	}
	directives = append(directives, extra...)

	counter, err := h.st.AgentCounter(ctx, a.ID)
	if err != nil {
		return nil, fmt.Errorf("agent counter: %w", err)
	}
	return &dto.PollResult{
		Config:      cfg,
		Directives:  directives,
		LastCounter: int64(counter),
		ServerTime:  h.now().UTC().Truncate(time.Second),
		Detectors:   table,
	}, nil
}

// detectorTable announces the detector table in cfg and returns it when
// the agent reported a table digest (agents that take tables do) that
// differs.
func (h *Handlers) detectorTable(ctx context.Context, cfg *dto.AgentConfig, held *string) (*dto.DetectorTable, error) {
	if h.detectors == nil {
		return nil, nil
	}
	digest, raw, err := h.detectors.Current(ctx)
	if err != nil {
		return nil, fmt.Errorf("detector table: %w", err)
	}
	cfg.DetectorsDigest = &digest
	if held == nil || *held == digest {
		return nil, nil
	}
	return &dto.DetectorTable{Digest: digest, Table: raw}, nil
}

// detectorsDigest keeps a reported table digest when it has the form of
// one; anything else is stored as reported by an agent that has none.
func detectorsDigest(d *string) *string {
	if d == nil {
		return nil
	}
	if len(*d) != 64 || strings.Trim(*d, "0123456789abcdef") != "" {
		empty := ""
		return &empty
	}
	v := *d
	return &v
}

// knownFeatures keeps the features the server knows of.
func knownFeatures(in *[]string) []string {
	if in == nil {
		return nil
	}
	var out []string
	for _, f := range *in {
		if (f == store.FeatureGoSymbols || f == store.FeatureIntegrity) && !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	return out
}

// maxUpdateMessage bounds the stored update message (bytes).
const maxUpdateMessage = 2048

// updateMessage returns the agent's update detail as stored: valid UTF-8,
// at most maxUpdateMessage bytes.
func updateMessage(m *string) string {
	if m == nil {
		return ""
	}
	s := strings.ToValidUTF8(strings.TrimSpace(*m), "\uFFFD")
	if len(s) <= maxUpdateMessage {
		return s
	}
	cut := maxUpdateMessage
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// waitDirectives returns the agent's pending directives, waiting up to the
// poll timeout for one to arrive unless immediate is set. Delivered
// directives are marked; they are delivered again until acknowledged.
func (h *Handlers) waitDirectives(ctx context.Context, agentID string, immediate bool) ([]dto.Directive, error) {
	deadline := time.NewTimer(h.pollMax)
	defer deadline.Stop()
	recheck := time.NewTicker(h.recheck)
	defer recheck.Stop()
	for {
		// Register before reading so an enqueue in between is not missed.
		wctx, cancel := context.WithCancel(ctx)
		wake := h.dispatch.Wait(wctx, agentID)
		pending, err := h.st.ListPendingDirectives(ctx, agentID, h.now(), maxDirectivesPerPoll)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("list directives: %w", err)
		}
		if len(pending) > 0 {
			cancel()
			return h.deliver(ctx, agentID, pending)
		}
		if immediate {
			cancel()
			return []dto.Directive{}, nil
		}
		select {
		case <-wake:
		case <-recheck.C:
		case <-deadline.C:
			immediate = true // read once more, then answer
		case <-ctx.Done():
			cancel()
			return []dto.Directive{}, nil
		}
		cancel()
	}
}

func (h *Handlers) deliver(ctx context.Context, agentID string, pending []store.Directive) ([]dto.Directive, error) {
	out := make([]dto.Directive, 0, len(pending))
	ids := make([]string, 0, len(pending))
	for _, d := range pending {
		g, err := dispatch.Deliverable(d)
		if err != nil {
			h.log.ErrorContext(ctx, "undeliverable directive", "agent_id", agentID, "directive_id", d.ID, "error", err)
			continue
		}
		out = append(out, g)
		ids = append(ids, d.ID)
	}
	if err := h.st.MarkDirectivesDelivered(ctx, agentID, ids, h.now()); err != nil {
		return nil, fmt.Errorf("mark directives delivered: %w", err)
	}
	return out, nil
}

// computedDirectives are derived from the agent's state on every poll and
// not stored: renew_cert once the certificate is past two thirds of its
// life and sync_trust_bundle while the agent's bundle is behind. Their ids
// are stable for the same condition.
func (h *Handlers) computedDirectives(ctx context.Context, agentID string, body *dto.PollRequest, bundleSerial int64, now time.Time) ([]dto.Directive, error) {
	var out []dto.Directive
	certs, err := h.st.ListAgentCerts(ctx, agentID)
	if err != nil {
		return nil, fmt.Errorf("agent certificates: %w", err)
	}
	var latest *store.AgentCert
	for i := range certs {
		c := &certs[i]
		if c.RevokedAt == nil && (latest == nil || c.NotAfter.After(latest.NotAfter)) {
			latest = c
		}
	}
	if latest != nil {
		life := latest.NotAfter.Sub(latest.NotBefore)
		if !now.Before(latest.NotBefore.Add(life * 2 / 3)) {
			var d dto.Directive
			if err := d.FromRenewCertDirective(dto.RenewCertDirective{
				Id: "renew_cert-" + strconv.FormatInt(latest.NotAfter.Unix(), 10), NewKey: false,
			}); err != nil {
				return nil, err
			}
			out = append(out, d)
		}
	}
	if body.TrustBundleSerial < bundleSerial {
		var d dto.Directive
		if err := d.FromSyncTrustBundleDirective(dto.SyncTrustBundleDirective{
			Id: "sync_trust_bundle-" + strconv.FormatInt(bundleSerial, 10), Serial: bundleSerial,
		}); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// observedIssuer returns the issuer of the server certificate the agent
// saw when it was not issued by one of the server's own CAs, empty
// otherwise. Only the CA matters: the leaf changes whenever it is renewed
// or its names change. A certificate whose issuing CA the agent did not
// report is treated as foreign.
func (h *Handlers) observedIssuer(o *dto.ObservedCert) string {
	if o == nil {
		return ""
	}
	if o.IssuerSpkiSha256 != nil {
		ca := strings.ToLower(*o.IssuerSpkiSha256)
		for _, c := range h.ownCAs() {
			sum := pki.SPKIHash(c)
			if hex.EncodeToString(sum[:]) == ca {
				return ""
			}
		}
	}
	if o.Issuer == "" {
		return "unknown issuer"
	}
	return o.Issuer
}
