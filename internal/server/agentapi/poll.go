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
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	gen "github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/msgsig"
	"github.com/bomcensus/bomcensus/internal/pki"
	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/server/dispatch"
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
	Policy *gen.Policy `json:"policy,omitempty"`
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

func defaultPolicy() gen.Policy {
	p := report.DefaultPolicy()
	return gen.Policy{ExecVersion: p.ExecVersion, CollectCmdline: p.CollectCmdline, ScanContainers: p.ScanContainers}
}

// agentConfig builds the configuration part of a poll response.
func (h *Handlers) agentConfig(ctx context.Context, bundleSerial int64) (gen.AgentConfig, error) {
	var cp CollectPolicy
	raw, err := h.st.GetSetting(ctx, SettingCollectPolicy)
	switch {
	case err == nil:
		if err := json.Unmarshal(raw, &cp); err != nil {
			h.log.WarnContext(ctx, "invalid collect policy setting; using defaults", "error", err)
			cp = CollectPolicy{}
		}
	case !errors.Is(err, store.ErrNotFound):
		return gen.AgentConfig{}, fmt.Errorf("collect policy: %w", err)
	}
	us, err := h.st.GetUpdateSettings(ctx)
	if err != nil {
		return gen.AgentConfig{}, fmt.Errorf("update settings: %w", err)
	}
	interval := us.CheckIntervalMinutes
	if interval < 1 {
		interval = store.DefaultUpdateCheckIntervalMinutes
	}
	si := cp.SectionIntervals
	cfg := gen.AgentConfig{
		SectionIntervals: gen.SectionIntervals{
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
	return cfg, nil
}

func validPoll(b *gen.PollRequest) bool {
	return b.Os.Valid() && b.Arch.Valid() && b.ConnectMode.Valid() && b.TlsMode.Valid() &&
		b.Privilege.Level.Valid() && b.Update.State.Valid()
}

// Poll implements gen.StrictServerInterface: it stores the reported status,
// acknowledges directives and waits up to the poll timeout for pending
// directives.
func (h *Handlers) Poll(ctx context.Context, req gen.PollRequestObject) (gen.PollResponseObject, error) {
	if req.Body == nil || !validPoll(req.Body) {
		return gen.Poll400JSONResponse{BadRequestJSONResponse: gen.BadRequestJSONResponse(apiError(msgsig.CodeInvalidRequest, "invalid poll request"))}, nil
	}
	body := req.Body
	a := agentFrom(ctx)
	info := requestInfoFrom(ctx)
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
		SeenAt:             now,
	}
	if info.remote.IsValid() {
		status.Address = info.remote.String()
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
	cfg, err := h.agentConfig(ctx, bundle.Serial)
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
	return gen.Poll200JSONResponse(gen.PollResult{
		Config:      cfg,
		Directives:  directives,
		LastCounter: int64(counter),
		ServerTime:  h.now().UTC().Truncate(time.Second),
	}), nil
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
func (h *Handlers) waitDirectives(ctx context.Context, agentID string, immediate bool) ([]gen.Directive, error) {
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
			return []gen.Directive{}, nil
		}
		select {
		case <-wake:
		case <-recheck.C:
		case <-deadline.C:
			immediate = true // read once more, then answer
		case <-ctx.Done():
			cancel()
			return []gen.Directive{}, nil
		}
		cancel()
	}
}

func (h *Handlers) deliver(ctx context.Context, agentID string, pending []store.Directive) ([]gen.Directive, error) {
	out := make([]gen.Directive, 0, len(pending))
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
func (h *Handlers) computedDirectives(ctx context.Context, agentID string, body *gen.PollRequest, bundleSerial int64, now time.Time) ([]gen.Directive, error) {
	var out []gen.Directive
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
			var d gen.Directive
			if err := d.FromRenewCertDirective(gen.RenewCertDirective{
				Id: "renew_cert-" + strconv.FormatInt(latest.NotAfter.Unix(), 10), NewKey: false,
			}); err != nil {
				return nil, err
			}
			out = append(out, d)
		}
	}
	if body.TrustBundleSerial < bundleSerial {
		var d gen.Directive
		if err := d.FromSyncTrustBundleDirective(gen.SyncTrustBundleDirective{
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
func (h *Handlers) observedIssuer(o *gen.ObservedCert) string {
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
