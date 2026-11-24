// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package core

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"runtime"
	"time"

	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/msgsig"
	"github.com/bomcensus/bomcensus/internal/pki"
	"github.com/bomcensus/bomcensus/internal/report"
)

// maxSeen bounds the remembered directive ids.
const maxSeen = 512

func (r *Runtime) pollLoop(ctx context.Context) {
	var backoff time.Duration
	for ctx.Err() == nil {
		start := r.opts.Now()
		if err := r.pollOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			if isRevoked(err) {
				r.revokedByServer(err)
				return
			}
			var ae *APIError
			if errors.As(err, &ae) && ae.Code == msgsig.CodeClientCertMismatch {
				// The agent state passed; the server wants the certificate.
				r.clearRevoked()
			}
			backoff = nextBackoff(backoff, r.opts.MaxBackoff)
			wait := backoff/2 + time.Duration(float64(backoff/2)*randFloat())
			r.log.Warn("poll failed", "error", err, "retry_in", wait.Round(time.Millisecond))
			sleep(ctx, wait)
			continue
		}
		backoff = 0
		r.clearRevoked()
		sleep(ctx, r.opts.MinPollInterval-r.opts.Now().Sub(start))
	}
}

func (r *Runtime) pollOnce(ctx context.Context) error {
	req, acks := r.pollRequest(ctx)
	pctx, cancel := context.WithTimeout(ctx, r.opts.PollTimeout)
	defer cancel()
	resp, err := r.client.PollWithResponse(pctx, req)
	if err != nil {
		return err
	}
	var res agentapi.PollResult
	if err := DecodeResponse(resp.HTTPResponse, resp.Body, 200, &res); err != nil {
		return err
	}
	r.acked(acks)
	if res.LastCounter > 0 {
		_ = r.counter.Observe(ctx, uint64(res.LastCounter))
	}
	r.applyConfig(ctx, res.Config)
	for _, f := range r.pollFuncs {
		f(ctx)
	}
	r.handleDirectives(ctx, res.Directives)
	return nil
}

// DefaultPrivilege describes the process itself; components that know
// better (the probe's report) override it in a StatusFunc.
func DefaultPrivilege() agentapi.Privilege {
	p := agentapi.Privilege{Level: agentapi.NonRoot, Uid: os.Getuid()}
	if p.Uid == 0 {
		p.Level = agentapi.Privileged
	}
	return p
}

func (r *Runtime) pollRequest(ctx context.Context) (agentapi.PollRequest, []string) {
	enr := r.Enrollment()
	tlsMode := agentapi.TlsMode(enr.TLSMode)
	if enr.ConnectMode == ModeListen || tlsMode == "" {
		tlsMode = agentapi.Pinned
	}
	req := agentapi.PollRequest{
		Version:        r.opts.Version,
		Os:             agentapi.TargetOs(runtime.GOOS),
		Arch:           agentapi.TargetArch(runtime.GOARCH),
		ConnectMode:    agentapi.ConnectMode(enr.ConnectMode),
		TlsMode:        tlsMode,
		Privilege:      DefaultPrivilege(),
		SectionDigests: map[string]string{},
		Update:         agentapi.UpdateStatus{State: agentapi.UpdateStateUpToDate},
	}
	if b := r.TrustBundle(); b != nil {
		req.TrustBundleSerial = int64(b.Version)
	}
	if c := r.Certificate(); c != nil {
		na := c.NotAfter
		req.CertNotAfter = &na
	}
	if fp, leaf, ok := r.ObservedServer(); ok {
		oc := &agentapi.ObservedCert{
			Sha256:  hex.EncodeToString(fp[:]),
			Subject: leaf.Subject.String(),
			Issuer:  leaf.Issuer.String(),
		}
		if ic := r.ObservedIssuer(); ic != nil {
			h := pki.SPKIHash(ic)
			hs := hex.EncodeToString(h[:])
			oc.IssuerSpkiSha256 = &hs
		}
		req.ObservedServerCert = oc
	}
	r.ackMu.Lock()
	acks := append([]string(nil), r.pendingAcks...)
	r.ackMu.Unlock()
	if len(acks) > 0 {
		req.AckedDirectives = &acks
	}
	for _, f := range r.statusFuncs {
		f(ctx, &req)
	}
	return req, acks
}

// acked removes acknowledgements the server has received.
func (r *Runtime) acked(sent []string) {
	if len(sent) == 0 {
		return
	}
	done := make(map[string]bool, len(sent))
	for _, id := range sent {
		done[id] = true
	}
	r.ackMu.Lock()
	defer r.ackMu.Unlock()
	kept := r.pendingAcks[:0]
	for _, id := range r.pendingAcks {
		if !done[id] {
			kept = append(kept, id)
		}
	}
	r.pendingAcks = kept
}

func (r *Runtime) ack(id string) {
	r.ackMu.Lock()
	defer r.ackMu.Unlock()
	for _, a := range r.pendingAcks {
		if a == id {
			return
		}
	}
	r.pendingAcks = append(r.pendingAcks, id)
}

// markSeen records a directive id and reports whether it was new.
func (r *Runtime) markSeen(id string) bool {
	r.ackMu.Lock()
	defer r.ackMu.Unlock()
	if _, ok := r.seen[id]; ok {
		return false
	}
	r.seen[id] = struct{}{}
	r.seenOrder = append(r.seenOrder, id)
	if len(r.seenOrder) > maxSeen {
		delete(r.seen, r.seenOrder[0])
		r.seenOrder = r.seenOrder[1:]
	}
	return true
}

type directiveHead struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

func (r *Runtime) handleDirectives(ctx context.Context, ds []agentapi.Directive) {
	for _, d := range ds {
		raw, err := d.MarshalJSON()
		var head directiveHead
		if err == nil {
			err = json.Unmarshal(raw, &head)
		}
		if err != nil || head.ID == "" {
			r.log.Warn("ignoring malformed directive")
			continue
		}
		if !r.markSeen(head.ID) {
			// Redelivered because the acknowledgement did not arrive.
			r.ack(head.ID)
			continue
		}
		h, ok := r.handlers[head.Type]
		if !ok {
			r.log.Info("ignoring unsupported directive", "id", head.ID, "type", head.Type)
		} else {
			r.log.Info("directive received", "id", head.ID, "type", head.Type)
			if err := h(ctx, d); err != nil {
				r.log.Warn("directive failed", "id", head.ID, "type", head.Type, "error", err)
			}
		}
		r.ack(head.ID)
	}
}

func (r *Runtime) applyConfig(ctx context.Context, cfg agentapi.AgentConfig) {
	r.mu.Lock()
	changed := r.config == nil || !reflect.DeepEqual(*r.config, cfg)
	if changed {
		c := cfg
		r.config = &c
	}
	r.mu.Unlock()
	if changed {
		if err := r.st.SaveServerConfig(cfg); err != nil {
			r.log.Warn("store server configuration", "error", err)
		}
		for _, f := range r.configFuncs {
			f(ctx, cfg)
		}
	}
	if b := r.TrustBundle(); b == nil || cfg.TrustBundleSerial > int64(b.Version) {
		if err := r.SyncTrustBundle(ctx); err != nil {
			r.log.Warn("trust bundle sync failed", "error", err)
		}
	}
}

// PolicyFromConfig converts the policy of a server configuration.
func PolicyFromConfig(p agentapi.Policy) report.Policy {
	out := report.Policy{
		ExecVersion:    p.ExecVersion,
		CollectCmdline: p.CollectCmdline,
		ScanContainers: p.ScanContainers,
	}
	if p.ExcludePaths != nil {
		out.ExcludePaths = append([]string(nil), *p.ExcludePaths...)
	}
	if p.WalkPaths != nil {
		out.WalkPaths = append([]string(nil), *p.WalkPaths...)
	}
	if p.MaxRuntimeSeconds != nil {
		out.MaxRuntimeSeconds = *p.MaxRuntimeSeconds
	}
	if p.MemoryLimitMb != nil {
		out.MemoryLimitMB = *p.MemoryLimitMb
	}
	return out
}
