// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package dispatch queues directives for agents and wakes their long polls.
//
// Directives are stored in the database (store.DirectiveQueue), so every
// server replica can deliver them. Wake-ups are in-process only; a poll
// handler also re-checks the store periodically to see directives enqueued
// by another replica.
package dispatch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/bomcensus/bomcensus/agentproto/dto"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// ErrNotAgentBacked is returned by RequestCollect for an asset that has no
// agent (scan targets and Kubernetes workloads are collected by scanners).
var ErrNotAgentBacked = errors.New("dispatch: asset is not collected by an agent")

// Store is what Service needs from the database.
type Store interface {
	store.DirectiveQueue
	GetAgent(ctx context.Context, id string) (store.Agent, error)
	GetAsset(ctx context.Context, id string) (store.AssetDetail, error)
}

// DefaultCollectTTL is how long a collect request waits for an offline
// agent.
const DefaultCollectTTL = 24 * time.Hour

// Directive is a directive to enqueue.
type Directive struct {
	// Body is the directive as delivered. Its id is assigned by Enqueue and
	// any id set here is replaced.
	Body dto.Directive
	// DedupeKey, when set, keeps at most one pending directive with this
	// key per agent.
	DedupeKey string
	// TTL bounds how long the directive stays pending; 0 means it never
	// expires.
	TTL time.Duration
}

// Service enqueues directives and wakes long polls.
type Service struct {
	store Store
	now   func() time.Time

	mu      sync.Mutex
	waiters map[string]map[chan struct{}]struct{}
}

// New returns a Service over st.
func New(st Store) *Service {
	return &Service{store: st, now: time.Now, waiters: make(map[string]map[chan struct{}]struct{})}
}

// RequestCollect asks the agent of an asset to collect all sections now.
// It returns ErrNotAgentBacked when the asset has no agent and
// store.ErrInvalidState when its agent is revoked. A pending collect request
// of the same agent is reused.
func (s *Service) RequestCollect(ctx context.Context, assetID string) error {
	asset, err := s.store.GetAsset(ctx, assetID)
	if err != nil {
		return fmt.Errorf("dispatch: asset %s: %w", assetID, err)
	}
	if asset.AgentID == "" {
		return ErrNotAgentBacked
	}
	agent, err := s.store.GetAgent(ctx, asset.AgentID)
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotAgentBacked
	}
	if err != nil {
		return fmt.Errorf("dispatch: agent of asset %s: %w", assetID, err)
	}
	if agent.Kind != store.AgentKindAgent {
		return ErrNotAgentBacked
	}
	if agent.State == store.AgentRevoked {
		return fmt.Errorf("dispatch: agent %s is revoked: %w", agent.ID, store.ErrInvalidState)
	}
	var body dto.Directive
	if err := body.FromCollectDirective(dto.CollectDirective{
		Type:     dto.Collect,
		Sections: []dto.SectionName{},
	}); err != nil {
		return fmt.Errorf("dispatch: build collect directive: %w", err)
	}
	_, err = s.Enqueue(ctx, agent.ID, Directive{Body: body, DedupeKey: "collect", TTL: DefaultCollectTTL})
	return err
}

// Enqueue stores d for the agent, wakes its long polls and returns the
// directive id (the id of the existing directive when d was deduplicated).
func (s *Service) Enqueue(ctx context.Context, agentID string, d Directive) (string, error) {
	typ, err := d.Body.Discriminator()
	if err != nil || typ == "" {
		return "", fmt.Errorf("dispatch: directive has no type: %w", store.ErrInvalid)
	}
	payload, err := Payload(d.Body)
	if err != nil {
		return "", err
	}
	now := s.now().UTC()
	rec := store.Directive{AgentID: agentID, Type: typ, Payload: payload, DedupeKey: d.DedupeKey, CreatedAt: now}
	if d.TTL > 0 {
		exp := now.Add(d.TTL)
		rec.ExpiresAt = &exp
	}
	out, _, err := s.store.EnqueueDirective(ctx, rec)
	if err != nil {
		return "", fmt.Errorf("dispatch: enqueue %s for %s: %w", typ, agentID, err)
	}
	s.Notify(agentID)
	return out.ID, nil
}

// Payload returns the stored form of a directive: its JSON object without
// the id.
func Payload(d dto.Directive) (json.RawMessage, error) {
	raw, err := d.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("dispatch: encode directive: %w", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, fmt.Errorf("dispatch: directive is not a JSON object: %w", store.ErrInvalid)
	}
	delete(m, "id")
	out, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("dispatch: encode directive: %w", err)
	}
	return out, nil
}

// Deliverable turns a stored directive into its wire form with its id.
func Deliverable(d store.Directive) (dto.Directive, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(d.Payload, &m); err != nil || m == nil {
		return dto.Directive{}, fmt.Errorf("dispatch: directive %s: payload is not a JSON object", d.ID)
	}
	id, _ := json.Marshal(d.ID)
	typ, _ := json.Marshal(d.Type)
	m["id"], m["type"] = id, typ
	raw, err := json.Marshal(m)
	if err != nil {
		return dto.Directive{}, fmt.Errorf("dispatch: directive %s: %w", d.ID, err)
	}
	var out dto.Directive
	if err := out.UnmarshalJSON(raw); err != nil {
		return dto.Directive{}, fmt.Errorf("dispatch: directive %s: %w", d.ID, err)
	}
	return out, nil
}

// Notify wakes every long poll of the agent waiting in this process.
func (s *Service) Notify(agentID string) {
	s.mu.Lock()
	set := s.waiters[agentID]
	delete(s.waiters, agentID)
	s.mu.Unlock()
	for ch := range set {
		close(ch)
	}
}

// Wait returns a channel that is closed by the next Notify for the agent.
// The registration is dropped when ctx is done; the channel is then never
// closed, so callers select on ctx.Done() as well.
func (s *Service) Wait(ctx context.Context, agentID string) <-chan struct{} {
	ch := make(chan struct{})
	s.mu.Lock()
	set := s.waiters[agentID]
	if set == nil {
		set = make(map[chan struct{}]struct{})
		s.waiters[agentID] = set
	}
	set[ch] = struct{}{}
	s.mu.Unlock()
	context.AfterFunc(ctx, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if set := s.waiters[agentID]; set != nil {
			delete(set, ch)
			if len(set) == 0 {
				delete(s.waiters, agentID)
			}
		}
	})
	return ch
}

// Cleanup removes expired directives and directives acknowledged more than
// keepAcked ago. It is meant to run periodically.
func (s *Service) Cleanup(ctx context.Context, keepAcked time.Duration) (int64, error) {
	now := s.now().UTC()
	n, err := s.store.DeleteExpiredDirectives(ctx, now, now.Add(-keepAcked))
	if err != nil {
		return 0, fmt.Errorf("dispatch: cleanup: %w", err)
	}
	return n, nil
}
