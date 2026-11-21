// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package agentapi

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	gen "github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/link"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// ReverseOptions configures NewReverseManager.
type ReverseOptions struct {
	Store store.ListenTargets
	// Handler serves the reverse connections; normally the NewHandler
	// result.
	Handler http.Handler
	// Verifier verifies the agents' listener certificates (NewAgentVerifier).
	Verifier *link.AgentVerifier
	// ClientCertificate is the Agent TLS client certificate the server
	// presents (PKI.AgentTLSClientCertificate).
	ClientCertificate func() (*tls.Certificate, error)
	// Owner identifies this process in the lease table; random when empty.
	Owner string
	// Interval is the lease acquisition period (default 10 s), LeaseTTL the
	// lease lifetime (default 3 × Interval).
	Interval time.Duration
	LeaseTTL time.Duration
	// MinBackoff and MaxBackoff bound the redial delay (defaults 1 s, 5 min).
	MinBackoff time.Duration
	MaxBackoff time.Duration
	// ReconnectDelay is the pause between delivering an enrollment
	// certificate on a temporary connection and closing it, so the agent
	// is redialed with its new certificate (default 300 ms).
	ReconnectDelay time.Duration
	// Dial configures link.DialReverse; ClientCertificate and VerifyAgent
	// are set by the manager.
	Dial   link.ReverseDialConfig
	Logger *slog.Logger
}

// ReverseManager dials the listen-mode agents whose leases this process
// holds and serves the agent API on those connections.
type ReverseManager struct {
	o   ReverseOptions
	log *slog.Logger
}

// NewReverseManager validates o.
func NewReverseManager(o ReverseOptions) (*ReverseManager, error) {
	if o.Store == nil || o.Handler == nil || o.Verifier == nil || o.ClientCertificate == nil {
		return nil, errors.New("agentapi: reverse manager needs Store, Handler, Verifier and ClientCertificate")
	}
	if o.Owner == "" {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, fmt.Errorf("agentapi: owner id: %w", err)
		}
		o.Owner = "server-" + hex.EncodeToString(b[:])
	}
	if o.Interval <= 0 {
		o.Interval = 10 * time.Second
	}
	if o.LeaseTTL <= o.Interval {
		o.LeaseTTL = 3 * o.Interval
	}
	if o.MinBackoff <= 0 {
		o.MinBackoff = time.Second
	}
	if o.MaxBackoff < o.MinBackoff {
		o.MaxBackoff = 5 * time.Minute
	}
	if o.ReconnectDelay <= 0 {
		o.ReconnectDelay = 300 * time.Millisecond
	}
	log := o.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &ReverseManager{o: o, log: log}, nil
}

// Owner returns the lease owner id of this manager.
func (m *ReverseManager) Owner() string { return m.o.Owner }

type dialer struct {
	target *reverseTarget
	cancel context.CancelFunc
	done   chan struct{}
}

// Run acquires and renews leases every Interval and keeps one dial loop per
// held target until ctx is done. It then stops the loops and releases the
// leases.
func (m *ReverseManager) Run(ctx context.Context) error {
	running := make(map[string]*dialer)
	stop := func(id string) {
		d := running[id]
		d.cancel()
		<-d.done
		delete(running, id)
	}
	lastOK := time.Now()
	tick := time.NewTicker(m.o.Interval)
	defer tick.Stop()
	for {
		held, err := m.o.Store.AcquireListenLeases(ctx, m.o.Owner, m.o.LeaseTTL, time.Now(), 0)
		switch {
		case err != nil && ctx.Err() == nil:
			m.log.ErrorContext(ctx, "acquire listen leases", "owner", m.o.Owner, "error", err)
			if time.Since(lastOK) >= m.o.LeaseTTL {
				// The leases may have been taken over by now.
				for id := range running {
					stop(id)
				}
			}
		case err == nil:
			lastOK = time.Now()
			keep := make(map[string]bool, len(held))
			for _, t := range held {
				keep[t.ID] = true
				if d, ok := running[t.ID]; ok {
					if d.target.address() != t.Address {
						stop(t.ID)
					} else {
						d.target.refresh(t)
						continue
					}
				}
				dctx, cancel := context.WithCancel(ctx)
				d := &dialer{target: m.newTarget(t), cancel: cancel, done: make(chan struct{})}
				running[t.ID] = d
				go func() {
					defer close(d.done)
					m.dialLoop(dctx, d.target)
				}()
			}
			for id := range running {
				if !keep[id] {
					m.log.InfoContext(ctx, "listen target lease lost", "listen_target", id, "owner", m.o.Owner)
					stop(id)
				}
			}
		}
		select {
		case <-ctx.Done():
			for id := range running {
				stop(id)
				rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				if err := m.o.Store.ReleaseListenLease(rctx, id, m.o.Owner); err != nil {
					m.log.Warn("release listen lease", "listen_target", id, "error", err)
				}
				cancel()
			}
			return ctx.Err()
		case <-tick.C:
		}
	}
}

// dialLoop connects to one target until ctx is done or the lease is lost.
func (m *ReverseManager) dialLoop(ctx context.Context, t *reverseTarget) {
	backoff := m.o.MinBackoff
	for ctx.Err() == nil {
		connCtx, cancel := context.WithCancel(ctx)
		t.startConn(cancel)
		cfg := m.o.Dial
		cfg.ClientCertificate = m.o.ClientCertificate
		cfg.VerifyAgent = func(chain []*x509.Certificate) (link.ReversePeer, error) {
			p, err := t.verify(ctx, chain)
			if err == nil {
				t.markConnected()
				m.record(ctx, t, store.ListenConnected, "")
			}
			return p, err
		}
		if cfg.Logger == nil {
			cfg.Logger = m.log
		}
		addr := t.address()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			m.o.Handler.ServeHTTP(w, r.WithContext(withReverseTarget(r.Context(), t)))
		})
		err := link.DialReverse(connCtx, addr, cfg, handler)
		connected, rotated := t.endConn()
		cancel()
		if ctx.Err() != nil {
			m.record(context.WithoutCancel(ctx), t, store.ListenDisconnected, "")
			return
		}
		state, lastErr := store.ListenDisconnected, ""
		if err != nil && !rotated {
			state, lastErr = store.ListenFailed, err.Error()
			m.log.InfoContext(ctx, "reverse connection failed", "listen_target", t.id, "address", addr, "error", err)
		}
		if !m.record(ctx, t, state, lastErr) {
			return
		}
		if connected {
			backoff = m.o.MinBackoff
		}
		delay := backoff
		if rotated {
			delay = 0
		} else if !connected {
			backoff = min(2*backoff, m.o.MaxBackoff)
		}
		if delay > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}
	}
}

// record stores the connection state. It returns false when the lease is
// no longer held.
func (m *ReverseManager) record(ctx context.Context, t *reverseTarget, state store.ListenTargetState, lastErr string) bool {
	err := m.o.Store.RecordListenState(ctx, t.id, m.o.Owner, state, lastErr, time.Now())
	if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) {
		m.log.InfoContext(ctx, "listen target no longer held", "listen_target", t.id, "error", err)
		return false
	}
	if err != nil && ctx.Err() == nil {
		m.log.WarnContext(ctx, "record listen state", "listen_target", t.id, "error", err)
	}
	return true
}

func (m *ReverseManager) newTarget(t store.ListenTarget) *reverseTarget {
	return &reverseTarget{id: t.ID, m: m, t: t}
}

// reverseTarget is the state of one held listen target shared by its dial
// loop and the requests served on its connections.
type reverseTarget struct {
	id string
	m  *ReverseManager

	mu        sync.Mutex
	t         store.ListenTarget
	cancel    context.CancelFunc
	connected bool
	rotated   bool
}

func (t *reverseTarget) address() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.t.Address
}

func (t *reverseTarget) snapshot() store.ListenTarget {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.t
}

func (t *reverseTarget) refresh(n store.ListenTarget) {
	t.mu.Lock()
	t.t = n
	t.mu.Unlock()
}

func (t *reverseTarget) startConn(cancel context.CancelFunc) {
	t.mu.Lock()
	t.cancel, t.connected, t.rotated = cancel, false, false
	t.mu.Unlock()
}

func (t *reverseTarget) markConnected() {
	t.mu.Lock()
	t.connected = true
	t.mu.Unlock()
}

func (t *reverseTarget) endConn() (connected, rotated bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cancel = nil
	return t.connected, t.rotated
}

// verify classifies the agent certificate and enforces the binding of the
// target to one agent id.
func (t *reverseTarget) verify(ctx context.Context, chain []*x509.Certificate) (link.ReversePeer, error) {
	p, err := t.m.o.Verifier.VerifyReverse(chain)
	if err != nil {
		return p, err
	}
	if p.Unenrolled {
		return p, nil
	}
	cur := t.snapshot()
	if cur.AgentID != "" {
		if cur.AgentID != p.AgentID {
			return link.ReversePeer{}, fmt.Errorf("certificate of agent %s, target is bound to agent %s", p.AgentID, cur.AgentID)
		}
		return p, nil
	}
	if err := t.bind(ctx, p.AgentID); err != nil {
		return link.ReversePeer{}, err
	}
	return p, nil
}

// bind records agentID as the agent of the target.
func (t *reverseTarget) bind(ctx context.Context, agentID string) error {
	if err := t.m.o.Store.BindListenTargetAgent(ctx, t.id, agentID); err != nil {
		return fmt.Errorf("bind listen target %s to agent %s: %w", t.id, agentID, err)
	}
	t.mu.Lock()
	t.t.AgentID = agentID
	t.mu.Unlock()
	return nil
}

// checkStart applies the target's expectations to an enroll/start body
// arriving on its connection.
func (t *reverseTarget) checkStart(body []byte) error {
	cur := t.snapshot()
	if cur.AgentID != "" {
		return fmt.Errorf("listen target is already bound to agent %s", cur.AgentID)
	}
	if cur.RegisterKeyID == "" {
		return nil
	}
	var r struct {
		KeyID string `json:"key_id"`
	}
	if err := json.Unmarshal(body, &r); err == nil && r.KeyID != cur.RegisterKeyID {
		return fmt.Errorf("register key %q, listen target expects %q", r.KeyID, cur.RegisterKeyID)
	}
	return nil
}

// maybeReconnect closes the temporary connection after an approved
// enroll/finish response was written, so the agent is redialed with the
// certificate it just received.
func (t *reverseTarget) maybeReconnect(w http.ResponseWriter, resp []byte) {
	var res gen.EnrollResult
	if json.Unmarshal(resp, &res) != nil || res.Status != gen.EnrollStatusApproved {
		return
	}
	_ = http.NewResponseController(w).Flush()
	t.reconnectSoon()
}

// reconnectSoon ends the current connection after ReconnectDelay; the dial
// loop redials at once.
func (t *reverseTarget) reconnectSoon() {
	t.mu.Lock()
	cancel := t.cancel
	t.rotated = true
	t.mu.Unlock()
	if cancel != nil {
		time.AfterFunc(t.m.o.ReconnectDelay, cancel)
	}
}
