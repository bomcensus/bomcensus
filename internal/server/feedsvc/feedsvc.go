// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package feedsvc connects the server to feed servers with feed-protocol
// sessions. It owns the instance key (created on first use, sealed with the
// master key), keeps the trusted server keys in the store (trust on first
// use) and keeps one session to the active feed server alive per replica.
//
// A server that presents another key than the trusted one is put in the
// key_changed state and not used until an administrator accepts the
// presented key.
package feedsvc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	feedprotocol "github.com/bomcensus/feed-protocol"
	"github.com/bomcensus/feed-protocol/client"
	"github.com/bomcensus/feed-protocol/handshake"
	"github.com/bomcensus/feed-protocol/instancekey"

	"github.com/bomcensus/bomcensus/internal/server/secret"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// ClientName is sent in the handshake.
const ClientName = "bomcensus"

// StatusPath is the feed server's data status endpoint.
const StatusPath = "/v1/status"

// Defaults of Config.
const (
	DefaultTick           = time.Minute
	DefaultRequestTimeout = 30 * time.Second
)

// ErrInvalid wraps rejected input, such as a malformed URL.
var ErrInvalid = errors.New("feedsvc: invalid input")

// ErrNoServer means there is no active server that may be used: none is
// active, it is disabled, or its key changed.
var ErrNoServer = errors.New("feedsvc: no usable active feed server")

// Config holds the dependencies of Service.
type Config struct {
	Store store.FeedServers
	Box   *secret.Box
	// Version is the software version sent in the handshake.
	Version string
	// Base sends the HTTP requests; a transport with timeouts by default.
	Base   http.RoundTripper
	Logger *slog.Logger
	Now    func() time.Time
	// Tick is how often Run re-reads the active server (DefaultTick).
	Tick time.Duration
	// RequestTimeout bounds each contact (DefaultRequestTimeout).
	RequestTimeout time.Duration
}

// Service is the feed connection of one replica. It is safe for concurrent
// use.
type Service struct {
	st      store.FeedServers
	box     *secret.Box
	version string
	base    http.RoundTripper
	log     *slog.Logger
	now     func() time.Time
	tick    time.Duration
	timeout time.Duration

	keyMu sync.Mutex
	key   *instancekey.PrivateKey

	mu     sync.Mutex
	active *conn
	wake   chan struct{}
}

// conn is a transport to one server, valid while the server's identity,
// trusted key and telemetry setting stay the same.
type conn struct {
	id, url, serverKey string
	telemetry          bool
	tr                 *client.Transport
	lastBeat           time.Time
}

// New returns a Service. Store and Box are required.
func New(cfg Config) (*Service, error) {
	if cfg.Store == nil || cfg.Box == nil {
		return nil, errors.New("feedsvc: store and box are required")
	}
	if cfg.Base == nil {
		cfg.Base = defaultTransport()
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Tick <= 0 {
		cfg.Tick = DefaultTick
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = DefaultRequestTimeout
	}
	return &Service{
		st: cfg.Store, box: cfg.Box, version: cfg.Version, base: cfg.Base, log: cfg.Logger,
		now: cfg.Now, tick: cfg.Tick, timeout: cfg.RequestTimeout, wake: make(chan struct{}, 1),
	}, nil
}

func defaultTransport() http.RoundTripper {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.ResponseHeaderTimeout = 30 * time.Second
	t.MaxIdleConnsPerHost = 4
	return t
}

// ── instance key ────────────────────────────────────────────────────────

const instanceAAD = "feed:instance"

// Instance returns the instance key record, creating the key on first use.
func (s *Service) Instance(ctx context.Context) (store.FeedInstance, error) {
	in, _, err := s.instance(ctx)
	return in, err
}

func (s *Service) instance(ctx context.Context) (store.FeedInstance, *instancekey.PrivateKey, error) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	in, err := s.st.GetFeedInstance(ctx)
	if errors.Is(err, store.ErrNotFound) {
		in, err = s.createInstance(ctx)
	}
	if err != nil {
		return store.FeedInstance{}, nil, err
	}
	if s.key != nil && s.key.Public().String() == in.PublicKey {
		return in, s.key, nil
	}
	pemKey, err := s.box.Open(in.EncryptedKey, []byte(instanceAAD))
	if err != nil {
		return store.FeedInstance{}, nil, fmt.Errorf("feedsvc: open instance key: %w", err)
	}
	defer clear(pemKey)
	key, err := instancekey.ParsePEM(pemKey)
	if err != nil {
		return store.FeedInstance{}, nil, fmt.Errorf("feedsvc: instance key: %w", err)
	}
	if key.Public().String() != in.PublicKey {
		return store.FeedInstance{}, nil, errors.New("feedsvc: instance key does not match its public key")
	}
	s.key = key
	return in, key, nil
}

func (s *Service) createInstance(ctx context.Context) (store.FeedInstance, error) {
	key, err := instancekey.Generate(nil)
	if err != nil {
		return store.FeedInstance{}, err
	}
	pemKey := key.MarshalPEM()
	sealed, err := s.box.Seal(pemKey, []byte(instanceAAD))
	clear(pemKey)
	if err != nil {
		return store.FeedInstance{}, fmt.Errorf("feedsvc: seal instance key: %w", err)
	}
	// Another replica may create one at the same time; the stored one wins.
	in, err := s.st.CreateFeedInstance(ctx, store.FeedInstance{PublicKey: key.Public().String(), EncryptedKey: sealed, CreatedAt: s.now()})
	if err != nil {
		return store.FeedInstance{}, err
	}
	if in.PublicKey == key.Public().String() {
		s.log.Info("feed instance key created", "instance", in.PublicKey)
	}
	return in, nil
}

// ── trust store ─────────────────────────────────────────────────────────

// trust is the client.TrustStore of one server row.
type trust struct {
	st store.FeedServers
	id string
}

func (t trust) ServerKey(ctx context.Context, _ string) (instancekey.PublicKey, bool, error) {
	srv, err := t.st.GetFeedServer(ctx, t.id)
	if err != nil {
		return instancekey.PublicKey{}, false, err
	}
	if srv.ServerKey == "" {
		return instancekey.PublicKey{}, false, nil
	}
	k, err := instancekey.ParsePublicKey(srv.ServerKey)
	if err != nil {
		return instancekey.PublicKey{}, false, fmt.Errorf("feedsvc: stored server key: %w", err)
	}
	return k, true, nil
}

func (t trust) TrustServerKey(ctx context.Context, _ string, key instancekey.PublicKey) error {
	stored, err := t.st.TrustFeedServerKey(ctx, t.id, key.String())
	if err != nil {
		return err
	}
	if stored != key.String() {
		// Another replica trusted a different key first.
		trusted, err := instancekey.ParsePublicKey(stored)
		if err != nil {
			return fmt.Errorf("feedsvc: stored server key: %w", err)
		}
		return &client.KeyChangedError{Trusted: trusted, Presented: key}
	}
	return nil
}

// ── contacts ────────────────────────────────────────────────────────────

func (s *Service) transport(ctx context.Context, srv store.FeedServer) (*client.Transport, error) {
	_, key, err := s.instance(ctx)
	if err != nil {
		return nil, err
	}
	return &client.Transport{
		BaseURL: srv.URL,
		Key:     key,
		Trust:   trust{st: s.st, id: srv.ID},
		Hello:   handshake.Hello{Client: ClientName, Version: s.version, Telemetry: srv.Telemetry},
		Base:    s.base,
		Now:     s.now,
	}, nil
}

// record stores the outcome of a contact with srv.
func (s *Service) record(ctx context.Context, srv store.FeedServer, tr *client.Transport, contactErr error) {
	ctx = context.WithoutCancel(ctx)
	var err error
	var kc *client.KeyChangedError
	switch {
	case errors.As(contactErr, &kc):
		s.log.Warn("feed server presented another key; it is not used until the key is trusted",
			"server", srv.URL, "trusted", kc.Trusted.String(), "presented", kc.Presented.String())
		err = s.st.RecordFeedServerKeyChange(ctx, srv.ID, kc.Presented.String())
	case contactErr != nil:
		err = s.st.RecordFeedServerError(ctx, srv.ID, errorText(contactErr))
	case tr == nil:
		return
	default:
		info, _ := tr.Session()
		err = s.st.RecordFeedServerOK(ctx, srv.ID, store.FeedSession{Grade: info.Grade, ExpiresAt: info.Expires})
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.Warn("record feed server state", "server", srv.URL, "error", err)
	}
}

// errorText is the message shown for a failed contact.
func errorText(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	msg := err.Error()
	if len(msg) > 500 {
		msg = msg[:500]
	}
	return msg
}

// Test contacts the server with a session of its own: handshake (storing
// the server key on first contact), data status, end of session. The
// outcome is stored and the server returned as stored afterwards.
func (s *Service) Test(ctx context.Context, id string) (store.FeedServer, error) {
	srv, err := s.st.GetFeedServer(ctx, id)
	if err != nil {
		return store.FeedServer{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	tr, err := s.transport(ctx, srv)
	if err != nil {
		return store.FeedServer{}, err
	}
	err = tr.Start(ctx)
	if err == nil {
		var data store.FeedData
		if data, err = s.fetchStatus(ctx, tr); err == nil {
			if rerr := s.st.RecordFeedData(context.WithoutCancel(ctx), srv.ID, data); rerr != nil {
				s.log.Warn("record feed data", "server", srv.URL, "error", rerr)
			}
		}
	}
	s.record(ctx, srv, tr, err)
	if err == nil {
		_ = tr.Close(ctx)
	}
	s.log.Info("feed server tested", "server", srv.URL, "ok", err == nil, "error", errText(err))
	return s.st.GetFeedServer(context.WithoutCancel(ctx), id)
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return errorText(err)
}

type dataInfo struct {
	Revision int64  `json:"revision"`
	Rules    string `json:"rules"`
	Sources  []struct {
		Name      string     `json:"name"`
		UpdatedAt *time.Time `json:"updated_at"`
		ChangedAt *time.Time `json:"changed_at"`
		Healthy   *bool      `json:"healthy"`
	} `json:"sources"`
}

// fetchStatus reads /v1/status in the session of tr.
func (s *Service) fetchStatus(ctx context.Context, tr *client.Transport) (store.FeedData, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(tr.BaseURL, "/")+StatusPath, nil)
	if err != nil {
		return store.FeedData{}, err
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return store.FeedData{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return store.FeedData{}, err
	}
	if resp.StatusCode != http.StatusOK {
		var e feedprotocol.Error
		if json.Unmarshal(body, &e) != nil || e.Code == "" {
			e.Code, e.Message = "http_error", strings.TrimSpace(string(body))
		}
		return store.FeedData{}, &client.Error{Status: resp.StatusCode, Code: e.Code, Message: e.Message}
	}
	var di dataInfo
	if err := json.Unmarshal(body, &di); err != nil {
		return store.FeedData{}, fmt.Errorf("feedsvc: status: %w", err)
	}
	out := store.FeedData{Revision: di.Revision, RulesDigest: di.Rules, Sources: make([]store.FeedSource, 0, len(di.Sources))}
	for _, src := range di.Sources {
		out.Sources = append(out.Sources, store.FeedSource{Name: src.Name, UpdatedAt: src.UpdatedAt, ChangedAt: src.ChangedAt, Healthy: src.Healthy})
	}
	return out, nil
}

// TrustKey accepts the key the server presented in place of the trusted
// one. key must equal the presented key, so that an administrator confirms
// the key they compared.
func (s *Service) TrustKey(ctx context.Context, id, key string) (store.FeedServer, error) {
	k, err := instancekey.ParsePublicKey(key)
	if err != nil {
		return store.FeedServer{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	srv, err := s.st.AcceptFeedServerKey(ctx, id, k.String())
	if err != nil {
		return store.FeedServer{}, err
	}
	s.Kick()
	return srv, nil
}

// Kick makes Run re-read the active server now.
func (s *Service) Kick() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// ── session of the active server ────────────────────────────────────────

// Session returns the active server and a RoundTripper that sends requests
// to it in this replica's session (shared with Run). Errors of requests
// sent through it should be passed to Report.
func (s *Service) Session(ctx context.Context) (store.FeedServer, http.RoundTripper, error) {
	srv, err := s.st.GetActiveFeedServer(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return store.FeedServer{}, nil, ErrNoServer
	}
	if err != nil {
		return store.FeedServer{}, nil, err
	}
	if !srv.Enabled || srv.Status == store.FeedServerKeyChanged {
		return store.FeedServer{}, nil, ErrNoServer
	}
	c, err := s.conn(ctx, srv)
	if err != nil {
		return store.FeedServer{}, nil, err
	}
	return srv, c.tr, nil
}

// Report stores the outcome of a request sent through Session's
// RoundTripper: a changed server key, a failure, or (nil) success.
func (s *Service) Report(ctx context.Context, srv store.FeedServer, err error) {
	s.mu.Lock()
	c := s.active
	s.mu.Unlock()
	if c == nil || c.id != srv.ID {
		if err != nil {
			s.record(ctx, srv, nil, err)
		}
		return
	}
	s.record(ctx, srv, c.tr, err)
}

// RefreshData reads the data status of the active server in rt's session
// and stores it.
func (s *Service) RefreshData(ctx context.Context, srv store.FeedServer, rt http.RoundTripper) (store.FeedData, error) {
	tr, ok := rt.(*client.Transport)
	if !ok {
		return store.FeedData{}, errors.New("feedsvc: not a feed transport")
	}
	data, err := s.fetchStatus(ctx, tr)
	if err != nil {
		return store.FeedData{}, err
	}
	if err := s.st.RecordFeedData(ctx, srv.ID, data); err != nil {
		return store.FeedData{}, err
	}
	return data, nil
}

// Run keeps a session to the active server until ctx ends: it re-reads the
// active server every tick (or after Kick), replaces the transport when the
// server or its settings change, and sends heartbeats at the interval the
// server asks for. Each contact's outcome is stored.
func (s *Service) Run(ctx context.Context) error {
	if _, err := s.Instance(ctx); err != nil {
		s.log.Warn("feed instance key", "error", err)
	}
	defer s.closeActive(context.WithoutCancel(ctx))
	for {
		s.step(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.tick):
		case <-s.wake:
		}
	}
}

func (s *Service) step(ctx context.Context) {
	srv, err := s.st.GetActiveFeedServer(ctx)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.closeActive(ctx)
		return
	case err != nil:
		if ctx.Err() == nil {
			s.log.Warn("read active feed server", "error", err)
		}
		return
	case !srv.Enabled || srv.Status == store.FeedServerKeyChanged:
		s.closeActive(ctx)
		return
	}
	c, err := s.conn(ctx, srv)
	if err != nil {
		s.log.Warn("feed connection", "server", srv.URL, "error", err)
		return
	}
	interval := s.tick
	if info, ok := c.tr.Session(); ok && info.Heartbeat > 0 {
		interval = info.Heartbeat
	}
	_, hasSession := c.tr.Session()
	if hasSession && s.now().Sub(c.lastBeat) < interval {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	err = c.tr.Heartbeat(cctx)
	if ctx.Err() != nil {
		return
	}
	c.lastBeat = s.now()
	if err != nil {
		s.log.Warn("feed session", "server", srv.URL, "error", errorText(err))
	} else if !hasSession {
		info, _ := c.tr.Session()
		s.log.Info("feed session started", "server", srv.URL, "grade", info.Grade, "expires", info.Expires)
	}
	s.record(ctx, srv, c.tr, err)
}

// conn returns the transport of the active server, replacing the cached one
// when srv differs from it.
func (s *Service) conn(ctx context.Context, srv store.FeedServer) (*conn, error) {
	s.mu.Lock()
	c := s.active
	s.mu.Unlock()
	if c != nil && c.id == srv.ID && c.url == srv.URL && c.serverKey == srv.ServerKey && c.telemetry == srv.Telemetry {
		return c, nil
	}
	// A key stored by this transport's own first contact does not make it
	// stale.
	if c != nil && c.id == srv.ID && c.url == srv.URL && c.telemetry == srv.Telemetry && c.serverKey == "" {
		s.mu.Lock()
		c.serverKey = srv.ServerKey
		s.mu.Unlock()
		return c, nil
	}
	s.closeActive(ctx)
	tr, err := s.transport(ctx, srv)
	if err != nil {
		return nil, err
	}
	c = &conn{id: srv.ID, url: srv.URL, serverKey: srv.ServerKey, telemetry: srv.Telemetry, tr: tr}
	s.mu.Lock()
	s.active = c
	s.mu.Unlock()
	return c, nil
}

func (s *Service) closeActive(ctx context.Context) {
	s.mu.Lock()
	c := s.active
	s.active = nil
	s.mu.Unlock()
	if c == nil {
		return
	}
	if _, ok := c.tr.Session(); !ok {
		return
	}
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := c.tr.Close(cctx); err != nil {
		s.log.Debug("end feed session", "server", c.url, "error", err)
	}
}

// ── input ───────────────────────────────────────────────────────────────

// NormalizeURL checks a feed server URL and returns its canonical form:
// https (http only for a loopback host), no user info, query or fragment,
// no trailing slash.
func NormalizeURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%w: url must be an absolute https URL", ErrInvalid)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && isLoopback(u.Hostname()):
	default:
		return "", fmt.Errorf("%w: url must use https", ErrInvalid)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", fmt.Errorf("%w: url must not have user info, query or fragment", ErrInvalid)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u.String(), nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
