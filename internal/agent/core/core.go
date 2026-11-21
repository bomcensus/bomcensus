// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package core is the part of the host agent that the scanner shares:
// enrollment, the connection to the server in both connection modes,
// message signatures, the long-poll loop with directive dispatch, periodic
// tasks, certificate renewal, trust bundle synchronization and the report
// upload spool.
//
// A Runtime is configured with its kind and extended with directive
// handlers (Handle), periodic tasks (AddTask) and hooks that add status to
// the poll request, react to configuration changes, successful polls and
// uploads. Run drives everything until the context ends or Stop is called.
package core

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/bomcensus/bomcensus/internal/agent/state"
	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/link"
	"github.com/bomcensus/bomcensus/internal/msgsig"
	"github.com/bomcensus/bomcensus/internal/pki"
)

// Kind is the enrolled component type.
type Kind string

const (
	KindAgent   Kind = "agent"
	KindScanner Kind = "scanner"
)

// Built-in directive types handled by every Runtime.
const (
	DirectiveRenewCert       = "renew_cert"
	DirectiveSyncTrustBundle = "sync_trust_bundle"
)

// DirectiveHandler handles one directive. Handlers run one after another on
// the poll loop, so long work must be handed to another goroutine. The
// directive is acknowledged after the handler returns, whatever the result.
type DirectiveHandler func(ctx context.Context, d agentapi.Directive) error

// Task is a periodic job.
type Task struct {
	Name string
	// Interval returns the wait before the next run. It is evaluated after
	// every run and once a minute while waiting, so it can follow
	// configuration changes (a shorter value ends the wait early). A zero or
	// negative value waits one minute and asks again without running.
	Interval func() time.Duration
	// Immediate runs the task once at start.
	Immediate bool
	// Run performs the work. Errors are logged.
	Run func(ctx context.Context) error
}

// StatusFunc adds component specific status to a poll request.
type StatusFunc func(ctx context.Context, req *agentapi.PollRequest)

// Options configures a Runtime. Zero durations select the defaults.
type Options struct {
	Kind    Kind
	State   *state.Dir
	Version string
	Logger  *slog.Logger

	// SpoolMax bounds the report spool (default state.DefaultSpoolMax).
	SpoolMax int64
	// CounterBatch is the number of counter values reserved per write.
	CounterBatch int

	// PollTimeout bounds one poll request (default 2 min; the server
	// answers within 30 s).
	PollTimeout time.Duration
	// MinPollInterval is the least time between two poll requests
	// (default 1 s).
	MinPollInterval time.Duration
	// MaxBackoff caps the retry wait after errors (default 5 min).
	MaxBackoff time.Duration
	// RenewCheckInterval is how often the certificate age is checked
	// (default 1 h).
	RenewCheckInterval time.Duration
	// PendingInterval is the wait between enroll/result requests while
	// approval is pending, unless the server suggests one (default 30 s).
	PendingInterval time.Duration
	// SpoolRetryInterval is how often spooled reports are retried
	// (default 1 min).
	SpoolRetryInterval time.Duration
	// RevokedBackoff is the wait at start after a previous run ended
	// because the server revoked the agent (default 5 min). It doubles with
	// every such run up to MaxRevokedBackoff (default 1 h).
	RevokedBackoff    time.Duration
	MaxRevokedBackoff time.Duration

	// OnListening is called with the bound address in listen mode.
	OnListening func(net.Addr)
	// Connect tunes the connect-mode HTTP transport.
	Connect link.ConnectOptions
	// Now is the clock (default time.Now).
	Now func() time.Time
}

func (o *Options) defaults() {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&o.PollTimeout, 2*time.Minute)
	def(&o.MinPollInterval, time.Second)
	def(&o.MaxBackoff, 5*time.Minute)
	def(&o.RenewCheckInterval, time.Hour)
	def(&o.PendingInterval, 30*time.Second)
	def(&o.SpoolRetryInterval, time.Minute)
	def(&o.RevokedBackoff, 5*time.Minute)
	def(&o.MaxRevokedBackoff, time.Hour)
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Kind == "" {
		o.Kind = KindAgent
	}
}

// Runtime is an enrolled agent or scanner talking to the server.
type Runtime struct {
	opts    Options
	log     *slog.Logger
	st      *state.Dir
	pin     [32]byte
	counter *state.Counter
	spool   *state.Spool
	keys    *serverKeys

	lc     *linkConn
	client *agentapi.ClientWithResponses
	httpc  *http.Client

	mu       sync.RWMutex
	enr      state.Enrollment
	ident    *state.Identity
	tlsCert  *tls.Certificate
	tempCert *tls.Certificate
	bundle   *pki.TrustBundle
	config   *agentapi.AgentConfig
	extra    []*x509.Certificate
	// revoked is the record of earlier runs that ended with agent_revoked.
	// While it is set, connect mode presents no client certificate: the
	// server refuses the handshake of a revoked certificate, and without
	// one the request reaches the signature check, which answers with a
	// signed agent_revoked (or tells that the record is stale).
	revoked *state.Revocation

	handlers    map[string]DirectiveHandler
	tasks       []Task
	statusFuncs []StatusFunc
	configFuncs []func(context.Context, agentapi.AgentConfig)
	pollFuncs   []func(context.Context)
	uploadFuncs []func(context.Context, ReportMeta)

	renewMu  sync.Mutex
	uploadMu sync.Mutex

	ackMu       sync.Mutex
	pendingAcks []string
	seen        map[string]struct{}
	seenOrder   []string

	stopMu sync.Mutex
	stop   context.CancelCauseFunc
	ran    bool
}

// ErrNotApproved is returned when the server rejected a pending enrollment.
var ErrNotApproved = errors.New("enrollment was rejected by the server")

// ErrRevoked is returned by Run when the server answered with a verified
// agent_revoked: the agent stops polling, and only a new enrollment brings
// it back.
var ErrRevoked = errors.New("the server revoked this enrollment")

// New loads an enrolled state directory. The connection is opened by Run.
func New(opts Options) (*Runtime, error) {
	opts.defaults()
	if opts.State == nil {
		return nil, errors.New("core: state directory is required")
	}
	st := opts.State
	enr, err := st.LoadEnrollment()
	if err != nil {
		return nil, err
	}
	if enr.Kind != "" && Kind(enr.Kind) != opts.Kind {
		return nil, fmt.Errorf("core: state directory belongs to a %s, not a %s", enr.Kind, opts.Kind)
	}
	pin, err := enr.PinHash()
	if err != nil {
		return nil, err
	}
	ident, err := st.LoadIdentity()
	if err != nil {
		return nil, err
	}
	if enr.Status == state.StatusApproved && ident.Cert == nil {
		return nil, errors.New("core: enrolled state has no certificate")
	}
	bundle, err := st.LoadTrustBundle()
	if err != nil {
		return nil, err
	}
	extra, err := st.LoadExtraRoots()
	if err != nil {
		return nil, err
	}
	counter, err := st.Counter(opts.CounterBatch)
	if err != nil {
		return nil, err
	}
	spool, err := st.Spool(opts.SpoolMax)
	if err != nil {
		return nil, err
	}
	revoked, err := st.LoadRevocation()
	if err != nil {
		return nil, err
	}
	r := &Runtime{
		opts:     opts,
		log:      opts.Logger,
		st:       st,
		pin:      pin,
		counter:  counter,
		spool:    spool,
		enr:      *enr,
		bundle:   bundle,
		extra:    extra,
		revoked:  revoked,
		handlers: map[string]DirectiveHandler{},
		seen:     map[string]struct{}{},
	}
	r.setIdentity(ident)
	var cfg agentapi.AgentConfig
	if ok, err := st.LoadServerConfig(&cfg); err != nil {
		r.log.Warn("ignoring stored server configuration", "error", err)
	} else if ok {
		r.config = &cfg
	}
	r.handlers[DirectiveRenewCert] = r.handleRenew
	r.handlers[DirectiveSyncTrustBundle] = r.handleSyncTrustBundle
	return r, nil
}

// Handle registers the handler of a directive type. It must be called
// before Run. Registering a built-in type replaces the built-in handler.
func (r *Runtime) Handle(typ string, h DirectiveHandler) { r.handlers[typ] = h }

// AddTask registers a periodic task. It must be called before Run.
func (r *Runtime) AddTask(t Task) { r.tasks = append(r.tasks, t) }

// OnStatus registers a function that adds status to every poll request.
func (r *Runtime) OnStatus(f StatusFunc) { r.statusFuncs = append(r.statusFuncs, f) }

// OnConfig registers a function called with the server configuration at
// start (when one is stored) and whenever it changes.
func (r *Runtime) OnConfig(f func(context.Context, agentapi.AgentConfig)) {
	r.configFuncs = append(r.configFuncs, f)
}

// OnPoll registers a function called after every successful poll, before
// the directives are handled.
func (r *Runtime) OnPoll(f func(context.Context)) { r.pollFuncs = append(r.pollFuncs, f) }

// OnUploaded registers a function called after a report was accepted by
// the server, with the metadata it was submitted with.
func (r *Runtime) OnUploaded(f func(context.Context, ReportMeta)) {
	r.uploadFuncs = append(r.uploadFuncs, f)
}

// Logger returns the runtime's logger.
func (r *Runtime) Logger() *slog.Logger { return r.log }

// State returns the state directory.
func (r *Runtime) State() *state.Dir { return r.st }

// Version returns the version the runtime reports.
func (r *Runtime) Version() string { return r.opts.Version }

// Enrollment returns a copy of the enrollment parameters.
func (r *Runtime) Enrollment() state.Enrollment {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.enr
}

// AgentID returns the agent id.
func (r *Runtime) AgentID() string { return r.Enrollment().AgentID }

// Config returns the last configuration received from the server.
func (r *Runtime) Config() (agentapi.AgentConfig, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.config == nil {
		return agentapi.AgentConfig{}, false
	}
	return *r.config, true
}

// Certificate returns the current agent certificate (nil while pending).
func (r *Runtime) Certificate() *x509.Certificate {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.ident.Cert
}

// TrustBundle returns the current trust bundle (nil before the first).
func (r *Runtime) TrustBundle() *pki.TrustBundle {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.bundle
}

// Client returns the signed API client. It is valid during Run.
func (r *Runtime) Client() *agentapi.ClientWithResponses { return r.client }

// HTTPClient returns the signed HTTP client used by Client, for streamed
// downloads. It is valid during Run.
func (r *Runtime) HTTPClient() *http.Client { return r.httpc }

// BaseURL returns the URL prefix of the protocol, ending in "/". It is
// valid during Run.
func (r *Runtime) BaseURL() string { return r.lc.baseURL }

// ObservedServer returns the server certificate seen in the last handshake.
func (r *Runtime) ObservedServer() (fingerprint [32]byte, leaf *x509.Certificate, ok bool) {
	if r.lc == nil {
		return fingerprint, nil, false
	}
	return r.lc.observed.Last()
}

// Stop ends Run, which returns err after shutting down.
func (r *Runtime) Stop(err error) {
	r.stopMu.Lock()
	defer r.stopMu.Unlock()
	if r.stop != nil {
		r.stop(err)
	}
}

func (r *Runtime) setIdentity(id *state.Identity) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ident = id
	r.tlsCert = nil
	if id.Cert != nil {
		c := pki.TLSCertificate([]*x509.Certificate{id.Cert}, id.Key)
		r.tlsCert = &c
	}
}

func (r *Runtime) identity() *state.Identity {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.ident
}

func (r *Runtime) currentBundle() *pki.TrustBundle { return r.TrustBundle() }

// clientCert is the connect-mode client certificate getter.
func (r *Runtime) clientCert() (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.revoked != nil {
		return nil, nil
	}
	return r.tlsCert, nil
}

// listenerCert returns the issued certificate, or before approval a
// temporary in-memory one.
func (r *Runtime) listenerCert() (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tlsCert != nil {
		return r.tlsCert, nil
	}
	if r.tempCert == nil {
		c, err := pki.NewTemporaryCertificate()
		if err != nil {
			return nil, err
		}
		r.tempCert = &c
	}
	return r.tempCert, nil
}

func (r *Runtime) linkParams() linkParams {
	r.mu.RLock()
	enr := r.enr
	extra := r.extra
	r.mu.RUnlock()
	mode, _ := link.ParseTLSMode(enr.TLSMode)
	p := linkParams{
		mode:        enr.ConnectMode,
		serverURL:   enr.ServerURL,
		serverName:  enr.ServerName,
		tlsMode:     mode,
		verify:      serverVerifier(r.pin, enr.ServerName, r.currentBundle),
		extraRoots:  extra,
		cert:        r.clientCert,
		listenAddr:  enr.ListenAddress,
		onListening: r.opts.OnListening,
		connect:     r.opts.Connect,
		logger:      r.log,
	}
	if enr.ConnectMode == ModeListen {
		p.cert = r.listenerCert
	}
	return p
}

// attach sets up the signed clients on lc.
func (r *Runtime) attach(lc *linkConn) error {
	r.lc = lc
	serverName := r.Enrollment().ServerName
	verify := serverVerifier(r.pin, serverName, r.currentBundle)
	if r.keys == nil {
		r.keys = &serverKeys{}
	}
	r.keys.fetch = func(ctx context.Context) ([]*x509.Certificate, error) {
		return fetchServerChain(ctx, lc.base, lc.baseURL)
	}
	r.keys.verify = func(chain []*x509.Certificate) error {
		return verify(chain, x509.ExtKeyUsageServerAuth)
	}
	r.httpc = &http.Client{Transport: &signer{r: r}}
	c, err := agentapi.NewClientWithResponses(lc.baseURL, agentapi.WithHTTPClient(r.httpc))
	if err != nil {
		return err
	}
	r.client = c
	return nil
}

// signer signs with the identity current at the time of each request.
type signer struct {
	r   *Runtime
	key ed25519.PrivateKey
}

func (s *signer) RoundTrip(req *http.Request) (*http.Response, error) {
	key := s.key
	if key == nil {
		key = s.r.identity().Key
	}
	t := &msgsig.Transport{
		Base:       s.r.lc.base,
		AgentID:    s.r.AgentID(),
		Key:        key,
		Counter:    s.r.counter,
		ServerKeys: s.r.keys,
		Exempt:     exemptPaths,
		Now:        s.r.opts.Now,
	}
	return t.RoundTrip(req)
}

// clientWithKey returns a client signing with key instead of the identity.
func (r *Runtime) clientWithKey(key ed25519.PrivateKey) (*agentapi.ClientWithResponses, error) {
	return agentapi.NewClientWithResponses(r.lc.baseURL, agentapi.WithHTTPClient(&http.Client{Transport: &signer{r: r, key: key}}))
}

// Run connects to the server and runs the poll loop, the built-in tasks and
// the registered tasks until ctx ends (it then returns nil) or Stop is
// called (it returns the error passed to Stop). A pending enrollment is
// resumed first.
func (r *Runtime) Run(ctx context.Context) error {
	r.stopMu.Lock()
	if r.ran {
		r.stopMu.Unlock()
		return errors.New("core: Run called twice")
	}
	r.ran = true
	rctx, cancel := context.WithCancelCause(ctx)
	r.stop = cancel
	r.stopMu.Unlock()
	defer cancel(nil)

	if rec := r.revocation(); rec != nil {
		wait := revokedWait(rec.Count, r.opts.RevokedBackoff, r.opts.MaxRevokedBackoff)
		r.log.Error("the server revoked this enrollment in an earlier run; waiting before asking again",
			"agent_id", r.AgentID(), "revoked_since", rec.FirstSeen, "runs", rec.Count, "retry_in", wait)
		if !sleep(rctx, wait) {
			return r.runResult(ctx, rctx, nil)
		}
	}

	if r.lc == nil {
		lc, err := openLink(rctx, r.linkParams())
		if err != nil {
			return err
		}
		if err := r.attach(lc); err != nil {
			lc.close()
			return err
		}
	}
	defer r.lc.close()

	return r.runResult(ctx, rctx, r.run(rctx))
}

func (r *Runtime) runResult(ctx, rctx context.Context, err error) error {
	if ctx.Err() != nil {
		return nil
	}
	if cause := context.Cause(rctx); cause != nil && !errors.Is(cause, context.Canceled) {
		return cause
	}
	return err
}

// revokedWait is the wait at start when the given number of earlier runs
// ended with agent_revoked: base, doubled per further run, capped at max.
func revokedWait(runs int, base, max time.Duration) time.Duration {
	d := base
	for i := 1; i < runs && d < max; i++ {
		d *= 2
	}
	return min(d, max)
}

func (r *Runtime) revocation() *state.Revocation {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.revoked
}

// isRevoked reports whether err is a verified agent_revoked answer. An
// APIError is only built from responses whose signature verified.
func isRevoked(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusForbidden && ae.Code == msgsig.CodeAgentRevoked
}

// revokedByServer records the revocation and stops the runtime with
// ErrRevoked.
func (r *Runtime) revokedByServer(err error) {
	now := r.opts.Now().UTC()
	r.mu.Lock()
	rec := state.Revocation{FirstSeen: now}
	if r.revoked != nil {
		rec = *r.revoked
	}
	rec.Count++
	rec.LastSeen = now
	r.revoked = &rec
	r.mu.Unlock()
	if serr := r.st.SaveRevocation(&rec); serr != nil {
		r.log.Warn("store revocation record", "error", serr)
	}
	r.log.Error("the server revoked this enrollment; stopping. Remove the state directory and enroll again to resume",
		"kind", string(r.opts.Kind), "agent_id", r.AgentID(), "state_dir", r.st.Path(), "error", err)
	r.Stop(ErrRevoked)
}

// clearRevoked drops a revocation record that the server contradicted and
// reconnects with the client certificate.
func (r *Runtime) clearRevoked() {
	r.mu.Lock()
	had := r.revoked != nil
	r.revoked = nil
	r.mu.Unlock()
	if !had {
		return
	}
	r.log.Info("the server no longer reports this enrollment as revoked", "agent_id", r.AgentID())
	if err := r.st.ClearRevocation(); err != nil {
		r.log.Warn("remove revocation record", "error", err)
	}
	if r.lc != nil && r.lc.reset != nil {
		r.lc.reset()
	}
}

func (r *Runtime) run(ctx context.Context) error {
	if r.Enrollment().Status == state.StatusPending {
		if err := r.waitApproved(ctx); err != nil {
			return err
		}
	}
	if err := r.recoverNextKey(ctx); err != nil {
		r.log.Warn("pending key change not resolved", "error", err)
	}
	r.log.Info("running", "kind", string(r.opts.Kind), "agent_id", r.AgentID(),
		"connect_mode", r.Enrollment().ConnectMode, "tls_mode", r.Enrollment().TLSMode, "version", r.opts.Version)

	if cfg, ok := r.Config(); ok {
		for _, f := range r.configFuncs {
			f(ctx, cfg)
		}
	}

	tasks := append([]Task{
		{
			Name:      "certificate renewal",
			Interval:  func() time.Duration { return r.opts.RenewCheckInterval },
			Immediate: true,
			Run:       r.renewIfDue,
		},
		{
			Name:     "report spool",
			Interval: func() time.Duration { return r.opts.SpoolRetryInterval },
			Run:      r.FlushSpool,
		},
	}, r.tasks...)

	var wg sync.WaitGroup
	for _, t := range tasks {
		wg.Go(func() { r.runTask(ctx, t) })
	}
	r.pollLoop(ctx)
	wg.Wait()
	return nil
}

func (r *Runtime) runTask(ctx context.Context, t Task) {
	run := func() {
		if err := t.Run(ctx); err != nil && ctx.Err() == nil {
			r.log.Warn("task failed", "task", t.Name, "error", err)
		}
	}
	if t.Immediate {
		run()
	}
	for {
		d := t.Interval()
		if d <= 0 {
			if !sleep(ctx, time.Minute) {
				return
			}
			continue
		}
		due, ok := waitInterval(ctx, t.Interval, d)
		if !ok {
			return
		}
		if due {
			run()
		}
	}
}

// taskRecheck is how often a waiting task asks its Interval again, so that
// a shorter interval from the server (for example the update check
// interval) takes effect without waiting out the old one.
var taskRecheck = time.Minute

// waitInterval waits for about d since the call, re-reading interval every
// taskRecheck and following a changed value. due is false when the
// interval became zero or negative meanwhile; ok is false when ctx ended.
func waitInterval(ctx context.Context, interval func() time.Duration, d time.Duration) (due, ok bool) {
	start := time.Now()
	wait := jitter(d, 0.1)
	for {
		left := wait - time.Since(start)
		if left <= 0 {
			return true, true
		}
		if !sleep(ctx, min(left, taskRecheck)) {
			return false, false
		}
		nd := interval()
		if nd <= 0 {
			return false, true
		}
		if nd != d {
			d = nd
			wait = jitter(d, 0.1)
		}
	}
}

// sleep waits for d or until ctx ends; it reports whether d elapsed.
func sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// jitter returns d varied by up to ±frac.
func jitter(d time.Duration, frac float64) time.Duration {
	if d <= 0 || frac <= 0 {
		return d
	}
	f := 1 + frac*(2*rand.Float64()-1)
	return time.Duration(float64(d) * f)
}

// Jitter returns d varied by up to ±frac, for schedulers built on the
// runtime.
func Jitter(d time.Duration, frac float64) time.Duration { return jitter(d, frac) }

func randFloat() float64 { return rand.Float64() }

// nextBackoff returns the next retry delay.
func nextBackoff(prev, max time.Duration) time.Duration {
	if prev <= 0 {
		return time.Second
	}
	return min(2*prev, max)
}
