// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package msgsig

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/bomcensus/bomcensus/internal/pki"
)

// State is the enrollment state of an agent.
type State int

// Agent states. The zero value is not a valid state and is rejected.
const (
	StateApproved State = iota + 1
	StatePending
	StateRevoked
)

func (s State) String() string {
	switch s {
	case StateApproved:
		return "approved"
	case StatePending:
		return "pending"
	case StateRevoked:
		return "revoked"
	}
	return "invalid"
}

// ErrUnknownAgent is returned by a KeyLookup for an agent id that does not
// exist.
var ErrUnknownAgent = errors.New("msgsig: unknown agent")

// AgentKey is what the server knows about a signing identity.
type AgentKey struct {
	// PublicKey is the agent's Ed25519 identity key.
	PublicKey ed25519.PublicKey
	State     State
	// RequireTLSClientCert rejects requests that arrive without a verified
	// TLS client certificate (agents not allowed to use a relaxed TLS mode).
	RequireTLSClientCert bool
}

// Agent is the authenticated identity of a request.
type Agent struct {
	ID    string
	State State
}

// Config configures Middleware.
type Config struct {
	// KeyLookup returns the identity key and state of an agent, or
	// ErrUnknownAgent. Required.
	KeyLookup func(ctx context.Context, agentID string) (AgentKey, error)
	// AdvanceCounter atomically stores n as the agent's counter if n is
	// greater than the stored value. It returns the stored value after the
	// call and whether n was accepted. Required.
	AdvanceCounter func(ctx context.Context, agentID string, n uint64) (current uint64, ok bool, err error)
	// Signer returns the current response signing key. Required.
	Signer func(ctx context.Context) (*ServerSigner, error)

	// Bypass paths are passed to the next handler without verification
	// and without a response signature (enroll/start, enroll/finish,
	// server-chain).
	Bypass Paths
	// Exempt paths are verified, but the response is streamed unsigned
	// (self-authenticating downloads).
	Exempt Paths
	// PendingAllowed paths may be called by pending agents.
	PendingAllowed Paths

	// MaxRequestBody caps request bodies (default DefaultMaxRequestBody).
	MaxRequestBody int64
	// MaxResponseBody caps buffered response bodies (default
	// DefaultMaxResponseBody).
	MaxResponseBody int64
	// MaxSkew is the accepted difference between the signature's created
	// time and the server clock (default 5 minutes). Nonces are remembered
	// for twice this duration.
	MaxSkew time.Duration
	// NonceCacheSize bounds the number of remembered nonces (default 100000).
	NonceCacheSize int

	Logger *slog.Logger
	Now    func() time.Time
}

// Middleware verifies request signatures and signs responses.
type Middleware struct {
	cfg        Config
	nonces     *nonceCache
	log        *slog.Logger
	revokedLog logOnce
}

// New validates cfg and returns a Middleware.
func New(cfg Config) (*Middleware, error) {
	if cfg.KeyLookup == nil || cfg.AdvanceCounter == nil || cfg.Signer == nil {
		return nil, errors.New("msgsig: KeyLookup, AdvanceCounter and Signer are required")
	}
	if cfg.MaxRequestBody <= 0 {
		cfg.MaxRequestBody = DefaultMaxRequestBody
	}
	if cfg.MaxResponseBody <= 0 {
		cfg.MaxResponseBody = DefaultMaxResponseBody
	}
	if cfg.MaxSkew <= 0 {
		cfg.MaxSkew = 5 * time.Minute
	}
	if cfg.NonceCacheSize <= 0 {
		cfg.NonceCacheSize = 100000
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Middleware{cfg: cfg, nonces: newNonceCache(cfg.NonceCacheSize, 2*cfg.MaxSkew), log: log,
		revokedLog: logOnce{interval: revokedLogInterval, max: revokedLogMax}}, nil
}

// A revoked agent retries until it is stopped; its rejections are logged at
// info level once per agent and code in this interval, then at debug level.
const (
	revokedLogInterval = time.Hour
	revokedLogMax      = 10000
)

// logOnce remembers when a key was last logged.
type logOnce struct {
	interval time.Duration
	max      int

	mu   sync.Mutex
	last map[string]time.Time
}

// first reports whether key was not logged within the interval and records
// now for it.
func (l *logOnce) first(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if t, ok := l.last[key]; ok && now.Sub(t) < l.interval {
		return false
	}
	if l.last == nil || len(l.last) >= l.max {
		l.last = make(map[string]time.Time)
	}
	l.last[key] = now
	return true
}

type ctxKey int

const (
	agentKey ctxKey = iota
	tlsPeerKey
	tlsPeerFailureKey
)

// AgentFromContext returns the authenticated agent of a request handled by
// Middleware.
func AgentFromContext(ctx context.Context) (Agent, bool) {
	a, ok := ctx.Value(agentKey).(Agent)
	return a, ok
}

// WithTLSPeerAgentID records the agent id of a verified TLS client (or, in
// listen mode, peer) certificate. When set, Middleware requires the signing
// identity to equal it. The caller extracts and verifies the certificate.
func WithTLSPeerAgentID(ctx context.Context, agentID string) context.Context {
	return context.WithValue(ctx, tlsPeerKey, agentID)
}

func tlsPeerAgentID(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(tlsPeerKey).(string)
	return id, ok
}

// TLSPeerFailure is why the TLS client certificate of a request failed the
// per-request check of the connection layer.
type TLSPeerFailure int

// TLS peer failures.
const (
	// TLSPeerRevoked: the certificate serial is revoked or unknown.
	TLSPeerRevoked TLSPeerFailure = iota + 1
	// TLSPeerInvalid: the chain no longer verifies (for example expired).
	TLSPeerInvalid
	// TLSPeerCheckFailed: the revocation state could not be determined.
	TLSPeerCheckFailed
)

// WithTLSPeerFailure records that the request arrived with a TLS client
// certificate that failed verification. Middleware then rejects the request
// in its authorization step with a signed error: 403 agent_revoked for
// TLSPeerRevoked, 403 client_certificate_mismatch for TLSPeerInvalid and
// 500 internal_error for TLSPeerCheckFailed.
func WithTLSPeerFailure(ctx context.Context, f TLSPeerFailure) context.Context {
	return context.WithValue(ctx, tlsPeerFailureKey, f)
}

func tlsPeerFailure(ctx context.Context) (TLSPeerFailure, bool) {
	f, ok := ctx.Value(tlsPeerFailureKey).(TLSPeerFailure)
	return f, ok && f != 0
}

// Error codes in {code, message} error bodies.
const (
	CodeInvalidRequest     = "invalid_request"
	CodeDigestMismatch     = "digest_mismatch"
	CodeUnauthorized       = "unauthorized"
	CodeNonceReplayed      = "nonce_replayed"
	CodeAgentRevoked       = "agent_revoked"
	CodeAgentPending       = "agent_pending"
	CodeClientCertMismatch = "client_certificate_mismatch"
	CodeCounterReplayed    = "counter_replayed"
	CodeBodyTooLarge       = "body_too_large"
	CodeInternal           = "internal_error"
)

type rejection struct {
	status  int
	code    string
	reason  string
	counter uint64 // carried in Bomcensus-Counter when non-zero
	// expected marks a rejection an agent keeps receiving until an operator
	// acts (revoked agent or certificate). It is logged at info level once
	// per agent and code within revokedLogInterval.
	expected bool
}

func reject(status int, code, reason string) *rejection {
	return &rejection{status: status, code: code, reason: reason}
}

// Wrap returns next guarded by the middleware.
func (m *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.serve(w, r, next)
	})
}

func (m *Middleware) serve(w http.ResponseWriter, r *http.Request, next http.Handler) {
	path, query, err := serverTarget(r)
	if err != nil || !validPath(path) || path != r.URL.Path {
		m.fail(w, r, "", reject(http.StatusBadRequest, CodeInvalidRequest, "invalid request path"))
		return
	}
	if m.cfg.Bypass.Match(path) {
		next.ServeHTTP(w, r)
		return
	}
	// The nonce is only used to bind error responses until the signature
	// is verified.
	nonce := r.Header.Get(HeaderNonce)
	if len(r.Header.Values(HeaderNonce)) != 1 || !validNonce(nonce) {
		nonce = ""
	}
	ctx := r.Context()

	v, rj := m.verifyRequest(r, path, query)
	if rj != nil {
		m.fail(w, r, nonce, rj)
		return
	}
	if rj := m.authorize(ctx, path, v); rj != nil {
		m.fail(w, r, nonce, rj)
		return
	}
	agent := v.agent

	r2 := r.WithContext(context.WithValue(ctx, agentKey, agent))
	r2.Body = io.NopCloser(bytes.NewReader(v.body))
	r2.ContentLength = int64(len(v.body))
	r2.GetBody = nil

	if m.cfg.Exempt.Match(path) {
		next.ServeHTTP(w, r2)
		return
	}
	bw := &bufferWriter{header: make(http.Header), max: m.cfg.MaxResponseBody}
	next.ServeHTTP(bw, r2)
	if bw.overflow {
		m.log.ErrorContext(ctx, "response exceeds buffer limit", "path", path, "agent_id", agent.ID, "limit", m.cfg.MaxResponseBody)
		m.fail(w, r, nonce, reject(http.StatusInternalServerError, CodeInternal, "response too large"))
		return
	}
	status := bw.status
	if status == 0 {
		status = http.StatusOK
	}
	if err := m.writeSigned(w, r, nonce, status, bw.header, bw.buf.Bytes()); err != nil {
		m.log.ErrorContext(ctx, "sign response", "path", path, "agent_id", agent.ID, "error", err)
		writeError(w, http.StatusInternalServerError, CodeInternal, "internal error", 0)
	}
}

// verified is the outcome of a successful request verification.
type verified struct {
	agent      Agent
	key        AgentKey
	body       []byte
	counter    uint64
	hasCounter bool
}

// verifyRequest checks the envelope, digest, signature, created time and
// nonce. It returns the identity and the buffered body.
func (m *Middleware) verifyRequest(r *http.Request, path, query string) (*verified, *rejection) {
	ctx := r.Context()
	h := r.Header
	v := &verified{}

	if r.ContentLength > m.cfg.MaxRequestBody {
		return nil, reject(http.StatusRequestEntityTooLarge, CodeBodyTooLarge, "request body too large")
	}
	agentID, err := singleHeader(h, HeaderAgentID)
	if err != nil || pki.ValidateAgentID(agentID) != nil {
		return nil, reject(http.StatusBadRequest, CodeInvalidRequest, "missing or invalid "+HeaderAgentID)
	}
	nonce, err := singleHeader(h, HeaderNonce)
	if err != nil || !validNonce(nonce) {
		return nil, reject(http.StatusBadRequest, CodeInvalidRequest, "missing or invalid "+HeaderNonce)
	}
	counterStr, hasCounter, err := optionalHeader(h, HeaderCounter)
	if err != nil || hasCounter != isStateChanging(r.Method) {
		return nil, reject(http.StatusBadRequest, CodeInvalidRequest, HeaderCounter+" must be sent exactly on state-changing requests")
	}
	if hasCounter {
		if v.counter, err = parseCounter(counterStr); err != nil {
			return nil, reject(http.StatusBadRequest, CodeInvalidRequest, "invalid "+HeaderCounter)
		}
		v.hasCounter = true
	}
	digest, err := singleHeader(h, HeaderContentDigest)
	if err != nil {
		return nil, reject(http.StatusBadRequest, CodeInvalidRequest, "missing "+HeaderContentDigest)
	}
	input, err := singleHeader(h, HeaderSignatureInput)
	if err != nil {
		return nil, reject(http.StatusBadRequest, CodeInvalidRequest, "missing "+HeaderSignatureInput)
	}
	p, err := parseSignatureInput(input, requestCovered(hasCounter))
	if err != nil {
		return nil, reject(http.StatusBadRequest, CodeInvalidRequest, "invalid "+HeaderSignatureInput+": "+err.Error())
	}
	sigStr, err := singleHeader(h, HeaderSignature)
	if err != nil {
		return nil, reject(http.StatusBadRequest, CodeInvalidRequest, "missing "+HeaderSignature)
	}
	sig, err := parseSignature(sigStr)
	if err != nil {
		return nil, reject(http.StatusBadRequest, CodeInvalidRequest, "invalid "+HeaderSignature)
	}
	if p.keyID != agentID || p.alg != AlgEd25519 {
		return nil, reject(http.StatusUnauthorized, CodeUnauthorized, "keyid or alg does not match")
	}

	if r.Body != nil {
		v.body, err = io.ReadAll(io.LimitReader(r.Body, m.cfg.MaxRequestBody+1))
		if err != nil {
			return nil, reject(http.StatusBadRequest, CodeInvalidRequest, "read body")
		}
		if int64(len(v.body)) > m.cfg.MaxRequestBody {
			return nil, reject(http.StatusRequestEntityTooLarge, CodeBodyTooLarge, "request body too large")
		}
	}
	if digest != ContentDigest(v.body) {
		return nil, reject(http.StatusBadRequest, CodeDigestMismatch, "content digest mismatch")
	}

	v.key, err = m.cfg.KeyLookup(ctx, agentID)
	if errors.Is(err, ErrUnknownAgent) {
		return nil, reject(http.StatusUnauthorized, CodeUnauthorized, "unknown agent "+agentID)
	}
	if err != nil {
		m.log.ErrorContext(ctx, "agent key lookup", "agent_id", agentID, "error", err)
		return nil, reject(http.StatusInternalServerError, CodeInternal, "internal error")
	}
	if len(v.key.PublicKey) != ed25519.PublicKeySize {
		return nil, reject(http.StatusUnauthorized, CodeUnauthorized, "agent has no identity key")
	}
	values := []string{r.Method, path, "?" + query, digest, agentID, nonce}
	if hasCounter {
		values = append(values, counterStr)
	}
	base, err := signatureBase(p, values)
	if err != nil {
		return nil, reject(http.StatusBadRequest, CodeInvalidRequest, err.Error())
	}
	if err := verify(v.key.PublicKey, p.alg, base, sig); err != nil {
		return nil, reject(http.StatusUnauthorized, CodeUnauthorized, "signature: "+err.Error())
	}

	now := m.cfg.Now()
	if d := now.Sub(time.Unix(p.created, 0)); d > m.cfg.MaxSkew || d < -m.cfg.MaxSkew {
		return nil, reject(http.StatusUnauthorized, CodeUnauthorized, fmt.Sprintf("created is %s off the server clock", d.Round(time.Second)))
	}
	if !m.nonces.add(agentID+"\x00"+nonce, now) {
		return nil, reject(http.StatusUnauthorized, CodeNonceReplayed, "nonce already used")
	}
	v.agent = Agent{ID: agentID, State: v.key.State}
	return v, nil
}

// authorize applies the state, TLS binding and counter rules to a verified
// request. The counter is advanced last, so a request rejected for any
// other reason does not consume it.
func (m *Middleware) authorize(ctx context.Context, path string, v *verified) *rejection {
	switch v.key.State {
	case StateApproved:
	case StatePending:
		if !m.cfg.PendingAllowed.Match(path) {
			return reject(http.StatusForbidden, CodeAgentPending, "agent is pending approval")
		}
	case StateRevoked:
		return expected(reject(http.StatusForbidden, CodeAgentRevoked, "agent is revoked"))
	default:
		return reject(http.StatusForbidden, CodeAgentRevoked, "agent state "+v.key.State.String())
	}
	if f, ok := tlsPeerFailure(ctx); ok {
		switch f {
		case TLSPeerRevoked:
			return expected(reject(http.StatusForbidden, CodeAgentRevoked, "TLS client certificate is revoked"))
		case TLSPeerCheckFailed:
			return reject(http.StatusInternalServerError, CodeInternal, "TLS client certificate revocation check failed")
		default:
			return expected(reject(http.StatusForbidden, CodeClientCertMismatch, "TLS client certificate does not verify"))
		}
	}
	if peer, ok := tlsPeerAgentID(ctx); ok {
		if peer != v.agent.ID {
			return reject(http.StatusForbidden, CodeClientCertMismatch, "TLS client certificate belongs to "+peer)
		}
	} else if v.key.RequireTLSClientCert {
		return reject(http.StatusForbidden, CodeClientCertMismatch, "TLS client certificate required")
	}
	if v.hasCounter {
		current, ok, err := m.cfg.AdvanceCounter(ctx, v.agent.ID, v.counter)
		if err != nil {
			m.log.ErrorContext(ctx, "advance counter", "agent_id", v.agent.ID, "error", err)
			return reject(http.StatusInternalServerError, CodeInternal, "internal error")
		}
		if !ok {
			rj := reject(http.StatusConflict, CodeCounterReplayed, fmt.Sprintf("counter %d is not above %d", v.counter, current))
			rj.counter = current
			return rj
		}
	}
	return nil
}

func expected(rj *rejection) *rejection {
	rj.expected = true
	return rj
}

func isStateChanging(method string) bool {
	return method != http.MethodGet && method != http.MethodHead
}

// fail logs a rejection and writes the error response, signed when the
// request carried a usable nonce.
func (m *Middleware) fail(w http.ResponseWriter, r *http.Request, nonce string, rj *rejection) {
	lvl := slog.LevelWarn
	switch {
	case rj.status >= 500:
		lvl = slog.LevelError
	case rj.expected:
		lvl = slog.LevelDebug
		if m.revokedLog.first(r.Header.Get(HeaderAgentID)+"\x00"+rj.code, m.cfg.Now()) {
			lvl = slog.LevelInfo
		}
	}
	m.log.Log(r.Context(), lvl, "agent request rejected",
		"path", r.URL.Path, "method", r.Method, "agent_id", r.Header.Get(HeaderAgentID),
		"status", rj.status, "code", rj.code, "reason", rj.reason)
	msg := http.StatusText(rj.status)
	if rj.status < 500 {
		msg = rj.reason
	}
	if nonce == "" {
		writeError(w, rj.status, rj.code, msg, 0)
		return
	}
	body := errorBody(rj.code, msg)
	h := make(http.Header)
	h.Set("Content-Type", "application/json")
	if rj.counter != 0 {
		h.Set(HeaderCounter, formatCounter(rj.counter))
	}
	if err := m.writeSigned(w, r, nonce, rj.status, h, body); err != nil {
		m.log.ErrorContext(r.Context(), "sign error response", "error", err)
		writeError(w, rj.status, rj.code, msg, rj.counter)
	}
}

func errorBody(code, msg string) []byte {
	b, _ := json.Marshal(struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{code, msg})
	return append(b, '\n')
}

// writeError writes an unsigned error response.
func writeError(w http.ResponseWriter, status int, code, msg string, counter uint64) {
	w.Header().Set("Content-Type", "application/json")
	if counter != 0 {
		w.Header().Set(HeaderCounter, formatCounter(counter))
	}
	w.WriteHeader(status)
	_, _ = w.Write(errorBody(code, msg))
}

// writeSigned writes status, header and body with a response signature
// bound to nonce. Nothing is written when it returns an error. The digest
// covers the body as delivered, which is empty for HEAD, 204 and 304.
func (m *Middleware) writeSigned(w http.ResponseWriter, r *http.Request, nonce string, status int, h http.Header, body []byte) error {
	if r.Method == http.MethodHead || !bodyAllowed(status) {
		body = nil
	}
	s, err := m.cfg.Signer(r.Context())
	if err != nil {
		return err
	}
	if s == nil {
		return errors.New("msgsig: no signer")
	}
	for _, k := range []string{HeaderSignature, HeaderSignatureInput, HeaderContentDigest, HeaderRequestNonce, "Content-Length"} {
		h.Del(k)
	}
	counterStr, hasCounter, err := optionalHeader(h, HeaderCounter)
	if err != nil {
		return err
	}
	if hasCounter {
		if _, err := parseCounter(counterStr); err != nil {
			return fmt.Errorf("msgsig: handler set invalid %s", HeaderCounter)
		}
	}
	digest := ContentDigest(body)
	p := params{covered: responseCovered(hasCounter), created: m.cfg.Now().Unix(), keyID: s.keyID, alg: s.alg}
	values := []string{strconv.Itoa(status), digest, nonce}
	if hasCounter {
		values = append(values, counterStr)
	}
	base, err := signatureBase(p, values)
	if err != nil {
		return err
	}
	sig, err := sign(s.key, s.alg, base)
	if err != nil {
		return fmt.Errorf("msgsig: sign: %w", err)
	}
	dst := w.Header()
	for k, v := range h {
		dst[k] = v
	}
	dst.Set(HeaderContentDigest, digest)
	dst.Set(HeaderRequestNonce, nonce)
	dst.Set(HeaderSignatureInput, Label+"="+p.serialize())
	dst.Set(HeaderSignature, formatSignature(sig))
	if r.Method != http.MethodHead && bodyAllowed(status) {
		dst.Set("Content-Length", strconv.Itoa(len(body)))
	}
	w.WriteHeader(status)
	if len(body) > 0 {
		_, _ = w.Write(body)
	}
	return nil
}

func bodyAllowed(status int) bool {
	return status >= 200 && status != http.StatusNoContent && status != http.StatusNotModified
}

// bufferWriter collects a handler's response so that it can be digested
// and signed.
type bufferWriter struct {
	header   http.Header
	status   int
	buf      bytes.Buffer
	max      int64
	overflow bool
}

var errResponseTooLarge = errors.New("msgsig: response exceeds buffer limit")

func (b *bufferWriter) Header() http.Header { return b.header }

func (b *bufferWriter) WriteHeader(code int) {
	if b.status != 0 || code < 200 {
		return
	}
	b.status = code
}

func (b *bufferWriter) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	if b.overflow {
		return 0, errResponseTooLarge
	}
	if int64(b.buf.Len())+int64(len(p)) > b.max {
		b.overflow = true
		return 0, errResponseTooLarge
	}
	return b.buf.Write(p)
}
