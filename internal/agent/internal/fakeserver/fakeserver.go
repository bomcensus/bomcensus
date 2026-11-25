// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package fakeserver is a minimal implementation of the server side of the
// agent protocol for tests. It is assembled from the same libraries as the
// real server: link.ServerTLSConfig, msgsig middleware, enroll signatures
// and the generated router.
package fakeserver

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bomcensus/bomcensus/agentproto/dto"
	"github.com/bomcensus/bomcensus/internal/enroll"
	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/link"
	"github.com/bomcensus/bomcensus/internal/msgsig"
	"github.com/bomcensus/bomcensus/internal/pki"
	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/token"
)

// ServerName is the name in the Agent TLS certificates.
const ServerName = "agents.test"

const base = "/agent/v1"

// Agent is an enrolled agent.
type Agent struct {
	ID       string
	Pub      ed25519.PublicKey
	CSR      *x509.CertificateRequest
	State    msgsig.State
	Relaxed  bool
	Cert     *x509.Certificate
	Counters []uint64
	Renewals int
}

// Update is the deployed release.
type Update struct {
	Version  string
	Manifest []byte
	Sig      []byte
	Bundle   []byte
}

// Options configures New.
type Options struct {
	// ManualApproval keeps enrollments pending until Approve.
	ManualApproval bool
	// CertNotBefore and CertLifetime control issued agent certificates.
	CertNotBefore time.Time
	CertLifetime  time.Duration
	// PollHold is how long a poll without directives is held (default 50 ms).
	PollHold time.Duration
}

// Server is the fake server.
type Server struct {
	t    testing.TB
	opts Options

	TLSCA      *pki.CA
	Pin        [32]byte
	Leaf       *x509.Certificate
	LeafKey    crypto.Signer
	ClientCert tls.Certificate
	AgentCA    *pki.CA
	Token      token.Token

	// InterceptCA issues the certificate presented by SetIntercept.
	InterceptCA *pki.CA

	handler  http.Handler
	verifier *link.AgentVerifier
	URL      string

	mu           sync.Mutex
	cond         chan struct{}
	tlsCert      tls.Certificate
	intercepted  *tls.Certificate
	sessions     map[string]session
	agents       map[string]*Agent
	nextID       int
	startBodies  [][]byte
	finishBodies [][]byte
	polls        []dto.PollRequest
	pollErrs     int
	reports      []*report.Report
	directives   []json.RawMessage
	acked        map[string]bool
	uploadFail   bool
	pollFail     bool
	config       dto.AgentConfig
	bundleSerial int64
	extraAnchors []*x509.Certificate
	update       *Update
	enrollGets   int
	revokedCerts map[string]bool
	requests     int
}

type session struct {
	tr  enroll.Transcript
	csr *x509.CertificateRequest
	req dto.EnrollStartRequest
}

// New creates the PKI and the handler stack. Call Start to listen.
func New(t testing.TB, opts Options) *Server {
	t.Helper()
	if opts.PollHold <= 0 {
		opts.PollHold = 50 * time.Millisecond
	}
	s := &Server{
		t: t, opts: opts,
		sessions: map[string]session{},
		agents:   map[string]*Agent{},
		acked:    map[string]bool{},
		cond:     make(chan struct{}),
		config: dto.AgentConfig{
			SectionIntervals:           dto.SectionIntervals{Host: 3600, Packages: 3600, Artifacts: 3600, Processes: 3600, Containers: 3600},
			Policy:                     dto.Policy{ExecVersion: true, CollectCmdline: true, ScanContainers: true},
			UpdateCheckIntervalMinutes: 60,
			TrustBundleSerial:          1,
		},
		bundleSerial: 1,
	}
	s.TLSCA = newCA(t, "Agent TLS CA")
	s.Pin = pki.SPKIHash(s.TLSCA.Cert)
	key, err := pki.GenerateKey()
	must(t, err)
	s.LeafKey = key
	s.Leaf, err = s.TLSCA.IssueServer(key.Public(), pki.LeafOptions{DNSNames: []string{ServerName}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}})
	must(t, err)
	s.tlsCert = pki.TLSCertificate([]*x509.Certificate{s.Leaf, s.TLSCA.Cert}, key)
	ckey, err := pki.GenerateKey()
	must(t, err)
	ccert, err := s.TLSCA.IssueClient(ckey.Public(), pki.LeafOptions{DNSNames: []string{ServerName}})
	must(t, err)
	s.ClientCert = pki.TLSCertificate([]*x509.Certificate{ccert, s.TLSCA.Cert}, ckey)
	s.AgentCA = newCA(t, "Agent CA")
	s.InterceptCA = newCA(t, "Inspection CA")
	s.Token, err = token.New(s.Pin)
	must(t, err)

	s.verifier = &link.AgentVerifier{AgentCA: func() *x509.Certificate { return s.AgentCA.Cert }, Revoked: s.certRevoked}
	signer, err := msgsig.NewServerSigner(s.Leaf, key)
	must(t, err)
	mw, err := msgsig.New(msgsig.Config{
		KeyLookup:      s.keyLookup,
		AdvanceCounter: s.advance,
		Signer:         func(context.Context) (*msgsig.ServerSigner, error) { return signer, nil },
		Bypass:         msgsig.Paths{base + "/enroll/start", base + "/enroll/finish", base + "/server-chain"},
		Exempt:         msgsig.Paths{base + "/update/bundle/", base + "/probe/"},
		PendingAllowed: msgsig.Paths{base + "/enroll/result"},
	})
	must(t, err)
	r := chi.NewRouter()
	agentapi.HandlerFromMuxWithBaseURL(s, r, base)
	bind := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if id, ok := link.PeerAgentID(r.Context()); ok {
				r = r.WithContext(msgsig.WithTLSPeerAgentID(r.Context(), id))
			}
			if err := link.PeerCertError(r.Context()); err != nil {
				f := msgsig.TLSPeerInvalid
				if errors.Is(err, link.ErrRevoked) {
					f = msgsig.TLSPeerRevoked
				}
				r = r.WithContext(msgsig.WithTLSPeerFailure(r.Context(), f))
			}
			next.ServeHTTP(w, r)
		})
	}
	signed := func(r *http.Request) bool {
		p := r.URL.Path
		return p != base+"/enroll/start" && p != base+"/enroll/finish" && p != base+"/server-chain"
	}
	s.handler = s.verifier.DeferringMiddleware(signed, bind(mw.Wrap(r)))
	return s
}

func newCA(t testing.TB, name string) *pki.CA {
	ca, err := pki.NewCA(pki.CAOptions{Subject: pkix.Name{CommonName: name}})
	must(t, err)
	return ca
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// Start listens on loopback (connect mode).
func (s *Server) Start() {
	tc, err := link.ServerTLSConfig(func() (*tls.Certificate, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.intercepted != nil {
			return s.intercepted, nil
		}
		c := s.tlsCert
		return &c, nil
	}, s.verifier)
	must(s.t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(s.t, err)
	srv := &http.Server{Handler: s.handler, TLSConfig: tc, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	s.t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		srv.Close()
	})
	s.URL = "https://" + ln.Addr().String()
}

// SetIntercept makes the TLS listener present a certificate of another CA,
// as a TLS inspection device would. Signatures still use the Agent TLS key.
func (s *Server) SetIntercept() *x509.Certificate {
	key, err := pki.GenerateKey()
	must(s.t, err)
	cert, err := s.InterceptCA.IssueServer(key.Public(), pki.LeafOptions{DNSNames: []string{ServerName}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}})
	must(s.t, err)
	c := pki.TLSCertificate([]*x509.Certificate{cert, s.InterceptCA.Cert}, key)
	s.mu.Lock()
	s.intercepted = &c
	s.mu.Unlock()
	return cert
}

// Dial connects to a listen-mode agent at addr and serves it until ctx
// ends, reconnecting after failures.
func (s *Server) Dial(ctx context.Context, addr func() string) {
	go func() {
		for ctx.Err() == nil {
			a := addr()
			if a != "" {
				_ = link.DialReverse(ctx, a, link.ReverseDialConfig{
					ClientCertificate: func() (*tls.Certificate, error) { c := s.ClientCert; return &c, nil },
					VerifyAgent:       s.verifier.VerifyReverse,
				}, s.handler)
			}
			select {
			case <-ctx.Done():
			case <-time.After(30 * time.Millisecond):
			}
		}
	}()
}

func (s *Server) changed() {
	close(s.cond)
	s.cond = make(chan struct{})
}

// ── test controls ──────────────────────────────────────────────────────

// Approve approves a pending agent.
func (s *Server) Approve(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents[id].State = msgsig.StateApproved
}

// Revoke revokes an agent: its state and its certificates, as the server
// does.
func (s *Server) Revoke(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.agents[id]
	a.State = msgsig.StateRevoked
	if s.revokedCerts == nil {
		s.revokedCerts = map[string]bool{}
	}
	if a.Cert != nil {
		s.revokedCerts[a.Cert.SerialNumber.String()] = true
	}
}

// Requests counts the signed requests that reached msgsig.
func (s *Server) Requests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

func (s *Server) certRevoked(serial *big.Int) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revokedCerts[serial.String()], nil
}

// Agents returns copies of the enrolled agents.
func (s *Server) Agents() []Agent {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Agent
	for i := 1; i <= s.nextID; i++ {
		if a, ok := s.agents[agentID(i)]; ok {
			c := *a
			c.Counters = append([]uint64(nil), a.Counters...)
			out = append(out, c)
		}
	}
	return out
}

// EnrollResultRequests counts GET /enroll/result requests.
func (s *Server) EnrollResultRequests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enrollGets
}

// Bodies returns the raw enrollment request bodies.
func (s *Server) Bodies() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append(append([][]byte(nil), s.startBodies...), s.finishBodies...)
}

// Polls returns the poll requests received.
func (s *Server) Polls() []dto.PollRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]dto.PollRequest(nil), s.polls...)
}

// Reports returns the reports received.
func (s *Server) Reports() []*report.Report {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*report.Report(nil), s.reports...)
}

// SetUploadFail makes report uploads fail with 503.
func (s *Server) SetUploadFail(v bool) {
	s.mu.Lock()
	s.uploadFail = v
	s.mu.Unlock()
}

// SetPollFail makes polls fail with 503, as if the server were unreachable.
func (s *Server) SetPollFail(v bool) {
	s.mu.Lock()
	s.pollFail = v
	s.mu.Unlock()
}

// SetConfig replaces the configuration sent in poll responses.
func (s *Server) SetConfig(f func(*dto.AgentConfig)) {
	s.mu.Lock()
	f(&s.config)
	s.changed()
	s.mu.Unlock()
}

// Queue adds a directive (any JSON object with id and type).
func (s *Server) Queue(d any) {
	b, err := json.Marshal(d)
	must(s.t, err)
	s.mu.Lock()
	s.directives = append(s.directives, b)
	s.changed()
	s.mu.Unlock()
}

// Acked reports whether a directive id was acknowledged.
func (s *Server) Acked(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.acked[id]
}

// SetBundle sets the trust bundle serial and additional anchors.
func (s *Server) SetBundle(serial int64, extra ...*x509.Certificate) {
	s.mu.Lock()
	s.bundleSerial = serial
	s.extraAnchors = extra
	s.mu.Unlock()
}

// SetUpdate sets the deployed release.
func (s *Server) SetUpdate(u *Update) {
	s.mu.Lock()
	s.update = u
	s.mu.Unlock()
}

// CounterOf returns the last accepted counter of an agent.
func (s *Server) CounterOf(id string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.agents[id]
	if a == nil || len(a.Counters) == 0 {
		return 0
	}
	return a.Counters[len(a.Counters)-1]
}

// ── msgsig callbacks ───────────────────────────────────────────────────

func (s *Server) keyLookup(ctx context.Context, id string) (msgsig.AgentKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests++
	a, ok := s.agents[id]
	if !ok {
		return msgsig.AgentKey{}, msgsig.ErrUnknownAgent
	}
	return msgsig.AgentKey{PublicKey: a.Pub, State: a.State, RequireTLSClientCert: !a.Relaxed && a.State == msgsig.StateApproved && a.Cert != nil}, nil
}

func (s *Server) advance(_ context.Context, id string, n uint64) (uint64, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agents[id]
	if !ok {
		return 0, false, msgsig.ErrUnknownAgent
	}
	var cur uint64
	if len(a.Counters) > 0 {
		cur = a.Counters[len(a.Counters)-1]
	}
	if n <= cur {
		return cur, false, nil
	}
	a.Counters = append(a.Counters, n)
	return n, true, nil
}

// ── helpers ────────────────────────────────────────────────────────────

func agentID(n int) string { return "agent-" + strconv.Itoa(n) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func writeErr(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, dto.Error{Code: code, Message: code})
}

func randID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) currentAgent(r *http.Request) (*Agent, bool) {
	a, ok := msgsig.AgentFromContext(r.Context())
	if !ok {
		return nil, false
	}
	ag, ok := s.agents[a.ID]
	return ag, ok
}

// issue issues a certificate for the agent's current CSR; s.mu is held.
func (s *Server) issue(a *Agent) {
	cert, err := s.AgentCA.IssueAgent(a.CSR, a.ID, pki.AgentOptions{NotBefore: s.opts.CertNotBefore, Lifetime: s.opts.CertLifetime})
	must(s.t, err)
	a.Cert = cert
}

func (s *Server) bundle() dto.TrustBundle {
	tb := dto.TrustBundle{Serial: s.bundleSerial, AgentCas: [][]byte{s.AgentCA.Cert.Raw}, Anchors: [][]byte{s.TLSCA.Cert.Raw}, IssuedAt: time.Now().UTC()}
	for _, c := range s.extraAnchors {
		tb.Anchors = append(tb.Anchors, c.Raw)
	}
	return tb
}

// result builds the enrollment result; s.mu is held.
func (s *Server) result(a *Agent) dto.EnrollResult {
	if a.State != msgsig.StateApproved {
		one := 1
		return dto.EnrollResult{Status: dto.EnrollStatusPending, AgentId: a.ID, RetryAfterSeconds: &one}
	}
	if a.Cert == nil {
		s.issue(a)
	}
	cert, ca, tb := a.Cert.Raw, s.AgentCA.Cert.Raw, s.bundle()
	return dto.EnrollResult{Status: dto.EnrollStatusApproved, AgentId: a.ID, Certificate: &cert, AgentCa: &ca, TrustBundle: &tb}
}

// ── handlers ───────────────────────────────────────────────────────────

var _ agentapi.ServerInterface = (*Server)(nil)

func (s *Server) EnrollStart(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var req dto.EnrollStartRequest
	if err := json.Unmarshal(body, &req); err != nil || req.KeyId != s.Token.KeyID.String() {
		writeErr(w, http.StatusForbidden, "enrollment_refused")
		return
	}
	csr, err := pki.ParseAgentCSR(req.Csr)
	if err != nil {
		writeErr(w, http.StatusForbidden, "enrollment_refused")
		return
	}
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	sess := dto.EnrollSession{SessionId: randID(), ServerNonce: nonce, ServerChain: [][]byte{s.Leaf.Raw, s.TLSCA.Cert.Raw}}
	resp, _ := json.Marshal(sess)
	tr := enroll.NewTranscript(body, resp)
	sig, err := enroll.SignServerStart(s.LeafKey, tr)
	must(s.t, err)
	s.mu.Lock()
	s.startBodies = append(s.startBodies, body)
	s.sessions[sess.SessionId] = session{tr: tr, csr: csr, req: req}
	s.mu.Unlock()
	w.Header().Set(enroll.HeaderSignature, sig)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(resp)
}

func (s *Server) EnrollFinish(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var req dto.EnrollFinishRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finishBodies = append(s.finishBodies, body)
	sess, ok := s.sessions[req.SessionId]
	delete(s.sessions, req.SessionId)
	if !ok || enroll.VerifyAgent(s.Token.PublicKey(), sess.tr, req.Signature) != nil {
		writeErr(w, http.StatusForbidden, "enrollment_refused")
		return
	}
	s.nextID++
	a := &Agent{
		ID:      agentID(s.nextID),
		Pub:     sess.csr.PublicKey.(ed25519.PublicKey),
		CSR:     sess.csr,
		State:   msgsig.StateApproved,
		Relaxed: sess.req.TlsMode != dto.Pinned,
	}
	if s.opts.ManualApproval {
		a.State = msgsig.StatePending
	}
	s.agents[a.ID] = a
	resp, _ := json.Marshal(s.result(a))
	sig, err := enroll.SignResult(s.LeafKey, sess.tr, resp)
	must(s.t, err)
	w.Header().Set(enroll.HeaderSignature, sig)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(resp)
}

func (s *Server) GetEnrollResult(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enrollGets++
	a, ok := s.currentAgent(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, s.result(a))
}

func (s *Server) RenewCert(w http.ResponseWriter, r *http.Request) {
	var req dto.CertRenewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.currentAgent(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if req.Csr != nil {
		csr, err := pki.ParseAgentCSR(*req.Csr)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request")
			return
		}
		a.CSR = csr
		a.Pub = csr.PublicKey.(ed25519.PublicKey)
	}
	s.issue(a)
	a.Renewals++
	writeJSON(w, http.StatusOK, dto.RenewedCert{Certificate: a.Cert.Raw, AgentCa: s.AgentCA.Cert.Raw, NotAfter: a.Cert.NotAfter})
}

func (s *Server) GetServerChain(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, dto.ServerChain{ChainPem: []string{
		string(pki.EncodeCertificatesPEM(s.Leaf)), string(pki.EncodeCertificatesPEM(s.TLSCA.Cert)),
	}})
}

func (s *Server) GetTrustBundle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, http.StatusOK, s.bundle())
}

func (s *Server) Poll(w http.ResponseWriter, r *http.Request) {
	var req dto.PollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.mu.Lock()
		s.pollErrs++
		s.mu.Unlock()
		writeErr(w, http.StatusBadRequest, "invalid_request")
		return
	}
	s.mu.Lock()
	if s.pollFail {
		s.mu.Unlock()
		writeErr(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	a, _ := s.currentAgent(r)
	s.polls = append(s.polls, req)
	if req.AckedDirectives != nil {
		for _, id := range *req.AckedDirectives {
			s.acked[id] = true
		}
	}
	pending := s.pendingDirectives()
	wait := s.cond
	s.mu.Unlock()
	if len(pending) == 0 {
		select {
		case <-wait:
		case <-time.After(s.opts.PollHold):
		case <-r.Context().Done():
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var last int64
	if a != nil && len(a.Counters) > 0 {
		last = int64(a.Counters[len(a.Counters)-1])
	}
	res := dto.PollResult{Config: s.config, LastCounter: last, ServerTime: time.Now().UTC(), Directives: []dto.Directive{}}
	for _, raw := range s.pendingDirectives() {
		var d dto.Directive
		must(s.t, d.UnmarshalJSON(raw))
		res.Directives = append(res.Directives, d)
	}
	writeJSON(w, http.StatusOK, res)
}

// pendingDirectives returns unacknowledged directives; s.mu is held.
func (s *Server) pendingDirectives() []json.RawMessage {
	var out []json.RawMessage
	for _, raw := range s.directives {
		var h struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(raw, &h)
		if !s.acked[h.ID] {
			out = append(out, raw)
		}
	}
	return out
}

func (s *Server) UploadReport(w http.ResponseWriter, r *http.Request, params dto.UploadReportParams) {
	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	fail := s.uploadFail
	s.mu.Unlock()
	if fail {
		writeErr(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	rep, err := report.Decode(bytes.NewReader(body))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_report")
		return
	}
	if rep.Subject == nil || rep.Subject.Kind != report.SubjectSelf || len(rep.Cache) != 0 {
		writeErr(w, http.StatusBadRequest, "invalid_subject")
		return
	}
	s.mu.Lock()
	s.reports = append(s.reports, rep)
	n := len(s.reports)
	s.changed()
	s.mu.Unlock()
	writeJSON(w, http.StatusAccepted, dto.ReportAccepted{ReportId: fmt.Sprintf("report-%d", n)})
}

func (s *Server) CheckUpdate(w http.ResponseWriter, r *http.Request, params dto.CheckUpdateParams) {
	s.mu.Lock()
	u := s.update
	s.mu.Unlock()
	res := dto.UpdateCheck{CheckIntervalMinutes: 60}
	if u != nil {
		v := u.Version
		size := int64(len(u.Bundle))
		res.TargetVersion = &v
		res.Manifest = &u.Manifest
		res.ManifestSignature = &u.Sig
		res.BundleSize = &size
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) DownloadUpdateBundle(w http.ResponseWriter, r *http.Request, version string, params dto.DownloadUpdateBundleParams) {
	s.mu.Lock()
	u := s.update
	s.mu.Unlock()
	if u == nil || u.Version != version {
		writeErr(w, http.StatusNotFound, "not_found")
		return
	}
	w.Header().Set("Content-Type", "application/x-tar")
	_, _ = w.Write(u.Bundle)
}

func (s *Server) UploadK8sInventory(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
}

func (s *Server) DownloadProbe(w http.ResponseWriter, r *http.Request, os dto.TargetOs, arch dto.TargetArch) {
	w.WriteHeader(http.StatusNotImplemented)
}

func (s *Server) SubmitScanJobResult(w http.ResponseWriter, r *http.Request, id string) {
	w.WriteHeader(http.StatusNotImplemented)
}

// ErrTimeout is returned by Wait.
var ErrTimeout = errors.New("fakeserver: condition not met in time")

// Wait polls cond until it holds or timeout passes.
func Wait(timeout time.Duration, cond func() bool) error {
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			return ErrTimeout
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil
}
