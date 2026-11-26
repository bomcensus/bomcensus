// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package agentapi

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/bomcensus/bomcensus/internal/enroll"

	"github.com/bomcensus/bomcensus/agentproto/dto"
	"github.com/bomcensus/bomcensus/internal/link"
	"github.com/bomcensus/bomcensus/internal/msgsig"
	"github.com/bomcensus/bomcensus/internal/pki"
	"github.com/bomcensus/bomcensus/internal/server/dispatch"
	"github.com/bomcensus/bomcensus/internal/server/enrollsvc"
	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/internal/server/store/postgres"
	"github.com/bomcensus/bomcensus/internal/token"
	"github.com/bomcensus/bomcensus/server/scope"
)

const testServerName = "agents.test"

// newTestDB creates a fresh database from BOMCENSUS_TEST_DATABASE_URL,
// applies the migrations and drops it when the test ends. The test is
// skipped when the variable is unset.
func newTestDB(t testing.TB) *postgres.DB {
	t.Helper()
	base := os.Getenv("BOMCENSUS_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("BOMCENSUS_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(scope.System(context.Background()), time.Minute)
	defer cancel()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	name := "bomcensus_test_" + hex.EncodeToString(b[:])
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		admin.Close(ctx)
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(scope.System(context.Background()), time.Minute)
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			t.Errorf("drop database: %v", err)
		}
		admin.Close(ctx)
	})
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	u.Path = "/" + name
	db, err := postgres.Open(ctx, u.String())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(db.Close)
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// fakePKI implements PKI with internal/pki directly.
type fakePKI struct {
	st      store.Store
	tlsCA   *pki.CA
	pin     [32]byte
	server  tls.Certificate
	key     crypto.Signer
	chain   []*x509.Certificate
	client  tls.Certificate
	agentCA *pki.CA
	pending *pki.CA // prepared anchor, when set

	mu            sync.Mutex
	bundleVersion uint64
}

func newFakePKI(t *testing.T, st store.Store) *fakePKI {
	t.Helper()
	newCA := func(name string) *pki.CA {
		ca, err := pki.NewCA(pki.CAOptions{Subject: pkix.Name{CommonName: name}})
		if err != nil {
			t.Fatal(err)
		}
		return ca
	}
	p := &fakePKI{st: st, tlsCA: newCA("Agent TLS CA"), agentCA: newCA("Agent CA"), bundleVersion: 1}
	p.pin = pki.SPKIHash(p.tlsCA.Cert)
	leaf := func(client bool) (tls.Certificate, crypto.Signer, []*x509.Certificate) {
		key, err := pki.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		opts := pki.LeafOptions{DNSNames: []string{testServerName}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
		var cert *x509.Certificate
		if client {
			cert, err = p.tlsCA.IssueClient(key.Public(), opts)
		} else {
			cert, err = p.tlsCA.IssueServer(key.Public(), opts)
		}
		if err != nil {
			t.Fatal(err)
		}
		chain := []*x509.Certificate{cert, p.tlsCA.Cert}
		return pki.TLSCertificate(chain, key), key, chain
	}
	p.server, p.key, p.chain = leaf(false)
	p.client, _, _ = leaf(true)
	return p
}

func (p *fakePKI) Signer() (crypto.Signer, []*x509.Certificate) { return p.key, p.chain }

func (p *fakePKI) IssueAgentCertificate(ctx context.Context, csrDER []byte, agentID string) (*x509.Certificate, error) {
	csr, err := pki.ParseAgentCSR(csrDER)
	if err != nil {
		return nil, err
	}
	cert, err := p.agentCA.IssueAgent(csr, agentID, pki.AgentOptions{})
	if err != nil {
		return nil, err
	}
	if err := p.st.InsertAgentCert(ctx, store.AgentCert{Serial: cert.SerialNumber.Text(16), AgentID: agentID,
		NotBefore: cert.NotBefore, NotAfter: cert.NotAfter}); err != nil {
		return nil, err
	}
	return cert, nil
}

func (p *fakePKI) AgentCA() (*x509.Certificate, error) { return p.agentCA.Cert, nil }

func (p *fakePKI) TrustBundle() (*pki.TrustBundle, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	anchors := []*x509.Certificate{p.tlsCA.Cert}
	if p.pending != nil {
		anchors = append(anchors, p.pending.Cert)
	}
	return &pki.TrustBundle{Version: p.bundleVersion, Anchors: anchors, AgentCA: p.agentCA.Cert}, nil
}

func (p *fakePKI) setBundleVersion(v uint64) {
	p.mu.Lock()
	p.bundleVersion = v
	p.mu.Unlock()
}

func (p *fakePKI) AgentServerCertificate() (*tls.Certificate, error) { return &p.server, nil }
func (p *fakePKI) AgentClientCertificate() (*tls.Certificate, error) { return &p.client, nil }

func (p *fakePKI) IsAgentCertRevoked(ctx context.Context, serial *big.Int) (bool, error) {
	revoked, err := p.st.IsAgentCertRevoked(ctx, serial.Text(16))
	if errors.Is(err, store.ErrNotFound) {
		return true, nil
	}
	return revoked, err
}

// fakeIngest records what it receives.
type fakeIngest struct {
	mu      sync.Mutex
	reports []submitted
}

type submitted struct {
	sender store.Agent
	jobID  string
	raw    []byte
}

func (f *fakeIngest) Submit(_ context.Context, sender store.Agent, jobID string, raw []byte) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, submitted{sender, jobID, append([]byte(nil), raw...)})
	return fmt.Sprintf("report-%d", len(f.reports)), nil
}

func (f *fakeIngest) IngestK8sInventory(context.Context, store.Agent, dto.K8sInventory) error {
	return nil
}

func (f *fakeIngest) RecordScanResult(context.Context, store.Agent, string, dto.ScanJobResult) error {
	return nil
}

func (f *fakeIngest) all() []submitted {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]submitted(nil), f.reports...)
}

// env is one server installation serving on loopback.
type env struct {
	db       *postgres.DB
	pki      *fakePKI
	ingest   *fakeIngest
	dispatch *dispatch.Service
	enroll   *enrollsvc.Service
	handler  http.Handler
	url      string
}

type envOpts struct {
	pollTimeout time.Duration
	maxFailures int
	detectors   DetectorTables
}

func newEnv(t *testing.T, o envOpts) *env {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if testing.Verbose() {
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	e := &env{db: newTestDB(t), ingest: &fakeIngest{}}
	e.pki = newFakePKI(t, e.db)
	var err error
	e.enroll, err = enrollsvc.New(enrollsvc.Options{Store: e.db, PKI: e.pki, Logger: log, MaxFailures: o.maxFailures})
	if err != nil {
		t.Fatal(err)
	}
	e.dispatch = dispatch.New(e.db)
	if o.pollTimeout == 0 {
		o.pollTimeout = 1500 * time.Millisecond
	}
	e.handler, err = NewHandler(Options{
		Store: e.db, PKI: e.pki, Enroll: e.enroll, Dispatch: e.dispatch, Ingest: e.ingest, Logger: log,
		PollTimeout: o.pollTimeout, PollRecheck: 300 * time.Millisecond, Detectors: o.detectors,
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(scope.System(context.Background()))
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, ln, ServeOptions{Handler: e.handler, Certificate: e.pki.AgentServerCertificate,
			Verifier: NewAgentVerifier(e.pki), ShutdownTimeout: time.Second, Logger: log})
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	e.url = "https://" + ln.Addr().String()
	return e
}

// newKey stores a Register Key and returns its enrollment token.
func (e *env) newKey(t *testing.T, mod func(*store.RegisterKey)) token.Token {
	t.Helper()
	tok, err := token.New(e.pki.pin)
	if err != nil {
		t.Fatal(err)
	}
	k := store.RegisterKey{
		ID: tok.KeyID.String(), Name: "test", PublicKey: tok.PublicKey(), Target: store.AgentKindAgent,
		Approval: store.ApprovalAuto, DefaultGroup: "web", DefaultTags: []string{"prod"},
	}
	if mod != nil {
		mod(&k)
	}
	if _, err := e.db.CreateRegisterKey(scope.System(context.Background()), k); err != nil {
		t.Fatal(err)
	}
	return tok
}

// memCounter is an in-memory msgsig.CounterSource.
type memCounter struct {
	mu sync.Mutex
	n  uint64
}

func (c *memCounter) Next(context.Context) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return c.n, nil
}

func (c *memCounter) Observe(_ context.Context, last uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if last > c.n {
		c.n = last
	}
	return nil
}

func (c *memCounter) value() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// fixedCounter always returns the same value.
type fixedCounter uint64

func (c fixedCounter) Next(context.Context) (uint64, error)  { return uint64(c), nil }
func (c fixedCounter) Observe(context.Context, uint64) error { return nil }

// serverKeys resolves the one server signing key of the test.
type serverKeys map[string]crypto.PublicKey

func (k serverKeys) ServerKey(_ context.Context, id string) (crypto.PublicKey, error) {
	if pub, ok := k[id]; ok {
		return pub, nil
	}
	return nil, fmt.Errorf("unknown server key %s", id)
}

// agentClient is the agent side built from enroll, link and msgsig.
type agentClient struct {
	e           *env
	tok         token.Token
	key         ed25519.PrivateKey
	kind        dto.AgentKind
	connectMode dto.ConnectMode
	base        string // URL prefix
	// rt carries enrollment requests: a connect transport without client
	// certificate, or a ReverseHolder.
	rt http.RoundTripper

	id      string
	leaf    *x509.Certificate
	cert    *tls.Certificate
	counter *memCounter
	signed  *http.Client
}

func (e *env) newAgent(t *testing.T, tok token.Token) *agentClient {
	t.Helper()
	key, err := pki.GenerateAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	c := &agentClient{e: e, tok: tok, key: key, kind: dto.Agent, connectMode: dto.Connect, base: e.url, counter: &memCounter{}}
	cfg, err := link.ClientTLSConfig(link.ClientConfig{Mode: link.TLSPinned, Verify: link.PinnedVerifier(tok.CAHash, testServerName)})
	if err != nil {
		t.Fatal(err)
	}
	c.rt = link.NewConnectTransport(cfg, link.ConnectOptions{})
	return c
}

func (c *agentClient) startBody(t *testing.T) []byte {
	t.Helper()
	csr, err := pki.CreateAgentCSR(c.key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	req := dto.EnrollStartRequest{
		KeyId: c.tok.KeyID.String(), AgentNonce: nonce, Csr: csr, Kind: c.kind, Version: "1.0.0",
		Host:        dto.HostFacts{Hostname: "node-1", Arch: "amd64", Os: dto.OsRelease{Family: "linux"}},
		ConnectMode: c.connectMode, TlsMode: dto.Pinned,
	}
	if c.connectMode == dto.Listen {
		la := ":7443"
		req.ListenAddress = &la
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// post sends a raw request on the enrollment transport.
func (c *agentClient) post(t *testing.T, path string, body []byte) (int, []byte, http.Header) {
	t.Helper()
	ctx, cancel := context.WithTimeout(scope.System(context.Background()), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Transport: c.rt}).Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, b, resp.Header
}

// enrollment is the outcome of the enrollment exchange as the agent sees it.
type enrollment struct {
	startStatus  int
	finishStatus int
	finishBody   []byte // the exact finish request body, for replays
	result       dto.EnrollResult
	errorCode    string
}

// enroll runs start and finish and verifies the server signatures.
func (c *agentClient) enroll(t *testing.T) enrollment {
	t.Helper()
	var out enrollment
	startReq := c.startBody(t)
	status, startResp, h := c.post(t, "/agent/v1/enroll/start", startReq)
	out.startStatus = status
	if status != http.StatusOK {
		out.errorCode = errorCode(t, startResp)
		return out
	}
	var sess dto.EnrollSession
	if err := json.Unmarshal(startResp, &sess); err != nil {
		t.Fatal(err)
	}
	chain, err := pki.ParseChain(sess.ServerChain)
	if err != nil {
		t.Fatal(err)
	}
	tr := enroll.NewTranscript(startReq, startResp)
	leaf, err := enroll.VerifyServerStart(chain, c.tok.CAHash, testServerName, tr, h.Get(enroll.HeaderSignature))
	if err != nil {
		t.Fatalf("verify start: %v", err)
	}
	c.leaf = leaf
	sig, err := enroll.SignAgent(c.tok.PrivateKey(), tr)
	if err != nil {
		t.Fatal(err)
	}
	out.finishBody, _ = json.Marshal(dto.EnrollFinishRequest{SessionId: sess.SessionId, Signature: sig})
	status, finResp, h := c.post(t, "/agent/v1/enroll/finish", out.finishBody)
	out.finishStatus = status
	if status != http.StatusOK {
		out.errorCode = errorCode(t, finResp)
		return out
	}
	if err := enroll.VerifyResult(leaf, tr, finResp, h.Get(enroll.HeaderSignature)); err != nil {
		t.Fatalf("verify result: %v", err)
	}
	if err := json.Unmarshal(finResp, &out.result); err != nil {
		t.Fatal(err)
	}
	c.id = out.result.AgentId
	if out.result.Certificate != nil {
		c.setCert(t, *out.result.Certificate)
	}
	return out
}

func (c *agentClient) setCert(t *testing.T, der []byte) {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	tc := pki.TLSCertificate([]*x509.Certificate{cert}, c.key)
	c.cert = &tc
}

// connectSigned builds the signed client for connect mode, presenting the
// agent certificate when there is one.
func (c *agentClient) connectSigned(t *testing.T) {
	t.Helper()
	cfg, err := link.ClientTLSConfig(link.ClientConfig{
		Mode:   link.TLSPinned,
		Verify: link.PinnedVerifier(c.tok.CAHash, testServerName),
		ClientCertificate: func() (*tls.Certificate, error) {
			return c.cert, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	c.useSigned(link.NewConnectTransport(cfg, link.ConnectOptions{}), c.counter)
}

func (c *agentClient) useSigned(base http.RoundTripper, counter msgsig.CounterSource) {
	c.signed = &http.Client{Transport: &msgsig.Transport{
		Base: base, AgentID: c.id, Key: c.key, Counter: counter,
		ServerKeys: serverKeys{msgsig.KeyID(c.leaf): c.leaf.PublicKey},
		Exempt:     exemptPaths,
	}}
}

func (c *agentClient) do(t *testing.T, method, path string, body []byte) (*http.Response, []byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(scope.System(context.Background()), 15*time.Second)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.signed.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp, b, err
}

func (c *agentClient) pollBody(t *testing.T, acks []string, bundleSerial int64) []byte {
	t.Helper()
	req := dto.PollRequest{
		Version: "1.0.0", Os: dto.Linux, Arch: dto.Amd64, ConnectMode: c.connectMode, TlsMode: dto.Pinned,
		Privilege:         dto.Privilege{Level: dto.PrivilegeLevel("non_root"), Uid: 1000},
		SectionDigests:    map[string]string{},
		TrustBundleSerial: bundleSerial,
		Update:            dto.UpdateStatus{State: dto.UpdateStateUpToDate},
	}
	if acks != nil {
		req.AckedDirectives = &acks
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// poll sends one poll and decodes a 200 answer.
func (c *agentClient) poll(t *testing.T, acks []string) dto.PollResult {
	t.Helper()
	resp, body, err := c.do(t, http.MethodPost, "/agent/v1/poll", c.pollBody(t, acks, 1))
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("poll: status %d: %s", resp.StatusCode, body)
	}
	var res dto.PollResult
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatal(err)
	}
	return res
}

func errorCode(t *testing.T, b []byte) string {
	t.Helper()
	var e dto.Error
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatalf("error body %q: %v", b, err)
	}
	return e.Code
}

func directiveIDs(t *testing.T, ds []dto.Directive) (ids, types []string) {
	t.Helper()
	for _, d := range ds {
		typ, err := d.Discriminator()
		if err != nil {
			t.Fatal(err)
		}
		var v struct {
			ID string `json:"id"`
		}
		raw, _ := d.MarshalJSON()
		_ = json.Unmarshal(raw, &v)
		ids, types = append(ids, v.ID), append(types, typ)
	}
	return ids, types
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
