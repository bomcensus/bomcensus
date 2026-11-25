// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	agentgen "github.com/bomcensus/bomcensus/agentproto/dto"
	admingen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/pki"
	"github.com/bomcensus/bomcensus/internal/server/console"
	"github.com/bomcensus/bomcensus/internal/server/session"
	"github.com/bomcensus/bomcensus/internal/token"
	"github.com/bomcensus/bomcensus/internal/version"
	"github.com/bomcensus/bomcensus/server/config"
	"github.com/bomcensus/bomcensus/server/scope"
)

const testPassword = "correct horse battery staple"

var (
	hashOnce sync.Once
	testHash string
)

func adminHash(t *testing.T) string {
	hashOnce.Do(func() {
		h, err := session.HashPassword(testPassword)
		if err != nil {
			t.Fatal(err)
		}
		testHash = h
	})
	return testHash
}

func newMasterKey(t *testing.T) string {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k[:])
}

// testConfig is the configuration of a server on loopback ports chosen by
// the kernel, with plain HTTP on the console listener.
func testConfig(t *testing.T, dbURL, masterKey string) config.Config {
	env := map[string]string{
		config.EnvDatabaseURL:       dbURL,
		config.EnvAdminUser:         "admin",
		config.EnvAdminPasswordHash: adminHash(t),
		config.EnvWebListen:         "127.0.0.1:0",
		config.EnvWebTLS:            "off",
		config.EnvAgentListen:       "127.0.0.1:0",
		config.EnvAgentServerNames:  "localhost,127.0.0.1",
		config.EnvMasterKey:         masterKey,
		config.EnvLogLevel:          "debug",
	}
	cfg, err := config.Parse(func(k string) (string, bool) { v, ok := env[k]; return v, ok }, "test-host", config.Serve)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// syncBuffer collects the server log.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type testServer struct {
	addrs  Addrs
	cancel context.CancelFunc
	done   chan error
	log    *syncBuffer
}

// startServer runs Run in the background and waits until it listens.
func startServer(t *testing.T, cfg config.Config) *testServer {
	t.Helper()
	s, err := start(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// offlineFeed fails every request to a feed server.
type offlineFeed struct{}

func (offlineFeed) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("feed servers are not reachable in tests")
}

// start is startServer for any goroutine: it reports instead of failing.
func start(t *testing.T, cfg config.Config) (*testServer, error) {
	return startWith(t, cfg, Options{Session: &Session{}, Console: consoleFS()})
}

// consoleFS is the console the server binary serves.
func consoleFS() fs.FS {
	f, _ := console.FS()
	return f
}

// startWith is start with options; Ready and ShutdownTimeout are set here.
func startWith(t *testing.T, cfg config.Config, opts Options) (*testServer, error) {
	ctx, cancel := context.WithCancel(scope.System(context.Background()))
	s := &testServer{cancel: cancel, done: make(chan error, 1), log: &syncBuffer{}}
	ready := make(chan Addrs, 1)
	logger := slog.New(slog.NewTextHandler(s.log, &slog.HandlerOptions{Level: slog.LevelDebug}))
	go func() {
		opts.Ready = func(a Addrs) { ready <- a }
		opts.ShutdownTimeout = 5 * time.Second
		if opts.FeedTransport == nil {
			// Tests never contact the real feed server.
			opts.FeedTransport = offlineFeed{}
		}
		s.done <- Run(ctx, cfg, logger, opts)
	}()
	t.Cleanup(func() {
		cancel()
		if t.Failed() {
			t.Logf("server log:\n%s", s.log.String())
		}
	})
	select {
	case s.addrs = <-ready:
		return s, nil
	case err := <-s.done:
		cancel()
		return nil, fmt.Errorf("Run: %w", err)
	case <-time.After(time.Minute):
		cancel()
		return nil, errors.New("server did not start in time")
	}
}

// stop cancels the server and waits for Run to return.
func (s *testServer) stop(t *testing.T) {
	t.Helper()
	s.cancel()
	select {
	case err := <-s.done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("server did not shut down in time")
	}
}

type client struct {
	t    *testing.T
	http *http.Client
}

func newClient(t *testing.T) *client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &client{t: t, http: &http.Client{Jar: jar, Timeout: 30 * time.Second}}
	t.Cleanup(c.http.CloseIdleConnections)
	return c
}

// do sends a request; csrf adds the header the console sends with every
// state-changing request.
func (c *client) do(method, url string, body any, csrf bool) (int, []byte) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			c.t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		c.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if csrf {
		req.Header.Set(session.CSRFHeader, session.CSRFHeaderValue)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatal(err)
	}
	return resp.StatusCode, b
}

func (c *client) expect(method, url string, body any, csrf bool, status int) []byte {
	c.t.Helper()
	got, b := c.do(method, url, body, csrf)
	if got != status {
		c.t.Fatalf("%s %s: status %d, want %d: %s", method, url, got, status, b)
	}
	return b
}

// agentChain returns the certificate chain the agent listener presents.
func agentChain(t *testing.T, addr net.Addr) []*x509.Certificate {
	t.Helper()
	d := tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"}} //nolint:gosec // verified below with the pin
	ctx, cancel := context.WithTimeout(scope.System(context.Background()), 10*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		t.Fatalf("dial agent port: %v", err)
	}
	defer conn.Close()
	return conn.(*tls.Conn).ConnectionState().PeerCertificates
}

func TestRun(t *testing.T) {
	cfg := testConfig(t, newTestDatabase(t), newMasterKey(t))
	s1 := startServer(t, cfg)
	web := "http://" + s1.addrs.Web.String()
	c := newClient(t)

	// Health endpoints need no session.
	if b := c.expect("GET", web+PathHealthz, nil, false, http.StatusOK); string(b) != "ok\n" {
		t.Fatalf("healthz: %q", b)
	}
	c.expect("GET", web+PathReadyz, nil, false, http.StatusOK)

	// Login and the CSRF rules.
	c.expect("GET", web+"/api/v1/meta", nil, false, http.StatusUnauthorized)
	login := admingen.LoginRequest{Username: "admin", Password: testPassword}
	c.expect("POST", web+"/api/v1/auth/login", login, false, http.StatusForbidden)
	c.expect("POST", web+"/api/v1/auth/login", admingen.LoginRequest{Username: "admin", Password: "wrong"}, true, http.StatusUnauthorized)
	c.expect("POST", web+"/api/v1/auth/login", login, true, http.StatusOK)

	var meta admingen.Meta
	mustJSON(t, c.expect("GET", web+"/api/v1/meta", nil, false, http.StatusOK), &meta)
	if meta.Version != version.Version {
		t.Fatalf("meta version %q", meta.Version)
	}
	var assets admingen.AssetList
	mustJSON(t, c.expect("GET", web+"/api/v1/assets", nil, false, http.StatusOK), &assets)
	if assets.Total != 0 || assets.Items == nil || len(assets.Items) != 0 {
		t.Fatalf("assets: %+v", assets)
	}

	// The console (or its placeholder) is served outside the API.
	page := string(c.expect("GET", web+"/", nil, false, http.StatusOK))
	if _, built := console.FS(); !built && !strings.Contains(page, "was not built into this binary") {
		t.Fatalf("console placeholder not served: %q", page)
	}

	// A Register Key's enrollment string pins the Agent TLS anchor.
	create := admingen.RegisterKeyCreate{Name: "test", Approval: admingen.RegisterKeyApprovalAuto, Target: admingen.AgentKindAgent}
	c.expect("POST", web+"/api/v1/register-keys", create, false, http.StatusForbidden)
	var created admingen.RegisterKeyCreated
	mustJSON(t, c.expect("POST", web+"/api/v1/register-keys", create, true, http.StatusCreated), &created)
	tok, err := token.Parse(created.Enrollment)
	if err != nil {
		t.Fatalf("enrollment string %q: %v", created.Enrollment, err)
	}
	chain := agentChain(t, s1.addrs.Agent)
	if err := pki.VerifyPinned(chain, tok.CAHash, "localhost", x509.ExtKeyUsageServerAuth); err != nil {
		t.Fatalf("agent TLS chain does not verify against the enrollment pin: %v", err)
	}

	// The unauthenticated server chain is the same chain.
	served := serverChain(t, s1.addrs.Agent)
	if err := pki.VerifyPinned(served, tok.CAHash, "localhost", x509.ExtKeyUsageServerAuth); err != nil {
		t.Fatalf("server-chain: %v", err)
	}
	if !served[0].Equal(chain[0]) {
		t.Fatal("server-chain leaf differs from the agent listener certificate")
	}

	// A replica on the same database starts, reuses the CAs and shares the
	// sessions (the cookie jar ignores ports).
	s2 := startServer(t, cfg)
	c.expect("GET", "http://"+s2.addrs.Web.String()+PathReadyz, nil, false, http.StatusOK)
	chain2 := agentChain(t, s2.addrs.Agent)
	if err := pki.VerifyPinned(chain2, tok.CAHash, "localhost", x509.ExtKeyUsageServerAuth); err != nil {
		t.Fatalf("replica agent chain: %v", err)
	}
	if !chain2[len(chain2)-1].Equal(chain[len(chain)-1]) {
		t.Fatal("replica presents another anchor")
	}
	c.expect("GET", "http://"+s2.addrs.Web.String()+"/api/v1/auth/me", nil, false, http.StatusOK)

	if len(serverGoroutines()) == 0 {
		t.Fatal("the leak check does not see the running servers")
	}
	s2.stop(t)
	s1.stop(t)
	c.http.CloseIdleConnections()
	checkNoLeaks(t)

	for _, secret := range []string{cfg.MasterKey.Reveal(), cfg.AdminPasswordHash, cfg.DatabaseURL.Reveal(), testPassword, created.Enrollment} {
		for _, l := range []string{s1.log.String(), s2.log.String()} {
			if strings.Contains(l, secret) {
				t.Fatalf("log contains a secret: %q", secret)
			}
		}
	}
	if !strings.Contains(s1.log.String(), "bomcensus server started") {
		t.Fatal("no startup summary")
	}
}

// TestConcurrentStart starts several servers on an empty database at once:
// migrations and the PKI bootstrap must not race.
func TestConcurrentStart(t *testing.T) {
	cfg := testConfig(t, newTestDatabase(t), newMasterKey(t))
	const n = 3
	servers := make([]*testServer, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			s, err := start(t, cfg)
			if err != nil {
				t.Error(err)
				return
			}
			servers[i] = s
		})
	}
	wg.Wait()
	if t.Failed() {
		t.FailNow()
	}
	var anchor *x509.Certificate
	for _, s := range servers {
		chain := agentChain(t, s.addrs.Agent)
		top := chain[len(chain)-1]
		if anchor == nil {
			anchor = top
		} else if !top.Equal(anchor) {
			t.Fatal("servers present different anchors")
		}
	}
	for _, s := range servers {
		s.stop(t)
	}
	checkNoLeaks(t)
}

func TestRunRejectsBadMasterKey(t *testing.T) {
	cfg := config.Config{DatabaseURL: "postgres://unused", MasterKey: "c2hvcnQ="}
	err := Run(scope.System(context.Background()), cfg, nil, Options{})
	if err == nil || !strings.Contains(err.Error(), "master key") {
		t.Fatalf("Run: %v", err)
	}
}

func serverChain(t *testing.T, addr net.Addr) []*x509.Certificate {
	t.Helper()
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // verified by the caller with the pin
	}}
	defer hc.CloseIdleConnections()
	resp, err := hc.Get("https://" + addr.String() + "/agent/v1/server-chain")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("server-chain: %d %s", resp.StatusCode, b)
	}
	var sc agentgen.ServerChain
	mustJSON(t, b, &sc)
	var out []*x509.Certificate
	for _, p := range sc.ChainPem {
		blk, _ := pem.Decode([]byte(p))
		if blk == nil {
			t.Fatalf("bad PEM %q", p)
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, cert)
	}
	if len(out) == 0 {
		t.Fatal("empty server chain")
	}
	return out
}

func mustJSON(t *testing.T, b []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
}

// leakMarkers identify goroutines started by the server and its libraries.
var leakMarkers = []string{
	"github.com/bomcensus/bomcensus/",
	"github.com/riverqueue/",
	"github.com/jackc/",
	"net/http.",
	"golang.org/x/net/http2",
}

// checkNoLeaks waits until no goroutine of the server is left. The test's
// own goroutine and the testing framework's are ignored.
func checkNoLeaks(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		left := serverGoroutines()
		if len(left) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines left after shutdown:\n\n%s", len(left), strings.Join(left, "\n\n"))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func serverGoroutines() []string {
	buf := make([]byte, 4<<20)
	buf = buf[:runtime.Stack(buf, true)]
	var out []string
	for _, g := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(g, "testing.tRunner") || strings.Contains(g, "testing.(*T).Run") ||
			strings.Contains(g, "app.serverGoroutines") {
			continue
		}
		for _, m := range leakMarkers {
			if strings.Contains(g, m) {
				out = append(out, g)
				break
			}
		}
	}
	return out
}

// TestScanService runs the server with the scan service: an on-demand run
// of a scan target is accepted (not 503) and the embedded scanner records
// its outcome.
func TestScanService(t *testing.T) {
	cfg := testConfig(t, newTestDatabase(t), newMasterKey(t))
	if !cfg.EmbeddedScanner {
		t.Fatal("embedded scanner is off by default")
	}
	s, err := startWith(t, cfg, Options{Scans: ScanService, Session: &Session{}, Console: consoleFS()})
	if err != nil {
		t.Fatal(err)
	}
	web := "http://" + s.addrs.Web.String()
	c := newClient(t)
	c.expect("POST", web+"/api/v1/auth/login", admingen.LoginRequest{Username: "admin", Password: testPassword}, true, http.StatusOK)

	// A port nobody listens on: the scan fails at connect time.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	user, pw := "scan", "secret"
	var cred admingen.Credential
	mustJSON(t, c.expect("POST", web+"/api/v1/credentials", admingen.CredentialCreate{Name: "pw", Kind: admingen.CredentialKindSshPassword,
		Username: &user, Password: &pw}, true, http.StatusCreated), &cred)
	var target admingen.ScanTarget
	mustJSON(t, c.expect("POST", web+"/api/v1/scan-targets", admingen.ScanTargetCreate{Name: "closed", Address: "127.0.0.1",
		Port: &port, CredentialId: cred.Id}, true, http.StatusCreated), &target)
	c.expect("POST", web+"/api/v1/scan-targets/"+target.Id+"/run", nil, true, http.StatusAccepted)

	deadline := time.Now().Add(30 * time.Second)
	for {
		var list admingen.ScanTargetList
		mustJSON(t, c.expect("GET", web+"/api/v1/scan-targets", nil, false, http.StatusOK), &list)
		if len(list.Items) == 1 && list.Items[0].LastRun != nil {
			r := list.Items[0].LastRun
			if r.Result != admingen.ScanResultFailed || r.Message == nil || !strings.HasPrefix(*r.Message, "connect_failed") {
				t.Fatalf("last run %+v", r)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the scan was not recorded")
		}
		time.Sleep(100 * time.Millisecond)
	}
	s.stop(t)
}

func TestAgentAddress(t *testing.T) {
	cfg := config.Config{AgentListen: ":8443", AgentServerNames: []string{"bomcensus.example.com", "10.0.0.1"}}
	if got := agentAddress(cfg); got != "bomcensus.example.com:8443" {
		t.Fatalf("agent address %q", got)
	}
	cfg.AgentListen = "127.0.0.1:0"
	if got := agentAddress(cfg); got != "" {
		t.Fatalf("agent address with a kernel-chosen port %q", got)
	}
}
