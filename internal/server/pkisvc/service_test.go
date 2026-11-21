// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pkisvc

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/pki"
	"github.com/bomcensus/bomcensus/internal/server/secret"
	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/internal/server/store/postgres"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type env struct {
	db       *postgres.DB
	box      *secret.Box
	clock    *clock
	unsynced atomic.Int64
}

func newEnv(t *testing.T) *env {
	t.Helper()
	key := make([]byte, secret.KeySize)
	_, _ = rand.Read(key)
	box, err := secret.New(key)
	if err != nil {
		t.Fatal(err)
	}
	return &env{db: newTestDB(t), box: box, clock: &clock{t: time.Now()}}
}

func (e *env) service(t *testing.T, mutate func(*Config)) *Service {
	t.Helper()
	cfg := Config{
		Store:            e.db,
		Box:              e.box,
		WebTLS:           true,
		WebServerNames:   []string{"console.example", "127.0.0.1"},
		AgentServerNames: []string{"agents.example"},
		UnsyncedAgents:   func(context.Context) (int, error) { return int(e.unsynced.Load()), nil },
		LeafLifetime:     30 * 24 * time.Hour,
		Now:              e.clock.Now,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (e *env) bootstrap(t *testing.T) *Service {
	t.Helper()
	s := e.service(t, nil)
	if err := s.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

type tlsCert = tls.Certificate

func leafOf(t *testing.T, get func() (*tlsCert, error)) *x509.Certificate {
	t.Helper()
	c, err := get()
	if err != nil {
		t.Fatal(err)
	}
	return c.Leaf
}

func TestBootstrapConcurrent(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	const n = 4
	svcs := make([]*Service, n)
	for i := range svcs {
		svcs[i] = e.service(t, nil)
	}
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i, s := range svcs {
		wg.Go(func() { errs[i] = s.Bootstrap(ctx) })
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("replica %d: %v", i, err)
		}
	}
	objs, err := e.db.ListPKIObjects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{store.PKIAgentCA: true, store.PKIWebCA: true, store.PKIWebLeaf: true, store.PKIAgentTLSCA: true,
		ObjAgentTLSAnchor: true, store.PKIAgentTLSLeaf: true, store.PKIAgentTLSClient: true}
	if len(objs) != len(want) {
		t.Fatalf("%d objects, want %d", len(objs), len(want))
	}
	for _, o := range objs {
		if !want[o.Name] {
			t.Fatalf("unexpected object %s", o.Name)
		}
		if o.Version != 1 {
			t.Fatalf("%s has version %d: written more than once", o.Name, o.Version)
		}
	}
	h0, _ := svcs[0].AnchorHash()
	ca0, _ := svcs[0].AgentCA()
	web0 := leafOf(t, svcs[0].WebCertificate)
	for _, s := range svcs[1:] {
		// A replica that lost a race may have loaded before the winner's
		// leaf write; one refresh converges.
		if err := s.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
		h, _ := s.AnchorHash()
		ca, _ := s.AgentCA()
		if h != h0 || !ca.Equal(ca0) || !leafOf(t, s.WebCertificate).Equal(web0) {
			t.Fatal("replicas disagree")
		}
	}
	tlsCA, err := svcs[0].loadCA(ctx, e.db, store.PKIAgentTLSCA)
	if err != nil {
		t.Fatal(err)
	}
	if pki.SPKIHash(tlsCA.Cert) != h0 {
		t.Fatal("anchor is not the Agent TLS CA")
	}
	if tlsCA.Cert.Equal(ca0) {
		t.Fatal("Agent TLS CA and Agent CA are the same")
	}
}

func TestRestartReuses(t *testing.T) {
	e := newEnv(t)
	a := e.bootstrap(t)
	b := e.bootstrap(t)
	ha, _ := a.AnchorHash()
	hb, _ := b.AnchorHash()
	if ha != hb {
		t.Fatal("anchor changed on restart")
	}
	if !leafOf(t, a.AgentServerCertificate).Equal(leafOf(t, b.AgentServerCertificate)) ||
		!leafOf(t, a.AgentClientCertificate).Equal(leafOf(t, b.AgentClientCertificate)) ||
		!leafOf(t, a.WebCertificate).Equal(leafOf(t, b.WebCertificate)) {
		t.Fatal("leaf reissued on restart")
	}
}

func TestLeafNamesAndUsage(t *testing.T) {
	e := newEnv(t)
	s := e.bootstrap(t)
	web := leafOf(t, s.WebCertificate)
	if web.VerifyHostname("console.example") != nil || web.VerifyHostname("127.0.0.1") != nil {
		t.Fatalf("web names %v %v", web.DNSNames, web.IPAddresses)
	}
	b, err := s.TrustBundle()
	if err != nil {
		t.Fatal(err)
	}
	srv, _ := s.AgentServerCertificate()
	chain, _ := pki.ParseChain(srv.Certificate)
	if err := pki.VerifyAnchors(chain, b.Anchors, "agents.example", x509.ExtKeyUsageServerAuth); err != nil {
		t.Fatalf("server: %v", err)
	}
	h, _ := s.AnchorHash()
	if err := pki.VerifyPinned(chain, h, "agents.example", x509.ExtKeyUsageServerAuth); err != nil {
		t.Fatalf("server pinned: %v", err)
	}
	cl, _ := s.AgentClientCertificate()
	chain, _ = pki.ParseChain(cl.Certificate)
	if err := pki.VerifyPinned(chain, h, "agents.example", x509.ExtKeyUsageClientAuth); err != nil {
		t.Fatalf("client: %v", err)
	}
	key, signerChain := s.Signer()
	if !pki.KeyMatches(signerChain[0], key) || !signerChain[0].Equal(srv.Leaf) {
		t.Fatal("signer is not the agent server certificate")
	}
}

func TestLeafRenewal(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	s := e.bootstrap(t)
	web := leafOf(t, s.WebCertificate)
	agent := leafOf(t, s.AgentServerCertificate)

	e.clock.Advance(10 * 24 * time.Hour)
	if err := s.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	if !leafOf(t, s.WebCertificate).Equal(web) {
		t.Fatal("renewed too early")
	}

	e.clock.Advance(11 * 24 * time.Hour) // past two thirds of 30 days
	other := e.service(t, nil)
	if err := other.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	newWeb := leafOf(t, s.WebCertificate)
	if newWeb.Equal(web) || leafOf(t, s.AgentServerCertificate).Equal(agent) {
		t.Fatal("not renewed")
	}
	if !leafOf(t, other.WebCertificate).Equal(newWeb) {
		t.Fatal("replicas disagree after renewal")
	}
	o, _ := e.db.GetPKIObject(ctx, store.PKIWebLeaf)
	if o.Version != 2 {
		t.Fatalf("web leaf version %d, want one renewal", o.Version)
	}

	// Changed names reissue at once.
	renamed := e.service(t, func(c *Config) { c.AgentServerNames = []string{"agents.example", "agents2.example"} })
	if err := renamed.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	if leafOf(t, renamed.AgentServerCertificate).VerifyHostname("agents2.example") != nil {
		t.Fatal("names not applied")
	}
}

// testCA is an external CA standing in for a corporate one.
type testCA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	ca, err := pki.NewCA(pki.CAOptions{Subject: pkix.Name{CommonName: cn}})
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: ca.Cert, key: ca.Key}
}

// issue signs a leaf with the given usages and returns chain and key PEM.
func (c *testCA) issue(t *testing.T, name string, notAfter time.Time, usages ...x509.ExtKeyUsage) (chainPEM, keyPEM []byte) {
	t.Helper()
	key, err := pki.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := pki.NewSerial()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  usages,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	keyPEM, err = pki.EncodePrivateKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	return pki.EncodeCertificatesPEM(leaf, c.cert), keyPEM
}

func TestWebManualAndBack(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	s := e.bootstrap(t)
	corp := newTestCA(t, "Corp Root")
	year := time.Now().Add(365 * 24 * time.Hour)

	chain, key := corp.issue(t, "console.example", year, x509.ExtKeyUsageServerAuth)
	_, otherKey := corp.issue(t, "console.example", year, x509.ExtKeyUsageServerAuth)
	if err := s.SetWebManual(ctx, chain, otherKey); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mismatched key: %v", err)
	}
	clientOnly, ck := corp.issue(t, "console.example", year, x509.ExtKeyUsageClientAuth)
	if err := s.SetWebManual(ctx, clientOnly, ck); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong usage: %v", err)
	}
	if err := s.SetWebManual(ctx, []byte("garbage"), key); !errors.Is(err, ErrInvalid) {
		t.Fatalf("garbage: %v", err)
	}
	if err := s.SetWebManual(ctx, chain, key); err != nil {
		t.Fatal(err)
	}
	st, err := s.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Web.Mode != ModeManual || st.Web.Subject != "CN=console.example" || st.Web.Issuer != "CN=Corp Root" {
		t.Fatalf("web status %+v", st.Web)
	}
	if leafOf(t, s.WebCertificate).Issuer.CommonName != "Corp Root" {
		t.Fatal("manual certificate not served")
	}
	// Manual certificates are never renewed.
	e.clock.Advance(300 * 24 * time.Hour)
	if err := s.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	if leafOf(t, s.WebCertificate).Issuer.CommonName != "Corp Root" {
		t.Fatal("manual certificate replaced by renewal")
	}

	if err := s.SetWebAuto(ctx); err != nil {
		t.Fatal(err)
	}
	webCA, _ := s.loadCA(ctx, e.db, store.PKIWebCA)
	if err := leafOf(t, s.WebCertificate).CheckSignatureFrom(webCA.Cert); err != nil {
		t.Fatalf("not reissued from the internal CA: %v", err)
	}
	if st, _ := s.Status(ctx); st.Web.Mode != ModeAuto {
		t.Fatalf("mode %s", st.Web.Mode)
	}
}

func TestWebOff(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	s := e.service(t, func(c *Config) { c.WebTLS = false })
	if err := s.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.WebCertificate(); !errors.Is(err, ErrWebTLSOff) {
		t.Fatalf("err %v", err)
	}
	if _, err := e.db.GetPKIObject(ctx, store.PKIWebCA); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("web CA created while off: %v", err)
	}
	st, err := s.Status(ctx)
	if err != nil || st.Web.Mode != ModeOff {
		t.Fatalf("status %+v %v", st.Web, err)
	}
	if err := s.SetWebAuto(ctx); !errors.Is(err, ErrWebTLSOff) {
		t.Fatalf("set: %v", err)
	}
}

// internalCA returns the current internal Agent TLS CA as a testCA, to issue
// "manual" certificates under the current anchor.
func internalCA(t *testing.T, s *Service) *testCA {
	t.Helper()
	ca, err := s.loadCA(context.Background(), s.st, store.PKIAgentTLSCA)
	if err != nil || ca == nil {
		t.Fatalf("agent TLS CA: %v", err)
	}
	return &testCA{cert: ca.Cert, key: ca.Key}
}

func TestAgentManual(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	s := e.bootstrap(t)
	year := time.Now().Add(365 * 24 * time.Hour)
	h, _ := s.AnchorHash()

	// Not under the anchor.
	corp := newTestCA(t, "Corp Root")
	both, bothKey := corp.issue(t, "agents.example", year, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
	if _, err := s.SetAgentManual(ctx, both, bothKey, nil, nil); !errors.Is(err, ErrAnchorMismatch) {
		t.Fatalf("foreign chain: %v", err)
	}

	in := internalCA(t, s)
	serverOnly, serverKey := in.issue(t, "agents.example", year, x509.ExtKeyUsageServerAuth)
	if _, err := s.SetAgentManual(ctx, serverOnly, serverKey, nil, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("server-only without client: %v", err)
	}
	if _, err := s.SetAgentManual(ctx, serverOnly, serverKey, serverOnly, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("client chain without key: %v", err)
	}
	foreignClient, fck := corp.issue(t, "agents.example", year, x509.ExtKeyUsageClientAuth)
	if _, err := s.SetAgentManual(ctx, serverOnly, serverKey, foreignClient, fck); !errors.Is(err, ErrAnchorMismatch) {
		t.Fatalf("client under another anchor: %v", err)
	}

	client, clientKey := in.issue(t, "agents.example", year, x509.ExtKeyUsageClientAuth)
	staged, err := s.SetAgentManual(ctx, serverOnly, serverKey, client, clientKey)
	if err != nil || staged {
		t.Fatalf("separate client: staged=%v err=%v", staged, err)
	}
	if got := leafOf(t, s.AgentClientCertificate); got.Subject.CommonName != "agents.example" || got.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatal("client certificate not stored")
	}

	dual, dualKey := in.issue(t, "agents.example", year, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
	if _, err := s.SetAgentManual(ctx, dual, dualKey, nil, nil); err != nil {
		t.Fatal(err)
	}
	if !leafOf(t, s.AgentClientCertificate).Equal(leafOf(t, s.AgentServerCertificate)) {
		t.Fatal("dual-use certificate not used for both")
	}
	st, _ := s.Status(ctx)
	if st.Agent.Mode != ModeManual || st.AnchorHash != h {
		t.Fatalf("status %+v", st)
	}

	if err := s.SetAgentAuto(ctx); err != nil {
		t.Fatal(err)
	}
	if err := leafOf(t, s.AgentServerCertificate).CheckSignatureFrom(in.cert); err != nil || len(leafOf(t, s.AgentServerCertificate).ExtKeyUsage) != 1 {
		t.Fatal("not reissued by the internal CA")
	}
	if st, _ := s.Status(ctx); st.Agent.Mode != ModeAuto {
		t.Fatalf("mode %s", st.Agent.Mode)
	}
}

func TestAnchorChangeInternal(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	s := e.bootstrap(t)
	old, _ := s.AnchorHash()
	b0, _ := s.TrustBundle()

	if err := s.ActivateAnchor(ctx, true); !errors.Is(err, ErrNoPendingAnchor) {
		t.Fatalf("activate without prepare: %v", err)
	}
	if err := s.CancelAnchor(ctx); !errors.Is(err, ErrNoPendingAnchor) {
		t.Fatalf("cancel without prepare: %v", err)
	}
	if err := s.PrepareAnchor(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.PrepareAnchor(ctx, nil); !errors.Is(err, ErrAnchorPending) {
		t.Fatalf("second prepare: %v", err)
	}
	b1, _ := s.TrustBundle()
	if b1.Version != b0.Version+1 || len(b1.Anchors) != 2 || pki.SPKIHash(b1.Anchors[0]) != old {
		t.Fatalf("bundle after prepare: version %d, %d anchors", b1.Version, len(b1.Anchors))
	}
	next := pki.SPKIHash(b1.Anchors[1])
	st, _ := s.Status(ctx)
	if st.Pending == nil || st.Pending.SPKIHash != next || !st.Pending.Internal {
		t.Fatalf("pending %+v", st.Pending)
	}
	if h, _ := s.AnchorHash(); h != old {
		t.Fatal("anchor changed by prepare")
	}

	e.unsynced.Store(2)
	if err := s.ActivateAnchor(ctx, false); !errors.Is(err, ErrAgentsNotSynced) {
		t.Fatalf("unsynced activate: %v", err)
	}
	e.unsynced.Store(0)
	if err := s.ActivateAnchor(ctx, false); err != nil {
		t.Fatal(err)
	}
	b2, _ := s.TrustBundle()
	if b2.Version != b1.Version+1 || len(b2.Anchors) != 1 || pki.SPKIHash(b2.Anchors[0]) != next {
		t.Fatalf("bundle after activate: version %d, %d anchors", b2.Version, len(b2.Anchors))
	}
	if h, _ := s.AnchorHash(); h != next {
		t.Fatal("anchor not switched")
	}
	srv, _ := s.AgentServerCertificate()
	chain, _ := pki.ParseChain(srv.Certificate)
	if err := pki.VerifyPinned(chain, next, "agents.example", x509.ExtKeyUsageServerAuth); err != nil {
		t.Fatalf("server certificate not under the new anchor: %v", err)
	}
	if !b2.AgentCA.Equal(b0.AgentCA) {
		t.Fatal("Agent CA changed")
	}

	// Cancel drops a prepared anchor and bumps the version.
	if err := s.PrepareAnchor(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.CancelAnchor(ctx); err != nil {
		t.Fatal(err)
	}
	b3, _ := s.TrustBundle()
	if b3.Version != b2.Version+2 || len(b3.Anchors) != 1 || pki.SPKIHash(b3.Anchors[0]) != next {
		t.Fatalf("bundle after cancel: version %d, %d anchors", b3.Version, len(b3.Anchors))
	}
}

func TestAnchorChangeManual(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	s := e.bootstrap(t)
	old, _ := s.AnchorHash()
	corp := newTestCA(t, "Corp Root")
	year := time.Now().Add(365 * 24 * time.Hour)
	chain, key := corp.issue(t, "agents.example", year, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)

	if err := s.PrepareAnchor(ctx, []byte("not pem")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("garbage anchor: %v", err)
	}
	// The topmost certificate of a supplied chain is the anchor.
	if err := s.PrepareAnchor(ctx, chain); err != nil {
		t.Fatal(err)
	}
	if err := s.ActivateAnchor(ctx, false); !errors.Is(err, ErrNotStaged) {
		t.Fatalf("activate without staged certificate: %v", err)
	}
	staged, err := s.SetAgentManual(ctx, chain, key, nil, nil)
	if err != nil || !staged {
		t.Fatalf("staged=%v err=%v", staged, err)
	}
	if st, _ := s.Status(ctx); st.Agent.Mode != ModeAuto || st.Pending == nil || !st.Pending.Staged || st.Pending.Internal {
		t.Fatalf("status before activation %+v %+v", st.Agent, st.Pending)
	}
	if h, _ := s.AnchorHash(); h != old {
		t.Fatal("anchor changed before activation")
	}
	if leafOf(t, s.AgentServerCertificate).Issuer.CommonName == "Corp Root" {
		t.Fatal("staged certificate served before activation")
	}

	if err := s.ActivateAnchor(ctx, false); err != nil {
		t.Fatal(err)
	}
	st, _ := s.Status(ctx)
	if st.Agent.Mode != ModeManual || st.AnchorHash != pki.SPKIHash(corp.cert) || st.Pending != nil {
		t.Fatalf("status after activation %+v", st)
	}
	if leafOf(t, s.AgentServerCertificate).Issuer.CommonName != "Corp Root" {
		t.Fatal("manual certificate not active")
	}
	// The internal CA is no longer the anchor: switching back needs an
	// anchor change.
	if err := s.SetAgentAuto(ctx); !errors.Is(err, ErrAnchorMismatch) {
		t.Fatalf("auto with foreign anchor: %v", err)
	}
	// Leaves are not renewed in manual mode.
	e.clock.Advance(25 * 24 * time.Hour)
	if err := s.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	if leafOf(t, s.AgentServerCertificate).Issuer.CommonName != "Corp Root" {
		t.Fatal("manual certificate renewed")
	}
	// Back to automatic through a new internal anchor.
	if err := s.PrepareAnchor(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.ActivateAnchor(ctx, false); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.Status(ctx); st.Agent.Mode != ModeAuto {
		t.Fatalf("mode %s", st.Agent.Mode)
	}
}

func TestAgentCertificates(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	s := e.bootstrap(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	agent, err := e.db.CreateAgent(ctx, store.Agent{Kind: store.AgentKindAgent, Hostname: "h1", IdentityKey: pub, State: store.AgentApproved})
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.CreateAgentCSR(priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.IssueAgentCertificate(ctx, []byte("bad"), agent.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad csr: %v", err)
	}
	cert, err := s.IssueAgentCertificate(ctx, csr, agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := s.AgentCA()
	id, err := pki.VerifyAgent([]*x509.Certificate{cert}, ca, x509.ExtKeyUsageClientAuth)
	if err != nil || id != agent.ID {
		t.Fatalf("verify: %q %v", id, err)
	}
	certs, _ := e.db.ListAgentCerts(ctx, agent.ID)
	if len(certs) != 1 || certs[0].Serial != FormatSerial(cert.SerialNumber) {
		t.Fatalf("recorded %+v", certs)
	}

	s.refreshRevocations(ctx)
	if r, err := s.IsAgentCertRevoked(ctx, cert.SerialNumber); err != nil || r {
		t.Fatalf("fresh: %v %v", r, err)
	}
	if r, err := s.IsAgentCertRevoked(ctx, big.NewInt(12345)); err != nil || !r {
		t.Fatalf("unknown serial: %v %v", r, err)
	}

	if err := e.db.RevokeAgent(ctx, agent.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Another replica's cached answer converges on refresh.
	if r, _ := s.IsAgentCertRevoked(ctx, cert.SerialNumber); r {
		t.Fatal("cache answered from the store before a refresh")
	}
	s.refreshRevocations(ctx)
	if r, _ := s.IsAgentCertRevoked(ctx, cert.SerialNumber); !r {
		t.Fatal("not revoked after refresh")
	}
	// A replica with an empty cache sees it at once.
	if r, _ := e.service(t, nil).IsAgentCertRevoked(ctx, cert.SerialNumber); !r {
		t.Fatal("not revoked on a fresh replica")
	}

	// The revoking replica marks it without waiting for a refresh.
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
	agent2, _ := e.db.CreateAgent(ctx, store.Agent{Kind: store.AgentKindAgent, IdentityKey: pub2, State: store.AgentApproved})
	csr2, _ := pki.CreateAgentCSR(priv2)
	cert2, err := s.IssueAgentCertificate(ctx, csr2, agent2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := s.IsAgentCertRevoked(ctx, cert2.SerialNumber); r {
		t.Fatal("revoked early")
	}
	if err := e.db.RevokeAgent(ctx, agent2.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.NoteAgentRevoked(ctx, agent2.ID); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.IsAgentCertRevoked(ctx, cert2.SerialNumber); !r {
		t.Fatal("not revoked after NoteAgentRevoked")
	}

	// A certificate revoked elsewhere and never looked up here enters the
	// set with the next refresh, which is incremental.
	pub3, priv3, _ := ed25519.GenerateKey(rand.Reader)
	agent3, _ := e.db.CreateAgent(ctx, store.Agent{Kind: store.AgentKindAgent, IdentityKey: pub3, State: store.AgentApproved})
	csr3, _ := pki.CreateAgentCSR(priv3)
	cert3, err := s.IssueAgentCertificate(ctx, csr3, agent3.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.RevokeAgentCerts(ctx, agent3.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	inSet := func(c *x509.Certificate) bool {
		s.rev.mu.Lock()
		defer s.rev.mu.Unlock()
		_, ok := s.rev.revoked[FormatSerial(c.SerialNumber)]
		return ok
	}
	if inSet(cert3) {
		t.Fatal("revoked before a refresh")
	}
	s.refreshRevocations(ctx)
	if !inSet(cert3) || s.rev.loads < 2 {
		t.Fatalf("refresh did not load a revocation made elsewhere (loads %d)", s.rev.loads)
	}
	if r, _ := s.IsAgentCertRevoked(ctx, cert3.SerialNumber); !r {
		t.Fatal("cert3 not revoked")
	}
	// Expired certificates leave the set; they fail verification anyway.
	e.clock.Advance(DefaultAgentCertLifetime + time.Hour)
	s.refreshRevocations(ctx)
	if inSet(cert3) || inSet(cert2) {
		t.Fatal("expired certificates kept in the set")
	}
}
