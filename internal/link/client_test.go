// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package link

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/bomcensus/bomcensus/internal/pki"
)

func connectClient(t *testing.T, cfg ClientConfig) *http.Client {
	t.Helper()
	tc, err := ClientTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rt := NewConnectTransport(tc, ConnectOptions{})
	t.Cleanup(func() { rt.(interface{ CloseIdleConnections() }).CloseIdleConnections() })
	return &http.Client{Transport: rt}
}

func agentServer(t *testing.T, p *testPKI, rev *revocations) string {
	t.Helper()
	v := p.verifier(rev)
	cfg, err := ServerTLSConfig(certGetter(p.serverCert), v)
	if err != nil {
		t.Fatal(err)
	}
	return startServer(t, cfg, v.Middleware(echoHandler("srv")))
}

func TestConnectPinned(t *testing.T) {
	p := newTestPKI(t)
	url := agentServer(t, p, nil)

	var seen ObservedPeer
	c := connectClient(t, ClientConfig{
		Mode:        TLSPinned,
		Verify:      PinnedVerifier(p.pin, testServerName),
		ObservePeer: seen.Observe,
	})
	body := mustGet(t, c, url+"/x")
	if !strings.HasPrefix(body, "srv||false|false|false|2|") {
		t.Fatalf("body %q: want HTTP/2 without agent id", body)
	}
	fp, leaf, ok := seen.Last()
	if !ok || fp != pki.Fingerprint(p.serverCert.Leaf) || leaf.SerialNumber.Cmp(p.serverCert.Leaf.SerialNumber) != 0 {
		t.Fatalf("observed fingerprint %x ok=%t, want %x", fp, ok, pki.Fingerprint(p.serverCert.Leaf))
	}
}

func TestConnectPinnedWrongPin(t *testing.T) {
	p := newTestPKI(t)
	url := agentServer(t, p, nil)
	other := newCA(t, "Other CA")

	called := false
	c := connectClient(t, ClientConfig{
		Mode:        TLSPinned,
		Verify:      PinnedVerifier(pki.SPKIHash(other.Cert), testServerName),
		ObservePeer: func([32]byte, *x509.Certificate) { called = true },
	})
	if _, err := get(t, c, url+"/x"); err == nil {
		t.Fatal("request with wrong pin succeeded")
	}
	if called {
		t.Fatal("observer called for a failed handshake")
	}

	// Pin is right but the name is not.
	c = connectClient(t, ClientConfig{Mode: TLSPinned, Verify: PinnedVerifier(p.pin, "other.test")})
	if _, err := get(t, c, url+"/x"); err == nil {
		t.Fatal("request with wrong server name succeeded")
	}
}

func TestConnectAnchorsFollowGetter(t *testing.T) {
	p := newTestPKI(t)
	url := agentServer(t, p, nil)

	var mu sync.Mutex
	anchors := []*x509.Certificate{newCA(t, "Old anchor").Cert}
	current := func() []*x509.Certificate {
		mu.Lock()
		defer mu.Unlock()
		return anchors
	}
	tc, err := ClientTLSConfig(ClientConfig{Mode: TLSPinned, Verify: AnchorVerifier(current, testServerName)})
	if err != nil {
		t.Fatal(err)
	}
	rt := NewConnectTransport(tc, ConnectOptions{})
	c := &http.Client{Transport: rt}
	if _, err := get(t, c, url+"/x"); err == nil {
		t.Fatal("request without the right anchor succeeded")
	}
	mu.Lock()
	anchors = append(anchors, p.tlsCA.Cert)
	mu.Unlock()
	if _, err := get(t, c, url+"/x"); err != nil {
		t.Fatalf("request after bundle update: %v", err)
	}
	c.CloseIdleConnections()
}

func TestConnectClientCertificate(t *testing.T) {
	p := newTestPKI(t)
	url := agentServer(t, p, nil)

	var mu sync.Mutex
	var cert *tls.Certificate
	c := connectClient(t, ClientConfig{
		Mode:   TLSPinned,
		Verify: PinnedVerifier(p.pin, testServerName),
		ClientCertificate: func() (*tls.Certificate, error) {
			mu.Lock()
			defer mu.Unlock()
			return cert, nil
		},
	})
	body := mustGet(t, c, url+"/x")
	if !strings.HasPrefix(body, "srv||false|") {
		t.Fatalf("before enrollment: %q", body)
	}
	c.CloseIdleConnections()

	mu.Lock()
	cert = &p.agentCert
	mu.Unlock()
	body = mustGet(t, c, url+"/x")
	if !strings.HasPrefix(body, "srv|agent-1|true|false|false|2|") {
		t.Fatalf("with certificate: %q", body)
	}
}

func TestConnectRevoked(t *testing.T) {
	p := newTestPKI(t)
	rev := &revocations{}
	url := agentServer(t, p, rev)
	c := connectClient(t, ClientConfig{
		Mode:              TLSPinned,
		Verify:            PinnedVerifier(p.pin, testServerName),
		ClientCertificate: certGetter(p.agentCert),
	})
	mustGet(t, c, url+"/x")

	// Revocation applies to the open connection at the next request.
	rev.revoke(p.agentCert.Leaf.SerialNumber)
	if body, err := get(t, c, url+"/x"); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("request on open connection after revocation: %v %q", err, body)
	}

	// A new handshake is rejected.
	c.CloseIdleConnections()
	if _, err := get(t, c, url+"/x"); err == nil {
		t.Fatal("handshake with revoked certificate succeeded")
	}

	// A certificate from another CA is rejected too.
	other := issueAgent(t, newCA(t, "Other Agent CA"), "agent-2")
	c = connectClient(t, ClientConfig{
		Mode:              TLSPinned,
		Verify:            PinnedVerifier(p.pin, testServerName),
		ClientCertificate: certGetter(other),
	})
	if _, err := get(t, c, url+"/x"); err == nil {
		t.Fatal("handshake with foreign agent certificate succeeded")
	}
}

func TestDeferringMiddleware(t *testing.T) {
	p := newTestPKI(t)
	rev := &revocations{}
	var mu sync.Mutex
	var gotErr, checkErr error
	v := p.verifier(nil)
	v.Revoked = func(s *big.Int) (bool, error) {
		mu.Lock()
		err := checkErr
		mu.Unlock()
		if err != nil {
			return false, err
		}
		return rev.check(s)
	}
	cfg, err := ServerTLSConfig(certGetter(p.serverCert), v)
	if err != nil {
		t.Fatal(err)
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotErr = PeerCertError(r.Context())
		mu.Unlock()
		echoHandler("srv").ServeHTTP(w, r)
	})
	deferred := func(r *http.Request) bool { return r.URL.Path == "/signed" }
	url := startServer(t, cfg, v.DeferringMiddleware(deferred, h))
	c := connectClient(t, ClientConfig{
		Mode:              TLSPinned,
		Verify:            PinnedVerifier(p.pin, testServerName),
		ClientCertificate: certGetter(p.agentCert),
	})
	if body := mustGet(t, c, url+"/signed"); !strings.HasPrefix(body, "srv|agent-1|true|") {
		t.Fatalf("body %q: want the agent id", body)
	}
	mu.Lock()
	if gotErr != nil {
		t.Fatalf("PeerCertError = %v for a valid certificate", gotErr)
	}
	mu.Unlock()

	rev.revoke(p.agentCert.Leaf.SerialNumber)
	// A deferred path reaches the handler without an id and with the reason.
	if body := mustGet(t, c, url+"/signed"); !strings.HasPrefix(body, "srv||false|") {
		t.Fatalf("body %q: want no agent id", body)
	}
	mu.Lock()
	if !errors.Is(gotErr, ErrRevoked) {
		t.Fatalf("PeerCertError = %v, want ErrRevoked", gotErr)
	}
	mu.Unlock()
	// Other paths are still answered with a plain 403.
	if body, err := get(t, c, url+"/enroll"); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("non-deferred path after revocation: %v %q", err, body)
	}

	// A failing revocation check is reported as such.
	mu.Lock()
	checkErr = errors.New("store down")
	mu.Unlock()
	mustGet(t, c, url+"/signed")
	mu.Lock()
	if !errors.Is(gotErr, ErrRevocationCheck) || errors.Is(gotErr, ErrRevoked) {
		t.Fatalf("PeerCertError = %v, want ErrRevocationCheck", gotErr)
	}
	mu.Unlock()
}

func TestConnectSystemAndNone(t *testing.T) {
	// A server whose certificate has nothing to do with the pinned anchor,
	// like an inspection device.
	p := newTestPKI(t)
	device := newCA(t, "Inspection CA")
	deviceCert := issueLeaf(t, device, false)
	url := startServer(t, &tls.Config{
		Certificates: []tls.Certificate{deviceCert},
		NextProtos:   []string{"h2", "http/1.1"},
	}, echoHandler("dev"))

	pinned := connectClient(t, ClientConfig{Mode: TLSPinned, Verify: PinnedVerifier(p.pin, testServerName)})
	if _, err := get(t, pinned, url+"/x"); err == nil {
		t.Fatal("pinned mode accepted the inspection certificate")
	}

	system := connectClient(t, ClientConfig{Mode: TLSSystem})
	if _, err := get(t, system, url+"/x"); err == nil {
		t.Fatal("system mode accepted an unknown CA")
	}

	var seen ObservedPeer
	system = connectClient(t, ClientConfig{Mode: TLSSystem, ExtraRoots: []*x509.Certificate{device.Cert}, ObservePeer: seen.Observe})
	mustGet(t, system, url+"/x")
	if fp, _, ok := seen.Last(); !ok || fp != pki.Fingerprint(deviceCert.Leaf) {
		t.Fatal("system mode did not observe the device certificate")
	}

	var seenNone ObservedPeer
	none := connectClient(t, ClientConfig{Mode: TLSNone, ObservePeer: seenNone.Observe})
	body := mustGet(t, none, url+"/x")
	if !strings.HasPrefix(body, "dev|") {
		t.Fatalf("none mode body %q", body)
	}
	if fp, _, ok := seenNone.Last(); !ok || fp != pki.Fingerprint(deviceCert.Leaf) {
		t.Fatal("none mode did not observe the device certificate")
	}
}

func TestRelaxedModesSendNoClientCertificate(t *testing.T) {
	p := newTestPKI(t)
	url := agentServer(t, p, nil)
	// ClientCertificate is ignored outside pinned mode.
	c := connectClient(t, ClientConfig{Mode: TLSNone, ClientCertificate: certGetter(p.agentCert)})
	body := mustGet(t, c, url+"/x")
	if !strings.HasPrefix(body, "srv||false|") {
		t.Fatalf("body %q: client certificate was sent", body)
	}
}

func TestClientTLSConfigErrors(t *testing.T) {
	if _, err := ClientTLSConfig(ClientConfig{Mode: TLSPinned}); err == nil {
		t.Fatal("pinned without verifier accepted")
	}
	if _, err := ClientTLSConfig(ClientConfig{Mode: "bogus"}); err == nil {
		t.Fatal("unknown mode accepted")
	}
	for in, want := range map[string]TLSMode{"": TLSPinned, "pinned": TLSPinned, "system": TLSSystem, "none": TLSNone} {
		got, err := ParseTLSMode(in)
		if err != nil || got != want {
			t.Fatalf("ParseTLSMode(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseTLSMode("insecure"); err == nil {
		t.Fatal("ParseTLSMode accepted an unknown mode")
	}
}
