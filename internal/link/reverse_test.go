// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package link

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/pki"
)

// agentSide is a listen-mode agent: Listener feeding a ReverseHolder and an
// http.Client over it.
type agentSide struct {
	ln       *Listener
	holder   *ReverseHolder
	client   *http.Client
	accepted atomic.Int32
	observed ObservedPeer
	done     chan error
}

func startAgent(t *testing.T, p *testPKI, cert tls.Certificate, mod func(*ListenConfig)) *agentSide {
	t.Helper()
	a := &agentSide{holder: &ReverseHolder{DrainTimeout: 2 * time.Second}, done: make(chan error, 1)}
	cfg := ListenConfig{
		Certificate: certGetter(cert),
		Verify:      PinnedVerifier(p.pin, testServerName),
		ObservePeer: a.observed.Observe,
	}
	if mod != nil {
		mod(&cfg)
	}
	ln, err := Listen(context.Background(), "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	a.ln = ln
	a.client = &http.Client{Transport: a.holder}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		a.done <- ln.Serve(ctx, func(c *ReverseConn) {
			a.accepted.Add(1)
			a.holder.Set(c)
		})
	}()
	t.Cleanup(func() {
		cancel()
		if err := recvErr(t, a.done); !errors.Is(err, context.Canceled) {
			t.Errorf("Serve returned %v", err)
		}
	})
	return a
}

func (a *agentSide) addr() string { return a.ln.Addr().String() }

// dialServer runs DialReverse in the background and returns its result
// channel and a cancel function.
func dialServer(t *testing.T, addr string, cfg ReverseDialConfig, h http.Handler) (<-chan error, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan error, 1)
	go func() { ch <- DialReverse(ctx, addr, cfg, h) }()
	t.Cleanup(cancel)
	return ch, cancel
}

func (p *testPKI) dialConfig(rev *revocations) ReverseDialConfig {
	return ReverseDialConfig{
		ClientCertificate: certGetter(p.clientCert),
		VerifyAgent:       p.verifier(rev).VerifyReverse,
	}
}

func TestListenRoundTrip(t *testing.T) {
	p := newTestPKI(t)
	a := startAgent(t, p, p.agentCert, nil)
	v := p.verifier(nil)
	// The same middleware stack as the connect listener.
	done, cancel := dialServer(t, a.addr(), p.dialConfig(nil), v.Middleware(echoHandler("srv")))

	body := mustGet(t, a.client, "https://"+testServerName+"/agent/v1/poll")
	want := "srv|agent-1|true|false|true|2|" + a.addr()
	if body != want {
		t.Fatalf("body %q, want %q", body, want)
	}
	if fp, _, ok := a.observed.Last(); !ok || fp != pki.Fingerprint(p.clientCert.Leaf) {
		t.Fatal("agent did not observe the server client certificate")
	}

	// A POST with a body works as well.
	req, err := http.NewRequest(http.MethodPost, "https://"+testServerName+"/agent/v1/reports", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	cancel()
	if err := recvErr(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("DialReverse returned %v", err)
	}
}

func TestListenTemporaryCertificateIsUnenrolled(t *testing.T) {
	p := newTestPKI(t)
	tmp, err := pki.NewTemporaryCertificate()
	if err != nil {
		t.Fatal(err)
	}
	a := startAgent(t, p, tmp, nil)
	dialServer(t, a.addr(), p.dialConfig(nil), echoHandler("srv"))

	body := mustGet(t, a.client, "https://"+testServerName+"/agent/v1/enroll/start")
	if !strings.HasPrefix(body, "srv||false|true|true|2|") {
		t.Fatalf("body %q: want unenrolled without agent id", body)
	}
}

func TestListenRevokedAgentRejected(t *testing.T) {
	p := newTestPKI(t)
	rev := &revocations{}
	rev.revoke(p.agentCert.Leaf.SerialNumber)
	a := startAgent(t, p, p.agentCert, nil)
	done, _ := dialServer(t, a.addr(), p.dialConfig(rev), echoHandler("srv"))
	err := recvErr(t, done)
	if !errors.Is(err, ErrRevoked) {
		t.Fatalf("DialReverse returned %v, want ErrRevoked", err)
	}
}

func TestListenRejectsServerFromWrongCA(t *testing.T) {
	p := newTestPKI(t)
	a := startAgent(t, p, p.agentCert, nil)

	rogue := newCA(t, "Rogue CA")
	cfg := p.dialConfig(nil)
	cfg.ClientCertificate = certGetter(issueLeaf(t, rogue, true))
	done, _ := dialServer(t, a.addr(), cfg, echoHandler("srv"))
	if err := recvErr(t, done); err == nil {
		t.Fatal("DialReverse with a rogue client certificate returned nil")
	} else {
		t.Log(err)
	}

	// A server certificate (serverAuth only) under the right anchor is not
	// a client certificate.
	cfg.ClientCertificate = certGetter(p.serverCert)
	done, _ = dialServer(t, a.addr(), cfg, echoHandler("srv"))
	if err := recvErr(t, done); err == nil {
		t.Fatal("DialReverse with a serverAuth certificate returned nil")
	}
	if n := a.accepted.Load(); n != 0 {
		t.Fatalf("agent accepted %d connections", n)
	}
	if _, _, ok := a.observed.Last(); ok {
		t.Fatal("agent observed a rejected certificate")
	}
}

func TestListenALPNMismatch(t *testing.T) {
	p := newTestPKI(t)
	a := startAgent(t, p, p.agentCert, nil)

	// A client that does not offer the reverse protocol.
	for _, protos := range [][]string{{"h2"}, nil} {
		conn, err := tls.Dial("tcp", a.addr(), &tls.Config{
			NextProtos:         protos,
			InsecureSkipVerify: true, //nolint:gosec // test
			Certificates:       []tls.Certificate{p.clientCert},
		})
		if err == nil {
			// TLS 1.3: the rejection arrives with the first read.
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, err = conn.Read(make([]byte, 1))
			conn.Close()
		}
		if err == nil {
			t.Fatalf("ALPN %v accepted", protos)
		}
	}
	if n := a.accepted.Load(); n != 0 {
		t.Fatalf("agent accepted %d connections", n)
	}

	// DialReverse against a TLS server that does not speak the protocol.
	url := startServer(t, &tls.Config{Certificates: []tls.Certificate{p.serverCert}, NextProtos: []string{"h2"}}, echoHandler("x"))
	done, _ := dialServer(t, strings.TrimPrefix(url, "https://"), p.dialConfig(nil), echoHandler("srv"))
	if err := recvErr(t, done); err == nil {
		t.Fatal("DialReverse to a plain HTTPS server returned nil")
	}
}

func TestListenReconnectReplacesConnection(t *testing.T) {
	p := newTestPKI(t)
	a := startAgent(t, p, p.agentCert, nil)
	url := "https://" + testServerName + "/x"

	doneA, _ := dialServer(t, a.addr(), p.dialConfig(nil), echoHandler("A"))
	if body := mustGet(t, a.client, url); !strings.HasPrefix(body, "A|") {
		t.Fatalf("first connection: %q", body)
	}

	_, cancelB := dialServer(t, a.addr(), p.dialConfig(nil), echoHandler("B"))
	waitFor(t, "second connection", func() bool { return a.accepted.Load() == 2 })
	if body := mustGet(t, a.client, url); !strings.HasPrefix(body, "B|") {
		t.Fatalf("after reconnect: %q", body)
	}
	// The replaced connection is shut down; the server sees it end.
	if err := recvErr(t, doneA); err != nil {
		t.Fatalf("first DialReverse returned %v", err)
	}

	// Without a connection, requests wait for the next one.
	cancelB()
	waitFor(t, "connection loss", func() bool {
		c, _ := a.holder.current()
		return !c.usable()
	})
	result := make(chan string, 1)
	go func() {
		body, err := get(t, a.client, url)
		if err != nil {
			body = err.Error()
		}
		result <- body
	}()
	time.Sleep(50 * time.Millisecond)
	dialServer(t, a.addr(), p.dialConfig(nil), echoHandler("C"))
	select {
	case body := <-result:
		if !strings.HasPrefix(body, "C|") {
			t.Fatalf("waiting request: %q", body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiting request did not complete")
	}
}

func TestReverseHolderWaitHonorsContext(t *testing.T) {
	var h ReverseHolder
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+testServerName+"/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.RoundTrip(req); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("RoundTrip returned %v", err)
	}
}

func TestListenHandshakeLimitAndTimeout(t *testing.T) {
	p := newTestPKI(t)
	a := startAgent(t, p, p.agentCert, func(c *ListenConfig) {
		c.MaxHandshakes = 1
		c.HandshakeTimeout = 500 * time.Millisecond
	})

	// An idle connection holds the only handshake slot.
	idle, err := net.Dial("tcp", a.addr())
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	time.Sleep(50 * time.Millisecond)

	done, _ := dialServer(t, a.addr(), p.dialConfig(nil), echoHandler("srv"))
	if err := recvErr(t, done); err == nil {
		t.Fatal("connection over the handshake limit was served")
	}

	// The idle connection is closed at the handshake timeout.
	_ = idle.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	if _, err := idle.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle connection received data")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("idle connection was not closed by the handshake timeout")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("idle connection closed after %v", d)
	}

	// The slot is free again.
	dialServer(t, a.addr(), p.dialConfig(nil), echoHandler("srv"))
	mustGet(t, a.client, "https://"+testServerName+"/x")
}

func TestListenAllowedSources(t *testing.T) {
	p := newTestPKI(t)
	a := startAgent(t, p, p.agentCert, func(c *ListenConfig) {
		c.AllowedSources = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	})
	done, _ := dialServer(t, a.addr(), p.dialConfig(nil), echoHandler("srv"))
	if err := recvErr(t, done); err == nil {
		t.Fatal("connection from a disallowed address was served")
	}

	b := startAgent(t, p, p.agentCert, func(c *ListenConfig) {
		c.AllowedSources = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	})
	dialServer(t, b.addr(), p.dialConfig(nil), echoHandler("srv"))
	mustGet(t, b.client, "https://"+testServerName+"/x")
}

func TestListenAnchorsAfterEnrollment(t *testing.T) {
	// After enrollment the agent verifies the server against the trust
	// bundle and presents its issued certificate; the certificate getter
	// switches without restarting the listener.
	p := newTestPKI(t)
	tmp, err := pki.NewTemporaryCertificate()
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	cur := &tmp
	var anchors []*x509.Certificate
	a := startAgent(t, p, tmp, func(c *ListenConfig) {
		c.Certificate = func() (*tls.Certificate, error) {
			mu.Lock()
			defer mu.Unlock()
			return cur, nil
		}
		pinned := PinnedVerifier(p.pin, testServerName)
		bundle := AnchorVerifier(func() []*x509.Certificate {
			mu.Lock()
			defer mu.Unlock()
			return anchors
		}, testServerName)
		c.Verify = func(chain []*x509.Certificate, usage x509.ExtKeyUsage) error {
			mu.Lock()
			enrolled := anchors != nil
			mu.Unlock()
			if enrolled {
				return bundle(chain, usage)
			}
			return pinned(chain, usage)
		}
	})
	_, cancel := dialServer(t, a.addr(), p.dialConfig(nil), echoHandler("srv"))
	if body := mustGet(t, a.client, "https://"+testServerName+"/x"); !strings.HasPrefix(body, "srv||false|true|") {
		t.Fatalf("before enrollment: %q", body)
	}
	cancel()

	mu.Lock()
	cur = &p.agentCert
	anchors = []*x509.Certificate{p.tlsCA.Cert}
	mu.Unlock()
	dialServer(t, a.addr(), p.dialConfig(nil), echoHandler("srv"))
	waitFor(t, "second connection", func() bool { return a.accepted.Load() == 2 })
	if body := mustGet(t, a.client, "https://"+testServerName+"/x"); !strings.HasPrefix(body, "srv|agent-1|true|false|") {
		t.Fatalf("after enrollment: %q", body)
	}
}
