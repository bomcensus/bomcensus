// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package link

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/pki"
)

const testServerName = "agents.test"

// testPKI is the material of one server installation: the Agent TLS CA
// with server and client leaves, and the Agent CA with one agent.
type testPKI struct {
	tlsCA      *pki.CA
	pin        [32]byte
	serverCert tls.Certificate
	clientCert tls.Certificate
	agentCA    *pki.CA
	agentCert  tls.Certificate
	agentID    string
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	p := &testPKI{agentID: "agent-1"}
	p.tlsCA = newCA(t, "Agent TLS CA")
	p.pin = pki.SPKIHash(p.tlsCA.Cert)
	p.serverCert = issueLeaf(t, p.tlsCA, false)
	p.clientCert = issueLeaf(t, p.tlsCA, true)
	p.agentCA = newCA(t, "Agent CA")
	p.agentCert = issueAgent(t, p.agentCA, p.agentID)
	return p
}

func newCA(t *testing.T, name string) *pki.CA {
	t.Helper()
	ca, err := pki.NewCA(pki.CAOptions{Subject: pkix.Name{CommonName: name}})
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func issueLeaf(t *testing.T, ca *pki.CA, client bool) tls.Certificate {
	t.Helper()
	key, err := pki.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	opts := pki.LeafOptions{DNSNames: []string{testServerName}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	var cert *x509.Certificate
	if client {
		cert, err = ca.IssueClient(key.Public(), opts)
	} else {
		cert, err = ca.IssueServer(key.Public(), opts)
	}
	if err != nil {
		t.Fatal(err)
	}
	return pki.TLSCertificate([]*x509.Certificate{cert, ca.Cert}, key)
}

func issueAgent(t *testing.T, ca *pki.CA, id string) tls.Certificate {
	t.Helper()
	key, err := pki.GenerateAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := pki.CreateAgentCSR(key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.ParseAgentCSR(der)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.IssueAgent(csr, id, pki.AgentOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return pki.TLSCertificate([]*x509.Certificate{cert}, key)
}

func certGetter(c tls.Certificate) func() (*tls.Certificate, error) {
	return func() (*tls.Certificate, error) { return &c, nil }
}

// revocations is a concurrency-safe revoked serial set.
type revocations struct {
	mu      sync.Mutex
	serials map[string]bool
}

func (r *revocations) revoke(s *big.Int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.serials == nil {
		r.serials = make(map[string]bool)
	}
	r.serials[s.String()] = true
}

func (r *revocations) check(s *big.Int) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.serials[s.String()], nil
}

func (p *testPKI) verifier(rev *revocations) *AgentVerifier {
	v := &AgentVerifier{AgentCA: func() *x509.Certificate { return p.agentCA.Cert }}
	if rev != nil {
		v.Revoked = rev.check
	}
	return v
}

// echoHandler reports what the transport layer told the handler.
func echoHandler(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := PeerAgentID(r.Context())
		fmt.Fprintf(w, "%s|%s|%t|%t|%t|%d|%s", name, id, ok, PeerUnenrolled(r.Context()), PeerReverse(r.Context()), r.ProtoMajor, r.RemoteAddr)
	})
}

// startServer runs an HTTPS server on loopback with cfg and returns its
// base URL.
func startServer(t *testing.T, cfg *tls.Config, h http.Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:           h,
		TLSConfig:         cfg,
		ReadHeaderTimeout: 5 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return "https://" + ln.Addr().String()
}

func get(t *testing.T, client *http.Client, url string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return string(b), fmt.Errorf("status %d", resp.StatusCode)
	}
	return string(b), nil
}

func mustGet(t *testing.T, client *http.Client, url string) string {
	t.Helper()
	body, err := get(t, client, url)
	if err != nil {
		t.Fatalf("GET %s: %v (%s)", url, err, body)
	}
	return body
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func recvErr(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for result")
		return errors.New("timeout")
	}
}
