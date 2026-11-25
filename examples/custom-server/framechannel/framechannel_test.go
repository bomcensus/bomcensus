// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package framechannel

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/agentproto"
	"github.com/bomcensus/bomcensus/agentproto/conformance"
	"github.com/bomcensus/bomcensus/agentproto/dto"
)

// TestConformance checks that the DTOs survive the frame encoding.
func TestConformance(t *testing.T) {
	conformance.Run(t, func(v any) (any, error) {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		out := reflect.New(reflect.TypeOf(v).Elem()).Interface()
		return out, json.Unmarshal(b, out)
	})
}

const agentID = "01a1fc83-4a09-77b9-a499-ef0449ae1388"

// fakeAPI records the agent of each call.
type fakeAPI struct {
	agentproto.API
	agents chan string
}

func (f *fakeAPI) Poll(ctx context.Context, req *dto.PollRequest) (*dto.PollResult, error) {
	id, _ := agentproto.AgentFrom(ctx)
	f.agents <- id
	if req.Version == "refuse" {
		return nil, agentproto.Errorf(http.StatusForbidden, agentproto.CodeAgentRevoked, "agent is revoked")
	}
	return &dto.PollResult{LastCounter: 7}, nil
}

func (f *fakeAPI) EnrollStart(ctx context.Context, body []byte) (*agentproto.SignedMessage, error) {
	if _, ok := agentproto.AgentFrom(ctx); ok {
		return nil, errors.New("enrollment must be unauthenticated")
	}
	return &agentproto.SignedMessage{Body: append([]byte("echo:"), body...), Signature: "sig"}, nil
}

func (f *fakeAPI) DownloadProbe(ctx context.Context, os dto.TargetOs, arch dto.TargetArch) (*agentproto.Download, error) {
	return &agentproto.Download{Body: io.NopCloser(strings.NewReader(string(os) + "/" + string(arch))), Version: "1.2.3"}, nil
}

type fakeAgents struct {
	pub  ed25519.PublicKey
	cert *tls.Certificate
}

func (a fakeAgents) AgentKey(_ context.Context, id string) (agentproto.AgentKey, error) {
	if id != agentID {
		return agentproto.AgentKey{}, agentproto.ErrUnknownAgent
	}
	return agentproto.AgentKey{PublicKey: a.pub, State: agentproto.StateApproved}, nil
}

func (fakeAgents) AdvanceCounter(context.Context, string, uint64) (uint64, bool, error) {
	return 0, false, errors.New("not used")
}

func (fakeAgents) SigningKey(context.Context) (crypto.Signer, []*x509.Certificate, error) {
	return nil, nil, errors.New("not used")
}

func (a fakeAgents) ServerCertificate() (*tls.Certificate, error) { return a.cert, nil }

func (fakeAgents) VerifyCertificate([]*x509.Certificate) (string, error) {
	return "", errors.New("no agent certificates in this test")
}

// testPKI returns a CA and a server certificate for name.
func testPKI(t *testing.T, name string) (*x509.Certificate, *tls.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return ca, &tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
}

type env struct {
	api  *fakeAPI
	gw   *gateway
	ch   agentproto.Channel
	priv ed25519.PrivateKey
}

func start(t *testing.T) *env {
	t.Helper()
	const name = "bomcensus.test"
	ca, cert := testPKI(t, name)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	api := &fakeAPI{agents: make(chan string, 4)}
	srv := &agentproto.Server{API: api, Agents: fakeAgents{pub: pub, cert: cert}}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	g := &Gateway{}
	go func() { done <- g.Serve(ctx, ln, srv) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	ch, err := Factory()(ctx, agentproto.ChannelParams{
		Name:       Name,
		ServerURL:  ln.Addr().String(),
		ServerName: name,
		VerifyServer: func(chain []*x509.Certificate, usage x509.ExtKeyUsage) error {
			inter := x509.NewCertPool()
			for _, c := range chain[1:] {
				inter.AddCert(c)
			}
			_, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: name,
				KeyUsages: []x509.ExtKeyUsage{usage}})
			return err
		},
		Identity: func(context.Context) agentproto.Identity {
			return agentproto.Identity{AgentID: agentID, Key: priv}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ch.Close() })
	return &env{api: api, gw: &gateway{s: srv, log: slog.New(slog.DiscardHandler), now: time.Now, nonces: map[string]time.Time{}}, ch: ch, priv: priv}
}

func TestRoundTrip(t *testing.T) {
	e := start(t)
	ctx := context.Background()

	res, err := e.ch.Poll(ctx, &dto.PollRequest{Version: "1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.LastCounter != 7 {
		t.Fatalf("poll result %+v", res)
	}
	if got := <-e.api.agents; got != agentID {
		t.Fatalf("API saw agent %q", got)
	}

	// Errors of the API reach the agent unchanged.
	_, err = e.ch.Poll(ctx, &dto.PollRequest{Version: "refuse"})
	<-e.api.agents
	if ae, ok := agentproto.AsError(err); !ok || ae.Status != http.StatusForbidden || ae.Code != agentproto.CodeAgentRevoked {
		t.Fatalf("refusal: %v", err)
	}

	// Enrollment messages travel as bytes, unsigned.
	m, err := e.ch.EnrollStart(ctx, []byte(`{"a":1}`))
	if err != nil || string(m.Body) != `echo:{"a":1}` || m.Signature != "sig" {
		t.Fatalf("enroll start: %+v %v", m, err)
	}

	d, err := e.ch.DownloadProbe(ctx, dto.Linux, dto.Amd64)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(d.Body)
	if string(b) != "linux/amd64" || d.Version != "1.2.3" {
		t.Fatalf("probe %q %q", b, d.Version)
	}
}

func TestRequestAuthentication(t *testing.T) {
	e := start(t)
	ctx := context.Background()
	signed := func(mod func(*request)) *request {
		req := &request{Op: opPoll, Body: json.RawMessage(`{"version":"1"}`), AgentID: agentID,
			Time: time.Now().Unix(), Nonce: make([]byte, 16)}
		_, _ = rand.Read(req.Nonce)
		if mod != nil {
			mod(req)
		}
		req.Signature = ed25519.Sign(e.priv, req.signedMessage())
		return req
	}
	code := func(resp *response) string {
		if resp.Err == nil {
			return ""
		}
		return resp.Err.Code
	}

	req := signed(nil)
	if resp := e.gw.serve(ctx, &connection{}, req); resp.Err != nil {
		t.Fatalf("signed request refused: %+v", resp.Err)
	}
	<-e.api.agents
	if resp := e.gw.serve(ctx, &connection{}, req); code(resp) != agentproto.CodeUnauthorized {
		t.Fatalf("replayed request: %+v", resp)
	}

	tampered := signed(nil)
	tampered.Body = json.RawMessage(`{"version":"2"}`)
	if resp := e.gw.serve(ctx, &connection{}, tampered); code(resp) != agentproto.CodeUnauthorized {
		t.Fatalf("tampered request: %+v", resp)
	}

	old := signed(func(r *request) { r.Time = time.Now().Add(-time.Hour).Unix() })
	if resp := e.gw.serve(ctx, &connection{}, old); code(resp) != agentproto.CodeUnauthorized {
		t.Fatalf("old request: %+v", resp)
	}

	other := signed(nil)
	if resp := e.gw.serve(ctx, &connection{certAgent: "someone-else"}, other); code(resp) != agentproto.CodeClientCertMismatch {
		t.Fatalf("certificate of another agent: %+v", resp)
	}
}
