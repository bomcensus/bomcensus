// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package msgsig

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/pki"
)

const testAgentID = "agent-1"

type memStore struct {
	mu       sync.Mutex
	agents   map[string]AgentKey
	counters map[string]uint64
}

func (s *memStore) lookup(_ context.Context, id string) (AgentKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.agents[id]
	if !ok {
		return AgentKey{}, ErrUnknownAgent
	}
	return k, nil
}

func (s *memStore) advance(_ context.Context, id string, n uint64) (uint64, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n <= s.counters[id] {
		return s.counters[id], false, nil
	}
	s.counters[id] = n
	return n, true, nil
}

func (s *memStore) counter(id string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counters[id]
}

func (s *memStore) setCounter(id string, n uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counters[id] = n
}

func (s *memStore) update(id string, f func(*AgentKey)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.agents[id]
	f(&k)
	s.agents[id] = k
}

func (s *memStore) remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.agents, id)
}

func (s *memStore) setState(id string, st State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.agents[id]
	k.State = st
	s.agents[id] = k
}

type memCounter struct {
	mu       sync.Mutex
	n        uint64
	observed []uint64
}

func (c *memCounter) Next(context.Context) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return c.n, nil
}

func (c *memCounter) seen() []uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]uint64(nil), c.observed...)
}

func (c *memCounter) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.observed = nil
}

func (c *memCounter) Observe(_ context.Context, last uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.observed = append(c.observed, last)
	if last > c.n {
		c.n = last
	}
	return nil
}

type keySet map[string]crypto.PublicKey

func (k keySet) ServerKey(_ context.Context, id string) (crypto.PublicKey, error) {
	if p, ok := k[id]; ok {
		return p, nil
	}
	return nil, errors.New("unknown server key")
}

// mitm sits between the transport and the network.
type mitm struct {
	base http.RoundTripper
	mu   sync.Mutex
	req  func(*http.Request)
	resp func(*http.Response)
}

func (m *mitm) set(req func(*http.Request), resp func(*http.Response)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.req, m.resp = req, resp
}

func (m *mitm) RoundTrip(r *http.Request) (*http.Response, error) {
	m.mu.Lock()
	reqHook, respHook := m.req, m.resp
	m.mu.Unlock()
	if reqHook != nil {
		reqHook(r)
	}
	resp, err := m.base.RoundTrip(r)
	if err == nil && respHook != nil {
		respHook(resp)
	}
	return resp, err
}

type env struct {
	srv      *httptest.Server
	store    *memStore
	counter  *memCounter
	tr       *Transport
	client   *http.Client
	mitm     *mitm
	handled  atomic.Int32
	release  chan struct{}
	agentKey ed25519.PrivateKey
}

type envOpts struct {
	serverKey string
	cfg       func(*Config)
	outer     func(http.Handler) http.Handler
}

func newServerKey(t *testing.T, kind string) crypto.Signer {
	t.Helper()
	var (
		k   crypto.Signer
		err error
	)
	switch kind {
	case "", "ecdsa-p256":
		k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ecdsa-p384":
		k, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "rsa":
		k, err = rsa.GenerateKey(rand.Reader, 2048)
	case "ed25519":
		_, k, err = ed25519.GenerateKey(rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	return k
}

const downloadSize = 4 << 20

func newEnv(t *testing.T, o envOpts) *env {
	t.Helper()
	ca, err := pki.NewCA(pki.CAOptions{Subject: pkix.Name{CommonName: "Test Agent TLS CA"}})
	if err != nil {
		t.Fatal(err)
	}
	skey := newServerKey(t, o.serverKey)
	leaf, err := ca.IssueServer(skey.Public(), pki.LeafOptions{DNSNames: []string{"agents.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewServerSigner(leaf, skey)
	if err != nil {
		t.Fatal(err)
	}
	apub, akey, _ := ed25519.GenerateKey(rand.Reader)

	e := &env{
		store: &memStore{
			agents:   map[string]AgentKey{testAgentID: {PublicKey: apub, State: StateApproved}},
			counters: map[string]uint64{},
		},
		counter:  &memCounter{},
		release:  make(chan struct{}),
		agentKey: akey,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /agent/v1/trust-bundle", func(w http.ResponseWriter, r *http.Request) {
		e.handled.Add(1)
		a, _ := AgentFromContext(r.Context())
		fmt.Fprintf(w, "bundle for %s", a.ID)
	})
	mux.HandleFunc("POST /agent/v1/reports", func(w http.ResponseWriter, r *http.Request) {
		e.handled.Add(1)
		a, _ := AgentFromContext(r.Context())
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, "%d bytes from %s: %s", len(b), a.ID, b)
	})
	mux.HandleFunc("GET /agent/v1/enroll/result", func(w http.ResponseWriter, r *http.Request) {
		e.handled.Add(1)
		io.WriteString(w, `{"status":"pending"}`)
	})
	mux.HandleFunc("POST /agent/v1/enroll/start", func(w http.ResponseWriter, r *http.Request) {
		e.handled.Add(1)
		if _, ok := AgentFromContext(r.Context()); ok {
			t.Error("bypass path has an agent identity")
		}
		io.WriteString(w, "start")
	})
	mux.HandleFunc("GET /agent/v1/big", func(w http.ResponseWriter, r *http.Request) {
		e.handled.Add(1)
		w.Write(make([]byte, 2<<20))
	})
	mux.HandleFunc("GET /agent/v1/update/bundle/{version}", func(w http.ResponseWriter, r *http.Request) {
		e.handled.Add(1)
		chunk := bytes.Repeat([]byte{'x'}, 64<<10)
		w.Header().Set("Content-Length", fmt.Sprint(downloadSize))
		w.Write(chunk)
		w.(http.Flusher).Flush()
		select {
		case <-e.release:
		case <-time.After(10 * time.Second):
			t.Error("client did not receive the first chunk while streaming")
			return
		}
		for n := len(chunk); n < downloadSize; n += len(chunk) {
			w.Write(chunk)
		}
	})

	cfg := Config{
		KeyLookup:       e.store.lookup,
		AdvanceCounter:  e.store.advance,
		Signer:          func(context.Context) (*ServerSigner, error) { return signer, nil },
		Bypass:          Paths{"/agent/v1/enroll/start", "/agent/v1/enroll/finish", "/agent/v1/server-chain"},
		Exempt:          Paths{"/agent/v1/update/bundle/"},
		PendingAllowed:  Paths{"/agent/v1/enroll/result"},
		MaxResponseBody: 1 << 20,
	}
	if o.cfg != nil {
		o.cfg(&cfg)
	}
	mw, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var h http.Handler = mw.Wrap(mux)
	if o.outer != nil {
		h = o.outer(h)
	}
	e.srv = httptest.NewServer(h)
	t.Cleanup(e.srv.Close)

	e.mitm = &mitm{base: e.srv.Client().Transport}
	e.tr = &Transport{
		Base:       e.mitm,
		AgentID:    testAgentID,
		Key:        akey,
		Counter:    e.counter,
		ServerKeys: keySet{signer.KeyID(): skey.Public()},
		Exempt:     Paths{"/agent/v1/update/bundle/", "/agent/v1/server-chain"},
	}
	e.client = &http.Client{Transport: e.tr}
	return e
}

func (e *env) get(t *testing.T, path string) (*http.Response, []byte, error) {
	t.Helper()
	return e.do(t, http.MethodGet, path, nil)
}

func (e *env) do(t *testing.T, method, path string, body []byte) (*http.Response, []byte, error) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, b, nil
}

func errorCode(t *testing.T, b []byte) string {
	t.Helper()
	var e struct{ Code string }
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatalf("error body %q: %v", b, err)
	}
	return e.Code
}

func expectStatus(t *testing.T, resp *http.Response, body []byte, err error, status int, code string) {
	t.Helper()
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != status {
		t.Fatalf("status %d, want %d (%s)", resp.StatusCode, status, body)
	}
	if code != "" {
		if got := errorCode(t, body); got != code {
			t.Fatalf("code %q, want %q", got, code)
		}
	}
}

func TestHappyPath(t *testing.T) {
	for _, kind := range []string{"ecdsa-p256", "ecdsa-p384", "rsa", "ed25519"} {
		t.Run(kind, func(t *testing.T) {
			e := newEnv(t, envOpts{serverKey: kind})

			resp, b, err := e.get(t, "/agent/v1/trust-bundle")
			expectStatus(t, resp, b, err, http.StatusOK, "")
			if string(b) != "bundle for "+testAgentID {
				t.Fatalf("body %q", b)
			}
			if resp.Header.Get(HeaderSignature) == "" {
				t.Fatal("response not signed")
			}

			resp, b, err = e.get(t, "/agent/v1/trust-bundle?since=3&x=a%20b")
			expectStatus(t, resp, b, err, http.StatusOK, "")

			for i := 1; i <= 3; i++ {
				resp, b, err = e.do(t, http.MethodPost, "/agent/v1/reports", []byte("report"))
				expectStatus(t, resp, b, err, http.StatusAccepted, "")
				if string(b) != "6 bytes from agent-1: report" {
					t.Fatalf("body %q", b)
				}
				if e.store.counter(testAgentID) != uint64(i) {
					t.Fatalf("server counter %d, want %d", e.store.counter(testAgentID), i)
				}
			}

			// Empty POST body: digest of the empty string.
			resp, b, err = e.do(t, http.MethodPost, "/agent/v1/reports", nil)
			expectStatus(t, resp, b, err, http.StatusAccepted, "")

			// Bypass path: no verification, no signature.
			resp, err = http.Post(e.srv.URL+"/agent/v1/enroll/start", "application/json", strings.NewReader("{}"))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK || resp.Header.Get(HeaderSignature) != "" {
				t.Fatalf("bypass: status %d, signature %q", resp.StatusCode, resp.Header.Get(HeaderSignature))
			}
		})
	}
}

func TestConcurrent(t *testing.T) {
	e := newEnv(t, envOpts{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, b, err := e.do(t, http.MethodPost, "/agent/v1/reports", []byte("r"))
			if err != nil || resp.StatusCode != http.StatusAccepted {
				t.Errorf("concurrent POST: %v %v %s", err, resp, b)
			}
		}()
	}
	wg.Wait()
}

func replaceBody(r *http.Request, b []byte) {
	r.Body = io.NopCloser(bytes.NewReader(b))
	r.ContentLength = int64(len(b))
}

func TestRequestTamper(t *testing.T) {
	e := newEnv(t, envOpts{})
	cases := []struct {
		name   string
		tamper func(*http.Request)
		status int
		code   string
	}{
		{"body", func(r *http.Request) { replaceBody(r, []byte("REPORT")) }, http.StatusBadRequest, CodeDigestMismatch},
		{"body and digest", func(r *http.Request) {
			replaceBody(r, []byte("REPORT"))
			r.Header.Set(HeaderContentDigest, ContentDigest([]byte("REPORT")))
		}, http.StatusUnauthorized, CodeUnauthorized},
		{"counter", func(r *http.Request) { r.Header.Set(HeaderCounter, "999") }, http.StatusUnauthorized, CodeUnauthorized},
		{"counter removed", func(r *http.Request) { r.Header.Del(HeaderCounter) }, http.StatusBadRequest, CodeInvalidRequest},
		{"agent id", func(r *http.Request) { r.Header.Set(HeaderAgentID, "agent-2") }, http.StatusUnauthorized, CodeUnauthorized},
		{"path", func(r *http.Request) { r.URL.Path = "/agent/v1/reportz" }, http.StatusUnauthorized, CodeUnauthorized},
		{"query", func(r *http.Request) { r.URL.RawQuery = "x=1" }, http.StatusUnauthorized, CodeUnauthorized},
		{"method", func(r *http.Request) { r.Method = http.MethodPut }, http.StatusUnauthorized, CodeUnauthorized},
		{"created", func(r *http.Request) {
			r.Header.Set(HeaderSignatureInput, strings.Replace(r.Header.Get(HeaderSignatureInput), "created=1", "created=2", 1))
		}, http.StatusUnauthorized, CodeUnauthorized},
		{"duplicate signature", func(r *http.Request) { r.Header.Add(HeaderSignature, r.Header.Get(HeaderSignature)) }, http.StatusBadRequest, CodeInvalidRequest},
		{"signature", func(r *http.Request) {
			r.Header.Set(HeaderSignature, formatSignature(make([]byte, 64)))
		}, http.StatusUnauthorized, CodeUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e.mitm.set(tc.tamper, nil)
			before := e.handled.Load()
			resp, b, err := e.do(t, http.MethodPost, "/agent/v1/reports", []byte("report"))
			expectStatus(t, resp, b, err, tc.status, tc.code)
			if e.handled.Load() != before {
				t.Fatal("handler ran for a tampered request")
			}
		})
	}
	// Header tamper on GET: the nonce is covered.
	e.mitm.set(func(r *http.Request) {
		n, _ := NewNonce()
		r.Header.Set(HeaderNonce, n)
	}, nil)
	_, _, err := e.get(t, "/agent/v1/trust-bundle")
	// The server binds its error to the substituted nonce, which the
	// client does not accept.
	if !errors.Is(err, ErrResponseVerification) {
		t.Fatalf("got %v, want ErrResponseVerification", err)
	}
}

// capture records the request headers and body as sent on the wire.
type capture struct {
	header http.Header
	body   []byte
	method string
	url    string
}

func captureHook(c *capture) func(*http.Request) {
	return func(r *http.Request) {
		c.header = r.Header.Clone()
		c.method, c.url = r.Method, r.URL.String()
		if r.Body != nil {
			c.body, _ = io.ReadAll(r.Body)
			replaceBody(r, c.body)
		}
	}
}

func (c *capture) replay(t *testing.T) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(c.method, c.url, bytes.NewReader(c.body))
	req.Header = c.header.Clone()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func TestReplayedRequest(t *testing.T) {
	e := newEnv(t, envOpts{})
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		t.Run(m, func(t *testing.T) {
			var c capture
			e.mitm.set(captureHook(&c), nil)
			path := "/agent/v1/trust-bundle"
			var body []byte
			want := http.StatusOK
			if m == http.MethodPost {
				path, body, want = "/agent/v1/reports", []byte("report"), http.StatusAccepted
			}
			resp, b, err := e.do(t, m, path, body)
			expectStatus(t, resp, b, err, want, "")
			e.mitm.set(nil, nil)
			before := e.handled.Load()
			resp, b = c.replay(t)
			expectStatus(t, resp, b, nil, http.StatusUnauthorized, CodeNonceReplayed)
			if e.handled.Load() != before {
				t.Fatal("handler ran for a replayed request")
			}
		})
	}
}

func TestStaleCounterResync(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.store.setCounter(testAgentID, 100) // agent lost its counter (disk restore)
	before := e.handled.Load()
	resp, b, err := e.do(t, http.MethodPost, "/agent/v1/reports", []byte("report"))
	expectStatus(t, resp, b, err, http.StatusAccepted, "")
	if e.handled.Load()-before != 1 {
		t.Fatalf("handler ran %d times", e.handled.Load()-before)
	}
	if got := e.store.counter(testAgentID); got != 101 {
		t.Fatalf("server counter %d, want 101", got)
	}
	if seen := e.counter.seen(); len(seen) != 1 || seen[0] != 100 {
		t.Fatalf("observed %v", seen)
	}

	// The rejection itself is signed and carries the counter.
	var got http.Header
	e.store.setCounter(testAgentID, 500)
	e.mitm.set(nil, func(r *http.Response) {
		if r.StatusCode == http.StatusConflict {
			got = r.Header.Clone()
		}
	})
	resp, b, err = e.do(t, http.MethodPost, "/agent/v1/reports", []byte("report"))
	expectStatus(t, resp, b, err, http.StatusAccepted, "")
	if got.Get(HeaderCounter) != "500" || !strings.Contains(got.Get(HeaderSignatureInput), `"bomcensus-counter"`) {
		t.Fatalf("rejection headers %v", got)
	}

	// A forged, unsigned rejection must not move the counter.
	e.counter.reset()
	e.mitm.set(nil, func(r *http.Response) {
		r.StatusCode = http.StatusConflict
		r.Header.Set(HeaderCounter, "100000")
	})
	_, _, err = e.do(t, http.MethodPost, "/agent/v1/reports", []byte("report"))
	if !errors.Is(err, ErrResponseVerification) {
		t.Fatalf("got %v, want ErrResponseVerification", err)
	}
	if seen := e.counter.seen(); len(seen) != 0 {
		t.Fatalf("forged counter observed: %v", seen)
	}
}

func TestResponseTamper(t *testing.T) {
	e := newEnv(t, envOpts{})
	cases := map[string]func(*http.Response){
		"body": func(r *http.Response) {
			b, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(append(b, '!')))
		},
		"body and digest": func(r *http.Response) {
			r.Body = io.NopCloser(strings.NewReader("forged"))
			r.Header.Set(HeaderContentDigest, ContentDigest([]byte("forged")))
		},
		"status":            func(r *http.Response) { r.StatusCode = http.StatusNotFound },
		"signature removed": func(r *http.Response) { r.Header.Del(HeaderSignature) },
		"unsigned":          func(r *http.Response) { r.Header.Del(HeaderSignature); r.Header.Del(HeaderSignatureInput) },
		"counter added": func(r *http.Response) {
			r.Header.Set(HeaderCounter, "7")
		},
		"unknown keyid": func(r *http.Response) {
			in := r.Header.Get(HeaderSignatureInput)
			i := strings.Index(in, `keyid="`) + len(`keyid="`)
			r.Header.Set(HeaderSignatureInput, in[:i]+"AAAA"+in[i+4:])
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			e.mitm.set(nil, tamper)
			resp, _, err := e.get(t, "/agent/v1/trust-bundle")
			if !errors.Is(err, ErrResponseVerification) || resp != nil {
				t.Fatalf("got %v, want ErrResponseVerification", err)
			}
		})
	}
}

func TestResponseReplay(t *testing.T) {
	e := newEnv(t, envOpts{})
	var saved *http.Response
	var savedBody []byte
	e.mitm.set(nil, func(r *http.Response) {
		savedBody, _ = io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(savedBody))
		saved = &http.Response{StatusCode: r.StatusCode, Header: r.Header.Clone()}
	})
	resp, b, err := e.get(t, "/agent/v1/trust-bundle")
	expectStatus(t, resp, b, err, http.StatusOK, "")

	e.mitm.set(nil, func(r *http.Response) {
		r.StatusCode = saved.StatusCode
		r.Header = saved.Header.Clone()
		r.Body = io.NopCloser(bytes.NewReader(savedBody))
	})
	_, _, err = e.get(t, "/agent/v1/trust-bundle")
	if !errors.Is(err, ErrResponseVerification) || !strings.Contains(err.Error(), "another request") {
		t.Fatalf("got %v, want binding failure", err)
	}
}

func TestAgentStates(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.store.setState(testAgentID, StatePending)
	resp, b, err := e.get(t, "/agent/v1/enroll/result")
	expectStatus(t, resp, b, err, http.StatusOK, "")
	resp, b, err = e.get(t, "/agent/v1/trust-bundle")
	expectStatus(t, resp, b, err, http.StatusForbidden, CodeAgentPending)
	resp, b, err = e.do(t, http.MethodPost, "/agent/v1/reports", []byte("r"))
	expectStatus(t, resp, b, err, http.StatusForbidden, CodeAgentPending)
	if e.store.counter(testAgentID) != 0 {
		t.Fatal("forbidden request consumed a counter")
	}

	e.store.setState(testAgentID, StateRevoked)
	resp, b, err = e.get(t, "/agent/v1/enroll/result")
	expectStatus(t, resp, b, err, http.StatusForbidden, CodeAgentRevoked)
	resp, b, err = e.get(t, "/agent/v1/trust-bundle")
	expectStatus(t, resp, b, err, http.StatusForbidden, CodeAgentRevoked)

	e.store.remove(testAgentID)
	resp, b, err = e.get(t, "/agent/v1/trust-bundle")
	expectStatus(t, resp, b, err, http.StatusUnauthorized, CodeUnauthorized)
}

func TestExemptDownloadStreams(t *testing.T) {
	e := newEnv(t, envOpts{})
	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/agent/v1/update/bundle/1.2.3", nil)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get(HeaderSignature) != "" {
		t.Fatal("exempt response is signed")
	}
	first := make([]byte, 64<<10)
	if _, err := io.ReadFull(resp.Body, first); err != nil {
		t.Fatal(err)
	}
	close(e.release)
	rest, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	// Larger than MaxResponseBody on both sides: not buffered.
	if int(rest)+len(first) != downloadSize {
		t.Fatalf("got %d bytes", int(rest)+len(first))
	}
}

func TestOversizedBody(t *testing.T) {
	e := newEnv(t, envOpts{cfg: func(c *Config) { c.MaxRequestBody = 1024 }})
	resp, b, err := e.do(t, http.MethodPost, "/agent/v1/reports", make([]byte, 2048))
	expectStatus(t, resp, b, err, http.StatusRequestEntityTooLarge, CodeBodyTooLarge)

	// Without Content-Length (chunked) the limit applies while reading.
	e.mitm.set(func(r *http.Request) { r.ContentLength = -1 }, nil)
	resp, b, err = e.do(t, http.MethodPost, "/agent/v1/reports", make([]byte, 2048))
	expectStatus(t, resp, b, err, http.StatusRequestEntityTooLarge, CodeBodyTooLarge)
	e.mitm.set(nil, nil)

	if e.store.counter(testAgentID) != 0 {
		t.Fatal("oversized request consumed a counter")
	}

	e.tr.MaxRequestBody = 512
	if _, _, err := e.do(t, http.MethodPost, "/agent/v1/reports", make([]byte, 1024)); err == nil {
		t.Fatal("client sent a body above its limit")
	}
}

func TestResponseTooLarge(t *testing.T) {
	e := newEnv(t, envOpts{})
	resp, b, err := e.get(t, "/agent/v1/big")
	expectStatus(t, resp, b, err, http.StatusInternalServerError, CodeInternal)
}

func TestClockSkew(t *testing.T) {
	e := newEnv(t, envOpts{cfg: func(c *Config) {
		c.Now = func() time.Time { return time.Now().Add(10 * time.Minute) }
	}})
	resp, b, err := e.get(t, "/agent/v1/trust-bundle")
	expectStatus(t, resp, b, err, http.StatusUnauthorized, CodeUnauthorized)
}

func TestTLSPeerBinding(t *testing.T) {
	peer := ""
	var mu sync.Mutex
	e := newEnv(t, envOpts{outer: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			p := peer
			mu.Unlock()
			if p != "" {
				r = r.WithContext(WithTLSPeerAgentID(r.Context(), p))
			}
			next.ServeHTTP(w, r)
		})
	}})
	set := func(p string) { mu.Lock(); peer = p; mu.Unlock() }

	set(testAgentID)
	resp, b, err := e.get(t, "/agent/v1/trust-bundle")
	expectStatus(t, resp, b, err, http.StatusOK, "")

	set("agent-2")
	resp, b, err = e.get(t, "/agent/v1/trust-bundle")
	expectStatus(t, resp, b, err, http.StatusForbidden, CodeClientCertMismatch)

	set("")
	e.store.update(testAgentID, func(k *AgentKey) { k.RequireTLSClientCert = true })
	resp, b, err = e.get(t, "/agent/v1/trust-bundle")
	expectStatus(t, resp, b, err, http.StatusForbidden, CodeClientCertMismatch)
}

func TestNonCanonicalPathRejected(t *testing.T) {
	e := newEnv(t, envOpts{})
	for _, p := range []string{"/agent/v1/enroll/start/../../reports", "/agent/v1/trust%2Dbundle", "/agent/v1//trust-bundle"} {
		req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/", nil)
		req.URL.Opaque = p // sent as the request target verbatim
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest || errorCode(t, b) != CodeInvalidRequest {
			t.Errorf("%s: status %d %s", p, resp.StatusCode, b)
		}
	}
}

// levelCounter counts "agent request rejected" records per level.
type levelCounter struct {
	mu     sync.Mutex
	counts map[slog.Level]int
}

func (c *levelCounter) Enabled(context.Context, slog.Level) bool { return true }
func (c *levelCounter) WithAttrs([]slog.Attr) slog.Handler       { return c }
func (c *levelCounter) WithGroup(string) slog.Handler            { return c }
func (c *levelCounter) Handle(_ context.Context, r slog.Record) error {
	if r.Message != "agent request rejected" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.counts == nil {
		c.counts = map[slog.Level]int{}
	}
	c.counts[r.Level]++
	return nil
}

func (c *levelCounter) get(l slog.Level) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[l]
}

func TestTLSPeerFailure(t *testing.T) {
	var failure atomic.Int32
	logs := &levelCounter{}
	e := newEnv(t, envOpts{
		cfg: func(c *Config) { c.Logger = slog.New(logs) },
		outer: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if f := TLSPeerFailure(failure.Load()); f != 0 {
					r = r.WithContext(WithTLSPeerFailure(r.Context(), f))
				}
				next.ServeHTTP(w, r)
			})
		},
	})

	failure.Store(int32(TLSPeerRevoked))
	for range 3 {
		resp, b, err := e.do(t, http.MethodPost, "/agent/v1/reports", []byte("r"))
		expectStatus(t, resp, b, err, http.StatusForbidden, CodeAgentRevoked)
	}
	if e.handled.Load() != 0 || e.store.counter(testAgentID) != 0 {
		t.Fatal("rejected request reached the handler or consumed a counter")
	}
	if logs.get(slog.LevelInfo) != 1 || logs.get(slog.LevelWarn) != 0 {
		t.Fatalf("revoked rejections logged info=%d warn=%d, want one info record",
			logs.get(slog.LevelInfo), logs.get(slog.LevelWarn))
	}

	failure.Store(int32(TLSPeerInvalid))
	resp, b, err := e.get(t, "/agent/v1/trust-bundle")
	expectStatus(t, resp, b, err, http.StatusForbidden, CodeClientCertMismatch)
	if logs.get(slog.LevelInfo) != 2 {
		t.Fatalf("certificate mismatch not logged once at info: %d", logs.get(slog.LevelInfo))
	}

	failure.Store(int32(TLSPeerCheckFailed))
	resp, b, err = e.get(t, "/agent/v1/trust-bundle")
	expectStatus(t, resp, b, err, http.StatusInternalServerError, CodeInternal)

	// A revoked agent state is logged the same way.
	failure.Store(0)
	e.store.setState(testAgentID, StateRevoked)
	for range 2 {
		resp, b, err = e.get(t, "/agent/v1/trust-bundle")
		expectStatus(t, resp, b, err, http.StatusForbidden, CodeAgentRevoked)
	}
	if logs.get(slog.LevelInfo) != 2 || logs.get(slog.LevelWarn) != 0 {
		t.Fatalf("revoked state logged info=%d warn=%d", logs.get(slog.LevelInfo), logs.get(slog.LevelWarn))
	}
	if e.handled.Load() != 0 {
		t.Fatal("rejected request reached the handler")
	}
}
