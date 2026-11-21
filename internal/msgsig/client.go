// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package msgsig

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// CounterSource provides the agent's monotonic request counter. The caller
// persists it.
type CounterSource interface {
	// Next returns a value greater than every value returned before and
	// greater than every value passed to Observe. It must be persisted
	// before it is returned.
	Next(ctx context.Context) (uint64, error)
	// Observe records the last counter the server accepted, taken from a
	// verified response.
	Observe(ctx context.Context, last uint64) error
}

// ServerKeys resolves the keyid of a response signature to the server's
// public key. For an unknown keyid the implementation fetches
// GET /agent/v1/server-chain (an Exempt path, or a plain client), verifies
// the chain against its trust anchors and caches the leaf key by KeyID.
type ServerKeys interface {
	ServerKey(ctx context.Context, keyID string) (crypto.PublicKey, error)
}

// Transport signs requests with the agent identity key and verifies the
// server's response signatures.
type Transport struct {
	// Base performs the requests; nil means http.DefaultTransport.
	Base http.RoundTripper
	// AgentID is the id assigned at enrollment.
	AgentID string
	// Key is the agent identity key.
	Key ed25519.PrivateKey
	// Counter supplies Bomcensus-Counter for state-changing requests.
	Counter CounterSource
	// ServerKeys resolves response keyids.
	ServerKeys ServerKeys
	// Exempt paths skip response verification; their bodies are streamed
	// through untouched.
	Exempt Paths
	// MaxRequestBody caps request bodies (default DefaultMaxRequestBody).
	MaxRequestBody int64
	// MaxResponseBody caps verified response bodies (default
	// DefaultMaxResponseBody).
	MaxResponseBody int64
	// Now is the clock for the created parameter (default time.Now).
	Now func() time.Time
}

// counterAttempts bounds the attempts of a state-changing request that is
// rejected for a stale counter. Concurrent requests of one agent can reach
// the server out of order; each retry takes a fresh, higher counter.
const counterAttempts = 4

// RoundTrip implements http.RoundTripper. A response that fails
// verification is closed and an error wrapping ErrResponseVerification is
// returned. A state-changing request rejected for a stale counter
// (409 with Bomcensus-Counter, verified) is retried after the counter
// source observed the server's value; the handler did not run for the
// rejected attempt.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := t.readBody(req)
	if err != nil {
		return nil, err
	}
	if len(t.Key) != ed25519.PrivateKeySize || !validKeyID(t.AgentID) {
		return nil, errors.New("msgsig: transport has no valid identity")
	}
	if req.URL == nil || req.URL.Opaque != "" {
		return nil, errors.New("msgsig: unsupported request URL")
	}
	for attempt := 1; ; attempt++ {
		resp, last, err := t.do(req, body)
		if err != nil {
			return nil, err
		}
		if last == 0 || t.Counter == nil {
			return resp, nil
		}
		if err := t.Counter.Observe(req.Context(), last); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("msgsig: store counter: %w", err)
		}
		if resp.StatusCode != http.StatusConflict || attempt == counterAttempts || !isStateChanging(req.Method) {
			return resp, nil
		}
		resp.Body.Close()
	}
}

func (t *Transport) readBody(req *http.Request) ([]byte, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}
	defer req.Body.Close()
	max := t.MaxRequestBody
	if max <= 0 {
		max = DefaultMaxRequestBody
	}
	b, err := io.ReadAll(io.LimitReader(req.Body, max+1))
	if err != nil {
		return nil, fmt.Errorf("msgsig: read request body: %w", err)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("msgsig: request body exceeds %d bytes", max)
	}
	return b, nil
}

// do sends one signed attempt. last is the server's counter when the
// verified response carried one.
func (t *Transport) do(req *http.Request, body []byte) (*http.Response, uint64, error) {
	ctx := req.Context()
	out := req.Clone(ctx)
	if len(body) == 0 {
		out.Body = http.NoBody
	} else {
		out.Body = io.NopCloser(bytes.NewReader(body))
	}
	out.ContentLength = int64(len(body))
	out.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }

	nonce, err := NewNonce()
	if err != nil {
		return nil, 0, err
	}
	digest := ContentDigest(body)
	path, query := splitTarget(out.URL.RequestURI())
	values := []string{out.Method, path, "?" + query, digest, t.AgentID, nonce}

	h := out.Header
	if h == nil {
		h = make(http.Header)
		out.Header = h
	}
	h.Del(HeaderCounter)
	stateChanging := isStateChanging(out.Method)
	if stateChanging {
		if t.Counter == nil {
			return nil, 0, errors.New("msgsig: no counter source for a state-changing request")
		}
		n, err := t.Counter.Next(ctx)
		if err != nil {
			return nil, 0, fmt.Errorf("msgsig: next counter: %w", err)
		}
		if n == 0 || n > 1<<63-1 {
			return nil, 0, fmt.Errorf("msgsig: counter %d out of range", n)
		}
		c := formatCounter(n)
		values = append(values, c)
		h.Set(HeaderCounter, c)
	}
	now := time.Now
	if t.Now != nil {
		now = t.Now
	}
	p := params{covered: requestCovered(stateChanging), created: now().Unix(), keyID: t.AgentID, alg: AlgEd25519}
	base, err := signatureBase(p, values)
	if err != nil {
		return nil, 0, err
	}
	h.Set(HeaderContentDigest, digest)
	h.Set(HeaderAgentID, t.AgentID)
	h.Set(HeaderNonce, nonce)
	h.Set(HeaderSignatureInput, Label+"="+p.serialize())
	h.Set(HeaderSignature, formatSignature(ed25519.Sign(t.Key, base)))
	if h.Get("Accept-Encoding") == "" {
		// The digest covers the body as sent; no transparent decompression.
		h.Set("Accept-Encoding", "identity")
	}

	base0 := t.Base
	if base0 == nil {
		base0 = http.DefaultTransport
	}
	resp, err := base0.RoundTrip(out)
	if err != nil {
		return nil, 0, err
	}
	if t.Exempt.Match(out.URL.Path) {
		return resp, 0, nil
	}
	last, err := t.verifyResponse(ctx, resp, nonce)
	if err != nil {
		resp.Body.Close()
		return nil, 0, fmt.Errorf("%w: %s %s: %w", ErrResponseVerification, out.Method, out.URL.Path, err)
	}
	return resp, last, nil
}

// verifyResponse buffers and verifies resp in place.
func (t *Transport) verifyResponse(ctx context.Context, resp *http.Response, nonce string) (uint64, error) {
	if t.ServerKeys == nil {
		return 0, errors.New("no server keys")
	}
	h := resp.Header
	digest, err := singleHeader(h, HeaderContentDigest)
	if err != nil {
		return 0, err
	}
	gotNonce, err := singleHeader(h, HeaderRequestNonce)
	if err != nil {
		return 0, err
	}
	if gotNonce != nonce {
		return 0, errors.New("response is bound to another request")
	}
	counterStr, hasCounter, err := optionalHeader(h, HeaderCounter)
	if err != nil {
		return 0, err
	}
	var last uint64
	if hasCounter {
		if last, err = parseCounter(counterStr); err != nil {
			return 0, err
		}
	}
	input, err := singleHeader(h, HeaderSignatureInput)
	if err != nil {
		return 0, err
	}
	p, err := parseSignatureInput(input, responseCovered(hasCounter))
	if err != nil {
		return 0, err
	}
	sigStr, err := singleHeader(h, HeaderSignature)
	if err != nil {
		return 0, err
	}
	sig, err := parseSignature(sigStr)
	if err != nil {
		return 0, err
	}

	max := t.MaxResponseBody
	if max <= 0 {
		max = DefaultMaxResponseBody
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return 0, fmt.Errorf("read body: %w", err)
	}
	if int64(len(body)) > max {
		return 0, fmt.Errorf("body exceeds %d bytes", max)
	}
	if digest != ContentDigest(body) {
		return 0, errors.New("content digest mismatch")
	}
	pub, err := t.ServerKeys.ServerKey(ctx, p.keyID)
	if err != nil {
		return 0, fmt.Errorf("server key %s: %w", p.keyID, err)
	}
	values := []string{strconv.Itoa(resp.StatusCode), digest, nonce}
	if hasCounter {
		values = append(values, counterStr)
	}
	base, err := signatureBase(p, values)
	if err != nil {
		return 0, err
	}
	if err := verify(pub, p.alg, base, sig); err != nil {
		return 0, err
	}
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	return last, nil
}
