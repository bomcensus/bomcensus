// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package agentapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	gen "github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/link"
	"github.com/bomcensus/bomcensus/internal/pki"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// startManager runs a reverse manager until the returned stop function is
// called.
func startManager(t *testing.T, e *env, owner string) (stop func()) {
	t.Helper()
	m, err := NewReverseManager(ReverseOptions{
		Store: e.db, Handler: e.handler, Verifier: NewAgentVerifier(e.pki),
		ClientCertificate: e.pki.AgentClientCertificate, Owner: owner,
		Interval: 200 * time.Millisecond, MinBackoff: 50 * time.Millisecond, MaxBackoff: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()
	var stopped bool
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("Run: %v", err)
		}
	}
	t.Cleanup(stop)
	return stop
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestListenModeRoundTrip(t *testing.T) {
	e := newEnv(t, envOpts{})
	ctx := context.Background()

	// Agent side: a listener with a temporary certificate feeding a
	// ReverseHolder.
	temp, err := pki.NewTemporaryCertificate()
	if err != nil {
		t.Fatal(err)
	}
	var listenerCert atomic.Pointer[tls.Certificate]
	listenerCert.Store(&temp)
	var accepted atomic.Int32
	holder := &link.ReverseHolder{DrainTimeout: time.Second}
	lctx, lcancel := context.WithCancel(ctx)
	ln, err := link.Listen(lctx, "127.0.0.1:0", link.ListenConfig{
		Certificate: func() (*tls.Certificate, error) { return listenerCert.Load(), nil },
		Verify:      link.PinnedVerifier(e.pki.pin, testServerName),
	})
	if err != nil {
		t.Fatal(err)
	}
	lnDone := make(chan error, 1)
	go func() {
		lnDone <- ln.Serve(lctx, func(c *link.ReverseConn) {
			accepted.Add(1)
			holder.Set(c)
		})
	}()
	t.Cleanup(func() {
		lcancel()
		<-lnDone
	})

	target, err := e.db.CreateListenTarget(ctx, store.ListenTarget{Address: ln.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	tok := e.newKey(t, func(k *store.RegisterKey) {
		k.AllowedCIDRs = []netip.Prefix{mustPrefix(t, "127.0.0.0/8")}
	})
	stop1 := startManager(t, e, "replica-1")

	// Enrollment over the reverse connection.
	c := e.newAgent(t, tok)
	c.connectMode = gen.Listen
	c.base = "https://" + testServerName
	c.rt = holder
	res := c.enroll(t)
	if res.finishStatus != http.StatusOK || res.result.Status != gen.EnrollStatusApproved || c.cert == nil {
		t.Fatalf("enroll: %+v", res)
	}
	if got, _ := e.db.GetListenTarget(ctx, target.ID); got.AgentID != c.id {
		t.Fatalf("target not bound: %+v", got)
	}
	a, _ := e.db.GetAgent(ctx, c.id)
	if a.ConnectMode != store.ConnectModeListen || a.ListenAddress != ":7443" {
		t.Fatalf("agent: %+v", a)
	}

	// The agent switches to the issued certificate; the server redials and
	// the identity of the new connection is the agent id.
	issued := pki.TLSCertificate([]*x509.Certificate{c.cert.Leaf}, c.key)
	listenerCert.Store(&issued)
	before := accepted.Load()
	waitUntil(t, "redial with the agent certificate", func() bool { return accepted.Load() > before })

	c.useSigned(holder, c.counter)
	c.poll(t, nil)
	if got, _ := e.db.GetListenTarget(ctx, target.ID); got.State != store.ListenConnected || got.LeaseOwner != "replica-1" {
		t.Fatalf("target: %+v", got)
	}
	if a, _ := e.db.GetAgent(ctx, c.id); a.Address != "127.0.0.1" || a.ObservedIssuer != "" {
		t.Fatalf("agent after poll: %+v", a)
	}

	// The first replica stops and releases its lease; a second one takes
	// the target over and the agent keeps working.
	stop1()
	startManager(t, e, "replica-2")
	waitUntil(t, "lease takeover", func() bool {
		got, _ := e.db.GetListenTarget(ctx, target.ID)
		return got.LeaseOwner == "replica-2" && got.State == store.ListenConnected
	})
	c.poll(t, nil)
}

func TestListenTargetBoundToOtherAgent(t *testing.T) {
	e := newEnv(t, envOpts{})
	ctx := context.Background()
	other := enrolledAgent(t, e)
	c := enrolledAgent(t, e)

	listenerCert := pki.TLSCertificate([]*x509.Certificate{c.cert.Leaf}, c.key)
	lctx, lcancel := context.WithCancel(ctx)
	ln, err := link.Listen(lctx, "127.0.0.1:0", link.ListenConfig{
		Certificate: func() (*tls.Certificate, error) { return &listenerCert, nil },
		Verify:      link.PinnedVerifier(e.pki.pin, testServerName),
	})
	if err != nil {
		t.Fatal(err)
	}
	lnDone := make(chan error, 1)
	go func() { lnDone <- ln.Serve(lctx, func(rc *link.ReverseConn) { _ = rc.Close() }) }()
	t.Cleanup(func() {
		lcancel()
		<-lnDone
	})
	target, err := e.db.CreateListenTarget(ctx, store.ListenTarget{Address: ln.Addr().String(), AgentID: other.id})
	if err != nil {
		t.Fatal(err)
	}
	startManager(t, e, "replica-1")
	waitUntil(t, "refused connection", func() bool {
		got, _ := e.db.GetListenTarget(ctx, target.ID)
		return got.State == store.ListenFailed && got.LastError != ""
	})
	if got, _ := e.db.GetListenTarget(ctx, target.ID); got.AgentID != other.id {
		t.Fatalf("binding changed: %+v", got)
	}
}
