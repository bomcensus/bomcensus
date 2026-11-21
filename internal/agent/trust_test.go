// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package agent

import (
	"context"
	"crypto/x509/pkix"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/agent/internal/fakeserver"
	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/pki"
)

func TestRenewCertDirective(t *testing.T) {
	h := newHarness(t, fakeserver.Options{})
	if err := h.enroll(nil); err != nil {
		t.Fatal(err)
	}
	_, id0, _ := loadState(t, h.stateDir)
	r := h.start(nil)
	h.wait("first poll", func() bool { return len(h.srv.Polls()) >= 1 })

	h.srv.Queue(map[string]any{"type": "renew_cert", "id": "r1", "new_key": false})
	h.wait("renewal", func() bool { return h.srv.Agents()[0].Renewals == 1 && h.srv.Acked("r1") })
	h.srv.Queue(map[string]any{"type": "renew_cert", "id": "r2", "new_key": true})
	h.wait("renewal with new key", func() bool { return h.srv.Agents()[0].Renewals == 2 && h.srv.Acked("r2") })
	n := len(h.srv.Polls())
	h.wait("polls with the new key", func() bool { return len(h.srv.Polls()) >= n+3 })
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	_, id1, _ := loadState(t, h.stateDir)
	if id1.Key.Equal(id0.Key) {
		t.Fatal("identity key did not change")
	}
	if !h.srv.Agents()[0].Pub.Equal(id1.Key.Public()) {
		t.Fatal("stored key differs from the server's")
	}
	if id1.Cert.SerialNumber.Cmp(id0.Cert.SerialNumber) == 0 || !pki.KeyMatches(id1.Cert, id1.Key) {
		t.Fatal("certificate not replaced")
	}
	if _, err := os.Stat(filepath.Join(h.stateDir, "identity-next.pem")); !os.IsNotExist(err) {
		t.Fatal("pending key file left behind")
	}
}

func TestRenewCertAfterTwoThirds(t *testing.T) {
	// Certificates are back-dated by 5 minutes, so 5 of 7 minutes have passed.
	h := newHarness(t, fakeserver.Options{CertLifetime: 7 * time.Minute})
	if err := h.enroll(nil); err != nil {
		t.Fatal(err)
	}
	h.start(nil)
	h.wait("automatic renewal", func() bool { return h.srv.Agents()[0].Renewals >= 1 })
}

func TestRecoverInterruptedKeyChange(t *testing.T) {
	h := newHarness(t, fakeserver.Options{})
	if err := h.enroll(nil); err != nil {
		t.Fatal(err)
	}
	// A key change whose request never reached the server: the pending key
	// is dropped and the old one keeps working.
	k, err := pki.GenerateAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	pem, err := pki.EncodePrivateKeyPEM(k)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.stateDir, "identity-next.pem"), pem, 0o600); err != nil {
		t.Fatal(err)
	}
	h.start(nil)
	h.wait("polls", func() bool { return len(h.srv.Polls()) >= 2 })
	if _, err := os.Stat(filepath.Join(h.stateDir, "identity-next.pem")); !os.IsNotExist(err) {
		t.Fatal("pending key not discarded")
	}
}

func TestTrustBundleSync(t *testing.T) {
	h := newHarness(t, fakeserver.Options{})
	if err := h.enroll(nil); err != nil {
		t.Fatal(err)
	}
	h.start(nil)
	h.wait("first poll", func() bool { return len(h.srv.Polls()) >= 1 })

	next, err := pki.NewCA(pki.CAOptions{Subject: pkix.Name{CommonName: "Next Agent TLS CA"}})
	if err != nil {
		t.Fatal(err)
	}
	// Announced through the configuration serial.
	h.srv.SetBundle(2, next.Cert)
	h.srv.SetConfig(func(c *agentapi.AgentConfig) { c.TrustBundleSerial = 2 })
	h.wait("bundle 2", func() bool { return lastPoll(h).TrustBundleSerial == 2 })

	// Announced through a directive.
	h.srv.SetBundle(3, next.Cert)
	h.srv.Queue(map[string]any{"type": "sync_trust_bundle", "id": "s3", "serial": 3})
	h.wait("bundle 3", func() bool { return lastPoll(h).TrustBundleSerial == 3 && h.srv.Acked("s3") })

	// A lower serial is never accepted.
	h.srv.SetBundle(1)
	h.srv.Queue(map[string]any{"type": "sync_trust_bundle", "id": "s4", "serial": 4})
	h.wait("directive acknowledged", func() bool { return h.srv.Acked("s4") })
	n := len(h.srv.Polls())
	h.wait("more polls", func() bool { return len(h.srv.Polls()) >= n+2 })
	if got := lastPoll(h).TrustBundleSerial; got != 3 {
		t.Fatalf("trust bundle serial = %d, want 3", got)
	}
	_, _, tb := loadState2(t, h.stateDir)
	if tb.Version != 3 || len(tb.Anchors) != 2 {
		t.Fatalf("stored bundle: version %d, %d anchors", tb.Version, len(tb.Anchors))
	}
}

func TestRelaxedTLSModes(t *testing.T) {
	for _, mode := range []string{"system", "none"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t, fakeserver.Options{})
			intercept := h.srv.SetIntercept()

			// Pinned verification refuses the inspection certificate.
			if err := h.enroll(nil); err == nil {
				t.Fatal("pinned enrollment through the inspection certificate succeeded")
			}

			caFile := ""
			if mode == "system" {
				caFile = filepath.Join(t.TempDir(), "ca.pem")
				if err := os.WriteFile(caFile, pki.EncodeCertificatesPEM(h.srv.InterceptCA.Cert), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			err := h.enroll(func(o *EnrollOptions) {
				o.TLSMode = mode
				o.ExtraRootsFile = caFile
			})
			if err != nil {
				t.Fatal(err)
			}
			h.start(nil)
			h.wait("report", func() bool { return len(h.srv.Reports()) >= 1 })
			p := lastPoll(h)
			if string(p.TlsMode) != mode || p.ObservedServerCert == nil || p.ObservedServerCert.Sha256 != hexFingerprint(intercept) {
				t.Fatalf("poll status: mode %s, observed %+v", p.TlsMode, p.ObservedServerCert)
			}
			assertNoSecret(t, h)
		})
	}
}

func TestListenMode(t *testing.T) {
	h := newHarness(t, fakeserver.Options{})
	var (
		mu   sync.Mutex
		addr string
	)
	setAddr := func(a net.Addr) {
		mu.Lock()
		addr = a.String()
		mu.Unlock()
	}
	getAddr := func() string {
		mu.Lock()
		defer mu.Unlock()
		return addr
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.srv.Dial(ctx, getAddr)

	err := h.enroll(func(o *EnrollOptions) {
		o.ServerURL = ""
		o.ConnectMode = "listen"
		o.ListenAddress = "127.0.0.1:0"
		o.ServerName = fakeserver.ServerName
		o.OnListening = setAddr
	})
	if err != nil {
		t.Fatal(err)
	}
	enr, id, _ := loadState(t, h.stateDir)
	if enr.ConnectMode != "listen" || id.Cert == nil {
		t.Fatalf("enrollment = %+v", enr)
	}
	mu.Lock()
	addr = ""
	mu.Unlock()

	h.start(func(o *Options) { o.Runtime.OnListening = setAddr })
	h.wait("report over the reverse connection", func() bool { return len(h.srv.Reports()) >= 1 })
	h.srv.Queue(map[string]any{"type": "collect", "id": "l1", "sections": []string{"host"}})
	h.wait("directive over the reverse connection", func() bool { return len(h.srv.Reports()) >= 2 && h.srv.Acked("l1") })
	if p := lastPoll(h); p.ConnectMode != agentapi.Listen || p.ObservedServerCert == nil {
		t.Fatalf("poll status = %+v", p)
	}
	assertNoSecret(t, h)
}

func TestListenModePendingApproval(t *testing.T) {
	h := newHarness(t, fakeserver.Options{ManualApproval: true})
	var (
		mu   sync.Mutex
		addr string
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.srv.Dial(ctx, func() string { mu.Lock(); defer mu.Unlock(); return addr })
	done := make(chan error, 1)
	go func() {
		done <- h.enroll(func(o *EnrollOptions) {
			o.ServerURL = ""
			o.ConnectMode = "listen"
			o.ListenAddress = "127.0.0.1:0"
			o.ServerName = fakeserver.ServerName
			o.OnListening = func(a net.Addr) { mu.Lock(); addr = a.String(); mu.Unlock() }
		})
	}()
	h.wait("pending", func() bool { return h.srv.EnrollResultRequests() >= 2 })
	h.srv.Approve("agent-1")
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("enrollment did not finish")
	}
}
