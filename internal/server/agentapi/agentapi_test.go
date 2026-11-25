// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package agentapi

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	gen "github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/msgsig"
	"github.com/bomcensus/bomcensus/internal/pki"
	"github.com/bomcensus/bomcensus/internal/server/dispatch"
	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/internal/token"
)

// enrolledAgent enrolls an agent with an auto-approving key and returns it
// with a signed connect-mode client.
func enrolledAgent(t *testing.T, e *env) *agentClient {
	t.Helper()
	c := e.newAgent(t, e.newKey(t, nil))
	res := c.enroll(t)
	if res.finishStatus != http.StatusOK || res.result.Status != gen.EnrollStatusApproved {
		t.Fatalf("enroll: %+v", res)
	}
	c.connectSigned(t)
	return c
}

func TestEnrollAutoApproved(t *testing.T) {
	e := newEnv(t, envOpts{})
	ctx := context.Background()
	c := e.newAgent(t, e.newKey(t, func(k *store.RegisterKey) {
		k.AllowedCIDRs = []netip.Prefix{mustPrefix(t, "127.0.0.0/8")}
		k.MaxUses = 1
	}))
	res := c.enroll(t)
	if res.finishStatus != http.StatusOK || res.result.Status != gen.EnrollStatusApproved || res.result.Certificate == nil ||
		res.result.AgentCa == nil || res.result.TrustBundle == nil {
		t.Fatalf("enroll: %+v", res)
	}
	cert, _ := x509.ParseCertificate(*res.result.Certificate)
	if id, err := pki.VerifyAgent([]*x509.Certificate{cert}, e.pki.agentCA.Cert, x509.ExtKeyUsageClientAuth); err != nil || id != c.id {
		t.Fatalf("certificate: %v %q", err, id)
	}

	a, err := e.db.GetAgent(ctx, c.id)
	if err != nil || a.State != store.AgentApproved || a.Hostname != "node-1" || a.CertNotAfter == nil || a.Address != "127.0.0.1" {
		t.Fatalf("agent: %+v %v", a, err)
	}
	en, err := e.db.GetAgentEnrollment(ctx, c.id)
	if err != nil || en.DefaultGroup != "web" || !slices.Equal(en.DefaultTags, []string{"prod"}) || en.AllowRelaxedTLS {
		t.Fatalf("enrollment record: %+v %v", en, err)
	}
	if k, _ := e.db.GetRegisterKey(ctx, c.tok.KeyID.String()); k.UsedCount != 1 {
		t.Fatalf("key used %d times", k.UsedCount)
	}

	c.connectSigned(t)
	res2 := c.poll(t, nil)
	if res2.Config.SectionIntervals.Processes != DefaultProcessesInterval || res2.Config.UpdateCheckIntervalMinutes != 60 ||
		res2.LastCounter == 0 || len(res2.Directives) != 0 {
		t.Fatalf("poll: %+v", res2)
	}
	if a, _ := e.db.GetAgent(ctx, c.id); a.LastSeen == nil || a.Privilege != store.PrivilegeNonRoot || a.ObservedIssuer != "" {
		t.Fatalf("after poll: %+v", a)
	}

	// The unsigned server chain is the signing chain.
	resp, body, err := c.do(t, http.MethodGet, "/agent/v1/trust-bundle", nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("trust bundle: %v %v", resp, err)
	}
	var tb gen.TrustBundle
	if err := json.Unmarshal(body, &tb); err != nil || tb.Serial != 1 || len(tb.Anchors) != 1 {
		t.Fatalf("trust bundle: %+v %v", tb, err)
	}

	// Renewal for the same key works, a CSR for another key does not.
	resp, body, err = c.do(t, http.MethodPost, "/agent/v1/cert/renew", []byte(`{}`))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("renew: %v %v %s", resp, err, body)
	}
	other, _ := pki.GenerateAgentKey()
	csr, _ := pki.CreateAgentCSR(other)
	b, _ := json.Marshal(gen.CertRenewRequest{Csr: &csr})
	if resp, _, err = c.do(t, http.MethodPost, "/agent/v1/cert/renew", b); err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("renew with another key: %v %v", resp, err)
	}
}

func TestEnrollPendingThenApproved(t *testing.T) {
	e := newEnv(t, envOpts{})
	ctx := context.Background()
	c := e.newAgent(t, e.newKey(t, func(k *store.RegisterKey) { k.Approval = store.ApprovalManual }))
	res := c.enroll(t)
	if res.finishStatus != http.StatusOK || res.result.Status != gen.EnrollStatusPending || res.result.Certificate != nil ||
		res.result.RetryAfterSeconds == nil || *res.result.RetryAfterSeconds != 10 {
		t.Fatalf("enroll: %+v", res)
	}
	c.connectSigned(t)

	result := func() gen.EnrollResult {
		t.Helper()
		resp, body, err := c.do(t, http.MethodGet, "/agent/v1/enroll/result", nil)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("result: %v %v %s", resp, err, body)
		}
		var r gen.EnrollResult
		if err := json.Unmarshal(body, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := result(); r.Status != gen.EnrollStatusPending {
		t.Fatalf("result before approval: %+v", r)
	}
	resp, body, err := c.do(t, http.MethodPost, "/agent/v1/poll", c.pollBody(t, nil, 1))
	if err != nil || resp.StatusCode != http.StatusForbidden || errorCode(t, body) != msgsig.CodeAgentPending {
		t.Fatalf("poll while pending: %v %v %s", resp, err, body)
	}

	if err := e.db.ApproveAgent(ctx, c.id, time.Now()); err != nil {
		t.Fatal(err)
	}
	r := result()
	if r.Status != gen.EnrollStatusApproved || r.Certificate == nil || r.TrustBundle == nil {
		t.Fatalf("result after approval: %+v", r)
	}
	c.setCert(t, *r.Certificate)
	c.connectSigned(t) // new connections present the certificate
	c.poll(t, nil)
}

func TestEnrollRefused(t *testing.T) {
	e := newEnv(t, envOpts{})
	ctx := context.Background()

	revoked := e.newKey(t, nil)
	if err := e.db.RevokeRegisterKey(ctx, revoked.KeyID.String(), time.Now()); err != nil {
		t.Fatal(err)
	}
	exhausted := e.newKey(t, func(k *store.RegisterKey) { k.MaxUses = 1 })
	if res := e.newAgent(t, exhausted).enroll(t); res.result.Status != gen.EnrollStatusApproved {
		t.Fatalf("first use: %+v", res)
	}
	wrongRange := e.newKey(t, func(k *store.RegisterKey) { k.AllowedCIDRs = []netip.Prefix{mustPrefix(t, "10.0.0.0/8")} })
	scannerKey := e.newKey(t, func(k *store.RegisterKey) { k.Target = store.AgentKindScanner })
	expired := e.newKey(t, func(k *store.RegisterKey) { past := time.Now().Add(-time.Minute); k.ExpiresAt = &past })

	for name, tok := range map[string]token.Token{"revoked": revoked, "exhausted": exhausted, "source range": wrongRange,
		"kind": scannerKey, "expired": expired} {
		t.Run(name, func(t *testing.T) {
			c := e.newAgent(t, tok)
			res := c.enroll(t)
			if res.startStatus != http.StatusForbidden || res.errorCode != "enrollment_refused" {
				t.Fatalf("got %+v", res)
			}
		})
	}

	t.Run("replayed finish", func(t *testing.T) {
		c := e.newAgent(t, e.newKey(t, nil))
		res := c.enroll(t)
		if res.result.Status != gen.EnrollStatusApproved {
			t.Fatalf("enroll: %+v", res)
		}
		status, body, _ := c.post(t, "/agent/v1/enroll/finish", res.finishBody)
		if status != http.StatusForbidden || errorCode(t, body) != "enrollment_refused" {
			t.Fatalf("replay: %d %s", status, body)
		}
	})

	t.Run("listen mode over connect", func(t *testing.T) {
		c := e.newAgent(t, e.newKey(t, nil))
		c.connectMode = gen.Listen
		if res := c.enroll(t); res.startStatus != http.StatusForbidden {
			t.Fatalf("got %+v", res)
		}
	})
}

func TestEnrollRateLimited(t *testing.T) {
	e := newEnv(t, envOpts{maxFailures: 2})
	tok := e.newKey(t, func(k *store.RegisterKey) { k.Target = store.AgentKindScanner })
	for i := 0; i < 2; i++ {
		if res := e.newAgent(t, tok).enroll(t); res.startStatus != http.StatusForbidden {
			t.Fatalf("attempt %d: %+v", i, res)
		}
	}
	c := e.newAgent(t, tok)
	status, _, h := c.post(t, "/agent/v1/enroll/start", c.startBody(t))
	if status != http.StatusTooManyRequests || h.Get("Retry-After") == "" {
		t.Fatalf("status %d, Retry-After %q", status, h.Get("Retry-After"))
	}
}

func TestPollDeliversDirective(t *testing.T) {
	e := newEnv(t, envOpts{pollTimeout: 3 * time.Second})
	ctx := context.Background()
	c := enrolledAgent(t, e)

	type result struct {
		res     gen.PollResult
		elapsed time.Duration
	}
	ch := make(chan result, 1)
	go func() {
		start := time.Now()
		r := c.poll(t, nil)
		ch <- result{r, time.Since(start)}
	}()
	time.Sleep(300 * time.Millisecond)
	var body gen.Directive
	if err := body.FromCollectDirective(gen.CollectDirective{Sections: []gen.SectionName{"packages"}}); err != nil {
		t.Fatal(err)
	}
	id, err := e.dispatch.Enqueue(ctx, c.id, dispatch.Directive{Body: body})
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	ids, types := directiveIDs(t, r.res.Directives)
	if !slices.Equal(ids, []string{id}) || !slices.Equal(types, []string{"collect"}) || r.elapsed > 2*time.Second {
		t.Fatalf("poll: ids %v types %v after %s", ids, types, r.elapsed)
	}
	got, _ := r.res.Directives[0].AsCollectDirective()
	if !slices.Equal(got.Sections, []gen.SectionName{"packages"}) {
		t.Fatalf("directive: %+v", got)
	}

	// Not acknowledged: delivered again at once.
	if ids, _ := directiveIDs(t, c.poll(t, nil).Directives); !slices.Equal(ids, []string{id}) {
		t.Fatalf("redelivery: %v", ids)
	}

	// A directive written by another replica (no notification) is found
	// by the periodic re-check; the acknowledged one is gone.
	go func() {
		time.Sleep(300 * time.Millisecond)
		if _, _, err := e.db.EnqueueDirective(ctx, store.Directive{AgentID: c.id, Type: "collect",
			Payload: json.RawMessage(`{"type":"collect","sections":[]}`)}); err != nil {
			t.Error(err)
		}
	}()
	r2 := c.poll(t, []string{id})
	ids, _ = directiveIDs(t, r2.Directives)
	if len(ids) != 1 || ids[0] == id {
		t.Fatalf("after ack: %v", ids)
	}

	// RequestCollect finds the asset's agent.
	asset, err := e.db.UpsertHostAsset(ctx, store.HostIdentity{AgentID: c.id}, store.AssetInit{Name: "node-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.dispatch.RequestCollect(ctx, asset.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.dispatch.RequestCollect(ctx, asset.ID); err != nil { // deduplicated
		t.Fatal(err)
	}
	pending, _ := e.db.ListPendingDirectives(ctx, c.id, time.Now(), 0)
	if len(pending) != 2 {
		t.Fatalf("pending after collect requests: %d", len(pending))
	}
	other, err := e.db.UpsertHostAsset(ctx, store.HostIdentity{MachineID: "m-1"}, store.AssetInit{Name: "agentless"})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.dispatch.RequestCollect(ctx, other.ID); !errors.Is(err, dispatch.ErrNotAgentBacked) {
		t.Fatalf("agentless asset: %v", err)
	}
}

func TestPollStoresUpdateStatus(t *testing.T) {
	e := newEnv(t, envOpts{})
	c := enrolledAgent(t, e)
	send := func(st gen.UpdateState, msg *string) {
		t.Helper()
		req := gen.PollRequest{
			Version: "0.2.0", Os: gen.Linux, Arch: gen.Amd64, ConnectMode: gen.Connect, TlsMode: gen.Pinned,
			Privilege:      gen.Privilege{Level: gen.PrivilegeLevel("non_root"), Uid: 1000},
			SectionDigests: map[string]string{}, TrustBundleSerial: 1,
			Update: gen.UpdateStatus{State: st, Message: msg},
		}
		b, _ := json.Marshal(req)
		resp, body, err := c.do(t, http.MethodPost, "/agent/v1/poll", b)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("poll: %v %v %s", resp, err, body)
		}
	}
	msg := "version 0.3.0 was rolled back: no confirmation within 10m0s"
	send(gen.UpdateStateRolledBack, &msg)
	a, err := e.db.GetAgent(context.Background(), c.id)
	if err != nil || a.UpdateState != store.UpdateRolledBack || a.UpdateMessage != msg {
		t.Fatalf("agent %q %q, %v", a.UpdateState, a.UpdateMessage, err)
	}
	long := strings.Repeat("é", maxUpdateMessage)
	send(gen.UpdateStateRolledBack, &long)
	if a, _ = e.db.GetAgent(context.Background(), c.id); len(a.UpdateMessage) != maxUpdateMessage || !utf8.ValidString(a.UpdateMessage) {
		t.Fatalf("long message stored with %d bytes", len(a.UpdateMessage))
	}
	send(gen.UpdateStateUpToDate, nil)
	if a, _ = e.db.GetAgent(context.Background(), c.id); a.UpdateState != store.UpdateUpToDate || a.UpdateMessage != "" {
		t.Fatalf("agent %q %q", a.UpdateState, a.UpdateMessage)
	}
}

func TestPollComputedDirectives(t *testing.T) {
	e := newEnv(t, envOpts{})
	ctx := context.Background()
	c := enrolledAgent(t, e)
	e.pki.setBundleVersion(3)
	now := time.Now().UTC().Truncate(time.Second)
	if err := e.db.InsertAgentCert(ctx, store.AgentCert{Serial: "old", AgentID: c.id,
		NotBefore: now.Add(-200 * 24 * time.Hour), NotAfter: now.Add(100 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	res := c.poll(t, nil)
	_, types := directiveIDs(t, res.Directives)
	if !slices.Equal(types, []string{"renew_cert", "sync_trust_bundle"}) || res.Config.TrustBundleSerial != 3 ||
		time.Since(start) > time.Second {
		t.Fatalf("directives %v, config %+v", types, res.Config)
	}
}

func TestCounterReplay(t *testing.T) {
	e := newEnv(t, envOpts{})
	ctx := context.Background()
	c := enrolledAgent(t, e)
	c.poll(t, nil)

	// The agent lost its counter: the server's value is adopted and the
	// request retried.
	if ok, err := e.db.AdvanceAgentCounter(ctx, c.id, 1000); err != nil || !ok {
		t.Fatal(ok, err)
	}
	res := c.poll(t, nil)
	if c.counter.value() <= 1000 || res.LastCounter <= 1000 {
		t.Fatalf("counter %d, last %d", c.counter.value(), res.LastCounter)
	}

	// A replayed counter is rejected with the server's value.
	c.useSigned(c.signed.Transport.(*msgsig.Transport).Base, fixedCounter(5))
	resp, body, err := c.do(t, http.MethodPost, "/agent/v1/poll", c.pollBody(t, nil, 1))
	if err != nil || resp.StatusCode != http.StatusConflict || errorCode(t, body) != msgsig.CodeCounterReplayed ||
		resp.Header.Get(msgsig.HeaderCounter) == "" {
		t.Fatalf("replay: %v %v %s", resp, err, body)
	}
}

func TestScannerOnlyOperation(t *testing.T) {
	e := newEnv(t, envOpts{})
	c := enrolledAgent(t, e)
	inv := []byte(`{"cluster_id":"c1","collected_at":"2026-01-01T00:00:00Z","server_version":"v1.30.0","namespaces":[],"workloads":[],"pods":[]}`)
	resp, body, err := c.do(t, http.MethodPost, "/agent/v1/k8s/inventory", inv)
	if err != nil || resp.StatusCode != http.StatusForbidden || errorCode(t, body) != "forbidden" {
		t.Fatalf("inventory by agent: %v %v %s", resp, err, body)
	}
	resp, _, err = c.do(t, http.MethodGet, "/agent/v1/probe/linux/amd64", nil)
	if err != nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("probe by agent: %v %v", resp, err)
	}
}

func TestReportUpload(t *testing.T) {
	e := newEnv(t, envOpts{})
	c := enrolledAgent(t, e)
	raw := []byte("\x28\xb5\x2f\xfd report bytes")
	resp, body, err := c.do(t, http.MethodPost, "/agent/v1/reports?job_id=j-1", raw)
	if err != nil || resp.StatusCode != http.StatusAccepted {
		t.Fatalf("upload: %v %v %s", resp, err, body)
	}
	var acc gen.ReportAccepted
	if err := json.Unmarshal(body, &acc); err != nil || acc.ReportId != "report-1" {
		t.Fatalf("accepted: %s %v", body, err)
	}
	got := e.ingest.all()
	if len(got) != 1 || got[0].sender.ID != c.id || got[0].sender.Kind != store.AgentKindAgent ||
		got[0].jobID != "j-1" || !bytes.Equal(got[0].raw, raw) {
		t.Fatalf("ingest got %+v", got)
	}
}

func TestRevokedAgentRejected(t *testing.T) {
	e := newEnv(t, envOpts{})
	c := enrolledAgent(t, e)
	c.poll(t, nil)
	if err := e.db.RevokeAgent(context.Background(), c.id, time.Now()); err != nil {
		t.Fatal(err)
	}
	// The open connection's certificate no longer verifies: the agent gets
	// a signed answer it can act on, for every signed path.
	resp, body, err := c.do(t, http.MethodPost, "/agent/v1/poll", c.pollBody(t, nil, 1))
	if err != nil || resp.StatusCode != http.StatusForbidden || errorCode(t, body) != msgsig.CodeAgentRevoked {
		t.Fatalf("revoked agent on open connection: %v %v %s", resp, err, body)
	}
	resp, body, err = c.do(t, http.MethodGet, "/agent/v1/trust-bundle", nil)
	if err != nil || resp.StatusCode != http.StatusForbidden || errorCode(t, body) != msgsig.CodeAgentRevoked {
		t.Fatalf("revoked agent on open connection: %v %v %s", resp, err, body)
	}
	// Paths outside message signing keep the plain 403.
	plain := &http.Client{Transport: c.signed.Transport.(*msgsig.Transport).Base}
	resp, err = plain.Get(c.base + "/agent/v1/server-chain")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get(msgsig.HeaderSignature) != "" {
		t.Fatalf("server chain with revoked certificate: %d %v", resp.StatusCode, resp.Header)
	}
	// Without a client certificate the signature check refuses it.
	c.cert = nil
	c.connectSigned(t)
	resp, body, err = c.do(t, http.MethodPost, "/agent/v1/poll", c.pollBody(t, nil, 1))
	if err != nil || resp.StatusCode != http.StatusForbidden || errorCode(t, body) != msgsig.CodeAgentRevoked {
		t.Fatalf("revoked agent without certificate: %v %v %s", resp, err, body)
	}
}

func TestClientCertificateRequired(t *testing.T) {
	e := newEnv(t, envOpts{})
	c := enrolledAgent(t, e)
	cert := c.cert
	c.cert = nil
	c.connectSigned(t)
	resp, body, err := c.do(t, http.MethodPost, "/agent/v1/poll", c.pollBody(t, nil, 1))
	if err != nil || resp.StatusCode != http.StatusForbidden || errorCode(t, body) != msgsig.CodeClientCertMismatch {
		t.Fatalf("without certificate: %v %v %s", resp, err, body)
	}
	c.cert = cert
	c.connectSigned(t)
	c.poll(t, nil)
}

func TestClientGone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/agent/v1/poll", nil)
	err := fmt.Errorf("agent counter: %w", context.Canceled)
	if clientGone(r, err) {
		t.Fatal("cancellation reported while the request is still open")
	}
	cancel()
	if !clientGone(r, err) {
		t.Fatal("cancellation of a closed request not recognized")
	}
	if clientGone(r, errors.New("connection refused")) {
		t.Fatal("other error reported as client cancellation")
	}
}

func TestPollSendsDetectPaths(t *testing.T) {
	e := newEnv(t, envOpts{})
	c := enrolledAgent(t, e)
	ctx := context.Background()
	poll := func() gen.Policy {
		t.Helper()
		req := gen.PollRequest{
			Version: "0.2.0", Os: gen.Linux, Arch: gen.Amd64, ConnectMode: gen.Connect, TlsMode: gen.Pinned,
			Privilege:      gen.Privilege{Level: gen.PrivilegeLevel("non_root"), Uid: 1000},
			SectionDigests: map[string]string{}, TrustBundleSerial: 1,
			Update: gen.UpdateStatus{State: gen.UpdateStateUpToDate},
		}
		b, _ := json.Marshal(req)
		resp, body, err := c.do(t, http.MethodPost, "/agent/v1/poll", b)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("poll: %v %v %s", resp, err, body)
		}
		var res gen.PollResult
		if err := json.Unmarshal(body, &res); err != nil {
			t.Fatal(err)
		}
		return res.Config.Policy
	}
	// Walk paths in the global policy are not used.
	if err := e.db.PutSetting(ctx, SettingCollectPolicy, json.RawMessage(`{"policy":{"exec_version":true,"collect_cmdline":true,"scan_containers":true,"walk_paths":["/"]}}`)); err != nil {
		t.Fatal(err)
	}
	if p := poll(); p.WalkPaths != nil {
		t.Fatalf("walk paths without detect dirs: %v", *p.WalkPaths)
	}
	var ids []string
	for _, p := range []string{"/srv", "/opt"} {
		d, err := e.db.CreateDetectDir(ctx, store.DetectDir{Path: p})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, d.ID)
	}
	if err := e.db.SetAgentDetectDirs(ctx, c.id, ids); err != nil {
		t.Fatal(err)
	}
	if p := poll(); p.WalkPaths == nil || !slices.Equal(*p.WalkPaths, []string{"/opt", "/srv"}) || !p.ExecVersion {
		t.Fatalf("policy %+v", p)
	}
}

func TestPollSendsIntegrity(t *testing.T) {
	e := newEnv(t, envOpts{})
	c := enrolledAgent(t, e)
	ctx := context.Background()
	poll := func(features ...string) *gen.IntegrityConfig {
		t.Helper()
		req := gen.PollRequest{
			Version: "0.2.0", Os: gen.Linux, Arch: gen.Amd64, ConnectMode: gen.Connect, TlsMode: gen.Pinned,
			Privilege:      gen.Privilege{Level: gen.PrivilegeLevel("privileged"), Uid: 0},
			SectionDigests: map[string]string{}, TrustBundleSerial: 1,
			Update:   gen.UpdateStatus{State: gen.UpdateStateUpToDate},
			Features: &features,
		}
		b, _ := json.Marshal(req)
		resp, body, err := c.do(t, http.MethodPost, "/agent/v1/poll", b)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("poll: %v %v %s", resp, err, body)
		}
		var res gen.PollResult
		if err := json.Unmarshal(body, &res); err != nil {
			t.Fatal(err)
		}
		return res.Config.Integrity
	}
	if cfg := poll(); cfg != nil {
		t.Errorf("integrity sent to an agent without the feature: %+v", cfg)
	}
	// The first poll with the feature already gets the configuration.
	cfg := poll("integrity")
	if cfg == nil || !cfg.Enabled || cfg.WindowStart != "02:00" || cfg.MaxReadMbps != 20 {
		t.Fatalf("default %+v", cfg)
	}
	if a, err := e.db.GetAgent(ctx, c.id); err != nil || !a.HasFeature(store.FeatureIntegrity) {
		t.Errorf("feature not stored: %+v %v", a.Features, err)
	}
	if err := e.db.SetAgentIntegrity(ctx, c.id, store.IntegrityOff); err != nil {
		t.Fatal(err)
	}
	if cfg := poll("integrity"); cfg == nil || cfg.Enabled {
		t.Errorf("off: %+v", cfg)
	}
}
