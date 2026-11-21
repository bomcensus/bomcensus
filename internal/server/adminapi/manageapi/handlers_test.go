// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package manageapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/pki"
	"github.com/bomcensus/bomcensus/internal/release"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/apierr"
	"github.com/bomcensus/bomcensus/internal/server/pkisvc"
	"github.com/bomcensus/bomcensus/internal/server/secret"
	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/internal/server/store/postgres"
	"github.com/bomcensus/bomcensus/internal/server/updatesvc"
	"github.com/bomcensus/bomcensus/internal/sign"
	"github.com/bomcensus/bomcensus/internal/sign/signtest"
	"github.com/bomcensus/bomcensus/internal/token"
	"golang.org/x/crypto/ssh"
)

// stub supplies the operations this package does not implement.
type stub struct{ gen.StrictServerInterface }

type server struct {
	*Handlers
	stub
}

type fakeRunner struct {
	mu  sync.Mutex
	ids []string
}

func (r *fakeRunner) RequestRun(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ids = append(r.ids, id)
	return nil
}

type env struct {
	t      *testing.T
	db     *postgres.DB
	box    *secret.Box
	pki    *pkisvc.Service
	h      *Handlers
	srv    *httptest.Server
	runner *fakeRunner
}

func newEnv(t *testing.T, withRunner bool) *env {
	t.Helper()
	ctx := context.Background()
	db := newTestDB(t)
	key := make([]byte, secret.KeySize)
	_, _ = rand.Read(key)
	box, err := secret.New(key)
	if err != nil {
		t.Fatal(err)
	}
	ps, err := pkisvc.New(pkisvc.Config{Store: db, Box: box, WebTLS: true, UnsyncedAgents: UnsyncedAgents(db)})
	if err != nil {
		t.Fatal(err)
	}
	if err := ps.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	us, err := updatesvc.New(updatesvc.Config{Store: db})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, db: db, box: box, pki: ps}
	cfg := Config{Store: db, PKI: ps, Updates: us, Secrets: box,
		PrincipalID: func(context.Context) string { return "admin-1" }}
	if withRunner {
		e.runner = &fakeRunner{}
		cfg.ScanRunner = e.runner
	}
	if e.h, err = New(cfg); err != nil {
		t.Fatal(err)
	}
	strict := gen.NewStrictHandlerWithOptions(server{Handlers: e.h}, nil, gen.StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
			apierr.Write(w, http.StatusBadRequest, gen.Error{Code: apierr.CodeInvalidArgument, Message: err.Error()})
		},
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
			if status := apierr.Render(w, err); status >= 500 {
				t.Logf("internal error: %v", err)
			}
		},
	})
	e.srv = httptest.NewServer(gen.HandlerWithOptions(strict, gen.ChiServerOptions{BaseURL: "/api/v1"}))
	t.Cleanup(e.srv.Close)
	return e
}

type resp struct {
	status int
	header http.Header
	body   []byte
}

func (r resp) code() string {
	var e gen.Error
	_ = json.Unmarshal(r.body, &e)
	return e.Code
}

func (e *env) do(method, path string, body any) resp {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			e.t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, e.srv.URL+"/api/v1"+path, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return e.send(req)
}

func (e *env) send(req *http.Request) resp {
	e.t.Helper()
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{status: res.StatusCode, header: res.Header, body: b}
}

func (e *env) want(r resp, status int, code string) {
	e.t.Helper()
	if r.status != status || (code != "" && r.code() != code) {
		e.t.Fatalf("status %d code %q, want %d %q: %s", r.status, r.code(), status, code, r.body)
	}
}

func decode[T any](t *testing.T, r resp) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(r.body, &v); err != nil {
		t.Fatalf("decode %s: %v", r.body, err)
	}
	return v
}

func ptr[T any](v T) *T { return &v }

func TestRegisterKeys(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()

	for _, bad := range []gen.RegisterKeyCreate{
		{Name: "", Target: gen.AgentKindAgent, Approval: gen.RegisterKeyApprovalAuto},
		{Name: "k", Target: "printer", Approval: gen.RegisterKeyApprovalAuto},
		{Name: "k", Target: gen.AgentKindAgent, Approval: "maybe"},
		{Name: "k", Target: gen.AgentKindAgent, Approval: gen.RegisterKeyApprovalAuto, MaxUses: ptr(-1)},
		{Name: "k", Target: gen.AgentKindAgent, Approval: gen.RegisterKeyApprovalAuto, ExpiresAt: ptr(time.Now().Add(-time.Hour))},
		{Name: "k", Target: gen.AgentKindAgent, Approval: gen.RegisterKeyApprovalAuto, AllowedCidrs: &[]string{"10.0.0.0/33"}},
		{Name: "k", Target: gen.AgentKindAgent, Approval: gen.RegisterKeyApprovalAuto, AllowedCidrs: &[]string{"example.com"}},
	} {
		e.want(e.do("POST", "/register-keys", bad), 400, apierr.CodeInvalidArgument)
	}

	r := e.do("POST", "/register-keys", gen.RegisterKeyCreate{
		Name: "rollout", Target: gen.AgentKindAgent, Approval: gen.RegisterKeyApprovalManual,
		ExpiresAt: ptr(time.Now().Add(24 * time.Hour)), MaxUses: ptr(5),
		AllowedCidrs: &[]string{"10.1.2.3/8", "192.168.1.1", "2001:db8::1/32"},
		DefaultTags:  &[]string{"prod", " prod ", ""}, DefaultGroup: ptr("web"),
	})
	e.want(r, 201, "")
	if r.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control %q", r.header.Get("Cache-Control"))
	}
	created := decode[gen.RegisterKeyCreated](t, r)
	tok, err := token.Parse(created.Enrollment)
	if err != nil {
		t.Fatal(err)
	}
	anchor, _ := e.pki.AnchorHash()
	if tok.CAHash != anchor {
		t.Fatal("enrollment string does not carry the anchor hash")
	}
	if tok.KeyID.String() != created.Key.Id {
		t.Fatal("key id mismatch")
	}
	stored, err := e.db.GetRegisterKey(ctx, created.Key.Id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored.PublicKey, tok.PublicKey()) || stored.CreatedBy != "admin-1" {
		t.Fatalf("stored key %+v", stored)
	}
	if strings.Join(created.Key.AllowedCidrs, ",") != "10.0.0.0/8,192.168.1.1/32,2001:db8::/32" ||
		strings.Join(created.Key.DefaultTags, ",") != "prod" || created.Key.State != gen.RegisterKeyStateValid {
		t.Fatalf("key %+v", created.Key)
	}

	list := decode[gen.RegisterKeyList](t, e.do("GET", "/register-keys", nil))
	if list.Total != 1 || strings.Contains(string(e.do("GET", "/register-keys", nil).body), created.Enrollment) {
		t.Fatalf("list %+v", list)
	}
	one := e.do("GET", "/register-keys/"+created.Key.Id, nil)
	e.want(one, 200, "")
	if k := decode[gen.RegisterKey](t, one); k.Id != created.Key.Id || k.Name != "rollout" || k.MaxUses != 5 ||
		strings.Contains(string(one.body), created.Enrollment) {
		t.Fatalf("get %s", one.body)
	}
	e.want(e.do("GET", "/register-keys/AAAAAAAAAAA", nil), 404, apierr.CodeNotFound)

	e.want(e.do("POST", "/register-keys/"+created.Key.Id+"/revoke", nil), 200, "")
	e.want(e.do("POST", "/register-keys/"+created.Key.Id+"/revoke", nil), 409, apierr.CodeInvalidState)
	e.want(e.do("POST", "/register-keys/AAAAAAAAAAA/revoke", nil), 404, apierr.CodeNotFound)
	if l := decode[gen.RegisterKeyList](t, e.do("GET", "/register-keys?state=revoked", nil)); l.Total != 1 || l.Items[0].State != gen.RegisterKeyStateRevoked {
		t.Fatalf("revoked filter %+v", l)
	}
	if l := decode[gen.RegisterKeyList](t, e.do("GET", "/register-keys?state=valid", nil)); l.Total != 0 {
		t.Fatalf("valid filter %+v", l)
	}
}

func TestAgents(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	mk := func(host string, state store.AgentState, seen *time.Time, version string) store.Agent {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		a, err := e.db.CreateAgent(ctx, store.Agent{Kind: store.AgentKindAgent, Hostname: host, IdentityKey: pub, State: state})
		if err != nil {
			t.Fatal(err)
		}
		if seen != nil {
			if err := e.db.UpdateAgentPoll(ctx, a.ID, store.AgentPollStatus{Hostname: host, Version: version, SeenAt: *seen,
				ConnectMode: store.ConnectModeConnect, TLSMode: store.TLSVerifyPinned, UpdateState: store.UpdateUpToDate}); err != nil {
				t.Fatal(err)
			}
		}
		return a
	}
	now := time.Now()
	old := now.Add(-time.Hour)
	online := mk("b-online", store.AgentApproved, &now, "1.0.0")
	mk("a-offline", store.AgentApproved, &old, "0.9.0")
	pending := mk("c-pending", store.AgentPending, nil, "")

	l := decode[gen.AgentList](t, e.do("GET", "/agents", nil))
	if l.Total != 3 || l.Items[0].Hostname != "a-offline" {
		t.Fatalf("list %+v", l)
	}
	status := map[string]gen.AgentStatus{}
	for _, a := range l.Items {
		status[a.Hostname] = a.Status
		if !a.TrustBundleSynced {
			t.Fatalf("%s not synced at bundle version 0", a.Hostname)
		}
	}
	if status["b-online"] != gen.AgentStatusOnline || status["a-offline"] != gen.AgentStatusOffline || status["c-pending"] != gen.AgentStatusPendingApproval {
		t.Fatalf("statuses %v", status)
	}
	if l := decode[gen.AgentList](t, e.do("GET", "/agents?status=online", nil)); l.Total != 1 || l.Items[0].Id != online.ID {
		t.Fatalf("online filter %+v", l)
	}
	if l := decode[gen.AgentList](t, e.do("GET", "/agents?version=1.0.0", nil)); l.Total != 1 || l.Items[0].Id != online.ID {
		t.Fatalf("version filter %+v", l)
	}
	if l := decode[gen.AgentList](t, e.do("GET", "/agents?sort=-status&limit=1", nil)); l.Total != 3 || len(l.Items) != 1 || l.Items[0].Status != gen.AgentStatusPendingApproval {
		t.Fatalf("status sort %+v", l)
	}
	if l := decode[gen.AgentList](t, e.do("GET", "/agents?sort=-hostname&offset=1", nil)); len(l.Items) != 2 || l.Items[0].Hostname != "b-online" {
		t.Fatalf("store sort %+v", l)
	}

	// The update detail reported with the last poll.
	if a := decode[gen.Agent](t, e.do("GET", "/agents/"+online.ID, nil)); a.UpdateMessage != nil {
		t.Fatalf("update message %q without one reported", *a.UpdateMessage)
	}
	msg := "version 1.1.0 was rolled back: the new version did not confirm"
	if err := e.db.UpdateAgentPoll(ctx, online.ID, store.AgentPollStatus{Hostname: "b-online", Version: "1.0.0", SeenAt: now,
		ConnectMode: store.ConnectModeConnect, TLSMode: store.TLSVerifyPinned, UpdateState: store.UpdateRolledBack,
		UpdateMessage: msg}); err != nil {
		t.Fatal(err)
	}
	if a := decode[gen.Agent](t, e.do("GET", "/agents/"+online.ID, nil)); a.UpdateState != gen.UpdateStateRolledBack ||
		a.UpdateMessage == nil || *a.UpdateMessage != msg {
		t.Fatalf("agent update %s %v", a.UpdateState, a.UpdateMessage)
	}

	e.want(e.do("POST", "/agents/"+online.ID+"/approve", nil), 409, apierr.CodeInvalidState)
	a := decode[gen.Agent](t, e.do("POST", "/agents/"+pending.ID+"/approve", nil))
	if a.Status != gen.AgentStatusOffline {
		t.Fatalf("approved status %s", a.Status)
	}
	a = decode[gen.Agent](t, e.do("POST", "/agents/"+online.ID+"/revoke", nil))
	if a.Status != gen.AgentStatusRevoked {
		t.Fatalf("revoked status %s", a.Status)
	}
	e.want(e.do("POST", "/agents/"+online.ID+"/revoke", nil), 409, apierr.CodeInvalidState)
	e.want(e.do("GET", "/agents/00000000-0000-0000-0000-000000000000", nil), 404, apierr.CodeNotFound)

	// A bundle change leaves agents unsynced.
	if _, err := e.db.BumpTrustBundleVersion(ctx); err != nil {
		t.Fatal(err)
	}
	if a := decode[gen.Agent](t, e.do("GET", "/agents/"+pending.ID, nil)); a.TrustBundleSynced {
		t.Fatal("synced after a bundle bump")
	}
}

func TestListenTargets(t *testing.T) {
	e := newEnv(t, false)
	for _, addr := range []string{"", "no-port", "host:0", "host:99999", " :22"} {
		e.want(e.do("POST", "/listen-targets", gen.ListenTargetCreate{Address: addr}), 400, apierr.CodeInvalidArgument)
	}
	e.want(e.do("POST", "/listen-targets", gen.ListenTargetCreate{Address: "h:7443", RegisterKeyId: ptr("AAAAAAAAAAA")}), 400, apierr.CodeInvalidArgument)
	r := e.do("POST", "/listen-targets", gen.ListenTargetCreate{Address: "agent1.example:7443"})
	e.want(r, 201, "")
	lt := decode[gen.ListenTarget](t, r)
	if lt.State != gen.ListenTargetStateConnecting {
		t.Fatalf("state %s", lt.State)
	}
	e.want(e.do("POST", "/listen-targets", gen.ListenTargetCreate{Address: "agent1.example:7443"}), 409, apierr.CodeConflict)
	if l := decode[gen.ListenTargetList](t, e.do("GET", "/listen-targets?state=connecting&q=AGENT1", nil)); l.Total != 1 {
		t.Fatalf("list %+v", l)
	}

	// Update: address and register key; null removes the key.
	agentKey := decode[gen.RegisterKeyCreated](t, e.do("POST", "/register-keys", gen.RegisterKeyCreate{Name: "a", Target: gen.AgentKindAgent, Approval: gen.RegisterKeyApprovalAuto}))
	scanKey := decode[gen.RegisterKeyCreated](t, e.do("POST", "/register-keys", gen.RegisterKeyCreate{Name: "s", Target: gen.AgentKindScanner, Approval: gen.RegisterKeyApprovalAuto}))
	decode[gen.ListenTarget](t, e.do("POST", "/listen-targets", gen.ListenTargetCreate{Address: "agent2.example:7443"}))
	up := decode[gen.ListenTarget](t, e.do("PATCH", "/listen-targets/"+lt.Id, map[string]any{"address": " agent1.example:7444 ", "registerKeyId": agentKey.Key.Id}))
	if up.Address != "agent1.example:7444" || deref(up.RegisterKeyId) != agentKey.Key.Id || up.State != gen.ListenTargetStateConnecting {
		t.Fatalf("updated %+v", up)
	}
	up = decode[gen.ListenTarget](t, e.do("PATCH", "/listen-targets/"+lt.Id, map[string]any{}))
	if up.Address != "agent1.example:7444" || deref(up.RegisterKeyId) != agentKey.Key.Id {
		t.Fatalf("empty patch changed %+v", up)
	}
	up = decode[gen.ListenTarget](t, e.do("PATCH", "/listen-targets/"+lt.Id, map[string]any{"registerKeyId": nil}))
	if up.RegisterKeyId != nil {
		t.Fatalf("key not removed %+v", up)
	}
	e.want(e.do("PATCH", "/listen-targets/"+lt.Id, map[string]any{"registerKeyId": scanKey.Key.Id}), 400, apierr.CodeInvalidArgument)
	e.want(e.do("PATCH", "/listen-targets/"+lt.Id, map[string]any{"address": "no-port"}), 400, apierr.CodeInvalidArgument)
	e.want(e.do("PATCH", "/listen-targets/"+lt.Id, map[string]any{"address": "agent2.example:7443"}), 409, apierr.CodeConflict)
	e.want(e.do("PATCH", "/listen-targets/00000000-0000-0000-0000-000000000000", map[string]any{}), 404, apierr.CodeNotFound)

	e.want(e.do("DELETE", "/listen-targets/"+lt.Id, nil), 204, "")
	e.want(e.do("DELETE", "/listen-targets/"+lt.Id, nil), 404, apierr.CodeNotFound)
}

// sshPrivateKey returns an OpenSSH private key (encrypted with passphrase
// when given) and its public key fingerprint.
func sshPrivateKey(t *testing.T, passphrase string) (string, string) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	var block *pem.Block
	var err error
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "test")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "test", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(block)), ssh.FingerprintSHA256(sp)
}

func TestCredentialKeysAndRotation(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	key, fp := sshPrivateKey(t, "")
	encKey, encFP := sshPrivateKey(t, "s3cret")

	e.want(e.do("POST", "/credentials", gen.CredentialCreate{Name: "bad", Kind: gen.CredentialKindSshKey, Username: ptr("root"),
		PrivateKey: ptr("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n")}), 400, apierr.CodeInvalidArgument)
	e.want(e.do("POST", "/credentials", gen.CredentialCreate{Name: "bad", Kind: gen.CredentialKindSshKey, Username: ptr("root"),
		PrivateKey: ptr(encKey), Passphrase: ptr("wrong")}), 400, apierr.CodeInvalidArgument)
	k := decode[gen.Credential](t, e.do("POST", "/credentials", gen.CredentialCreate{Name: "key", Kind: gen.CredentialKindSshKey,
		Username: ptr("root"), PrivateKey: ptr(key)}))
	if deref(k.PublicKeyFingerprint) != fp {
		t.Fatalf("fingerprint %v, want %s", k.PublicKeyFingerprint, fp)
	}
	// The public key of an encrypted OpenSSH key is readable without the
	// passphrase.
	enc := decode[gen.Credential](t, e.do("POST", "/credentials", gen.CredentialCreate{Name: "enc", Kind: gen.CredentialKindSshKey,
		Username: ptr("root"), PrivateKey: ptr(encKey)}))
	if deref(enc.PublicKeyFingerprint) != encFP {
		t.Fatalf("encrypted key fingerprint %v", enc.PublicKeyFingerprint)
	}
	pw := decode[gen.Credential](t, e.do("POST", "/credentials", gen.CredentialCreate{Name: "pw", Kind: gen.CredentialKindSshPassword,
		Username: ptr("u"), Password: ptr("old")}))
	if pw.PublicKeyFingerprint != nil {
		t.Fatalf("password credential with fingerprint %+v", pw)
	}
	list := decode[gen.CredentialList](t, e.do("GET", "/credentials?kind=ssh_key", nil))
	if list.Total != 2 || deref(list.Items[1].PublicKeyFingerprint) != fp {
		t.Fatalf("list %+v", list)
	}

	// Rotation: same kind, username kept unless given.
	r := e.do("PUT", "/credentials/"+k.Id+"/secret", gen.CredentialSecretUpdate{PrivateKey: ptr(encKey), Passphrase: ptr("s3cret")})
	e.want(r, 200, "")
	if c := decode[gen.Credential](t, r); deref(c.PublicKeyFingerprint) != encFP || deref(c.Username) != "root" || c.Name != "key" {
		t.Fatalf("rotated key %+v", c)
	}
	if bytes.Contains(r.body, []byte("s3cret")) {
		t.Fatal("secret in response")
	}
	stored, err := e.db.GetCredentialWithSecret(ctx, k.Id)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := e.box.OpenCredential(k.Id, stored.Secret); err != nil || s.PrivateKey != encKey || s.Passphrase != "s3cret" {
		t.Fatalf("rotated secret %v", err)
	}
	r = e.do("PUT", "/credentials/"+pw.Id+"/secret", gen.CredentialSecretUpdate{Username: ptr("admin"), Password: ptr("new")})
	e.want(r, 200, "")
	if c := decode[gen.Credential](t, r); deref(c.Username) != "admin" {
		t.Fatalf("rotated password %+v", c)
	}
	stored, _ = e.db.GetCredentialWithSecret(ctx, pw.Id)
	if s, err := e.box.OpenCredential(pw.Id, stored.Secret); err != nil || s.Password != "new" {
		t.Fatalf("rotated password secret %v", err)
	}
	e.want(e.do("PUT", "/credentials/"+pw.Id+"/secret", gen.CredentialSecretUpdate{PrivateKey: ptr(key)}), 400, apierr.CodeInvalidArgument)
	e.want(e.do("PUT", "/credentials/"+k.Id+"/secret", gen.CredentialSecretUpdate{}), 400, apierr.CodeInvalidArgument)
	e.want(e.do("PUT", "/credentials/00000000-0000-0000-0000-000000000000/secret", gen.CredentialSecretUpdate{Password: ptr("x")}), 404, apierr.CodeNotFound)
}

func TestCredentials(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	const password = "hunter2-very-secret"
	const kubeconfig = "apiVersion: v1\nkind: Config\nusers: [{name: x, user: {token: kube-secret-token}}]\n"

	for _, bad := range []gen.CredentialCreate{
		{Name: "x", Kind: gen.CredentialKindSshKey, Username: ptr("root")},
		{Name: "x", Kind: gen.CredentialKindSshKey, Username: ptr("root"), PrivateKey: ptr("not a key")},
		{Name: "x", Kind: gen.CredentialKindSshPassword, Password: ptr("p")},
		{Name: "x", Kind: gen.CredentialKindSshPassword, Username: ptr("u"), Password: ptr("p"), Kubeconfig: ptr("k")},
		{Name: "x", Kind: gen.CredentialKindKubeconfig, Kubeconfig: ptr(kubeconfig), Username: ptr("u")},
		{Name: "x", Kind: "token"},
		{Name: " ", Kind: gen.CredentialKindKubeconfig, Kubeconfig: ptr(kubeconfig)},
	} {
		e.want(e.do("POST", "/credentials", bad), 400, apierr.CodeInvalidArgument)
	}

	r := e.do("POST", "/credentials", gen.CredentialCreate{Name: "ssh", Kind: gen.CredentialKindSshPassword, Username: ptr("collector"), Password: ptr(password)})
	e.want(r, 201, "")
	sshCred := decode[gen.Credential](t, r)
	r2 := e.do("POST", "/credentials", gen.CredentialCreate{Name: "kube", Kind: gen.CredentialKindKubeconfig, Kubeconfig: ptr(kubeconfig)})
	e.want(r2, 201, "")
	kubeCred := decode[gen.Credential](t, r2)
	e.want(e.do("POST", "/credentials", gen.CredentialCreate{Name: "ssh", Kind: gen.CredentialKindSshPassword, Username: ptr("u"), Password: ptr("p")}), 409, apierr.CodeConflict)

	list := e.do("GET", "/credentials", nil)
	for _, body := range [][]byte{r.body, r2.body, list.body} {
		if bytes.Contains(body, []byte(password)) || bytes.Contains(body, []byte("kube-secret-token")) {
			t.Fatalf("secret leaked: %s", body)
		}
	}
	if l := decode[gen.CredentialList](t, list); l.Total != 2 || l.Items[0].Name != "kube" {
		t.Fatalf("list %+v", l)
	}

	stored, err := e.db.GetCredentialWithSecret(ctx, sshCred.Id)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored.Secret, []byte(password)) {
		t.Fatal("secret stored in clear")
	}
	if s, err := e.box.OpenCredential(sshCred.Id, stored.Secret); err != nil || s.Password != password {
		t.Fatalf("open: %+v %v", s, err)
	}
	if _, err := e.box.OpenCredential(kubeCred.Id, stored.Secret); err == nil {
		t.Fatal("secret opens under another credential id")
	}

	// In use by a scan target, then by a cluster.
	st := decode[gen.ScanTarget](t, e.do("POST", "/scan-targets", gen.ScanTargetCreate{Name: "h", Address: "10.0.0.5", CredentialId: sshCred.Id}))
	e.want(e.do("DELETE", "/credentials/"+sshCred.Id, nil), 409, apierr.CodeInUse)
	e.want(e.do("DELETE", "/scan-targets/"+st.Id, nil), 204, "")
	e.want(e.do("DELETE", "/credentials/"+sshCred.Id, nil), 204, "")

	if _, err := e.db.CreateCluster(ctx, store.K8sClusterConfig{Name: "c1", Connection: store.K8sKubeconfig, CredentialID: kubeCred.Id}); err != nil {
		t.Fatal(err)
	}
	if l := decode[gen.CredentialList](t, e.do("GET", "/credentials?kind=kubeconfig", nil)); l.Total != 1 || l.Items[0].UsedBy != 1 {
		t.Fatalf("usedBy %+v", l)
	}
	e.want(e.do("DELETE", "/credentials/"+kubeCred.Id, nil), 409, apierr.CodeInUse)
	e.want(e.do("DELETE", "/credentials/00000000-0000-0000-0000-000000000000", nil), 404, apierr.CodeNotFound)
}

func sshHostKeyLine() (string, []byte) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	typ := "ssh-ed25519"
	var wire []byte
	wire = binary.BigEndian.AppendUint32(wire, uint32(len(typ)))
	wire = append(wire, typ...)
	wire = binary.BigEndian.AppendUint32(wire, uint32(len(pub)))
	wire = append(wire, pub...)
	return typ + " " + base64.StdEncoding.EncodeToString(wire) + " host@example", wire
}

func TestScanTargets(t *testing.T) {
	e := newEnv(t, true)
	cred := decode[gen.Credential](t, e.do("POST", "/credentials", gen.CredentialCreate{Name: "ssh", Kind: gen.CredentialKindSshPassword, Username: ptr("u"), Password: ptr("p")}))
	kube := decode[gen.Credential](t, e.do("POST", "/credentials", gen.CredentialCreate{Name: "kube", Kind: gen.CredentialKindKubeconfig, Kubeconfig: ptr("apiVersion: v1")}))
	line, wire := sshHostKeyLine()

	for _, bad := range []gen.ScanTargetCreate{
		{Name: "h", Address: "10.0.0.1", CredentialId: kube.Id},
		{Name: "h", Address: "10.0.0.1", CredentialId: "00000000-0000-0000-0000-000000000000"},
		{Name: "h", Address: "10.0.0.1", CredentialId: cred.Id, HostKeyFingerprint: ptr("SHA256:abc")},
		{Name: "h", Address: "10.0.0.1", CredentialId: cred.Id, HostKey: ptr("ssh-rsa " + strings.Fields(line)[1])},
		{Name: "h", Address: "10.0.0.1", CredentialId: cred.Id, IntervalMinutes: ptr(-1)},
		{Name: "h", Address: "10.0.0.1", CredentialId: cred.Id, Port: ptr(70000)},
		{Name: "h", Address: "10.0.0.1", CredentialId: cred.Id, ScannerId: ptr("00000000-0000-0000-0000-000000000000")},
	} {
		e.want(e.do("POST", "/scan-targets", bad), 400, apierr.CodeInvalidArgument)
	}
	r := e.do("POST", "/scan-targets", gen.ScanTargetCreate{Name: "db1", Address: "10.0.0.1", CredentialId: cred.Id, HostKey: ptr(line), IntervalMinutes: ptr(15), Sudo: ptr(true)})
	e.want(r, 201, "")
	st := decode[gen.ScanTarget](t, r)
	if st.Port != 22 || st.IntervalMinutes != 15 || !st.HostKeyPinned || deref(st.HostKeyFingerprint) != SSHFingerprint(wire) || !st.Sudo || st.Protocol != gen.ScanProtocolSsh {
		t.Fatalf("scan target %+v", st)
	}
	decode[gen.ScanTarget](t, e.do("POST", "/scan-targets", gen.ScanTargetCreate{Name: "app1", Address: "10.0.0.2", CredentialId: cred.Id}))
	if l := decode[gen.ScanTargetList](t, e.do("GET", "/scan-targets?sort=-name", nil)); l.Total != 2 || l.Items[0].Name != "db1" || l.Items[1].IntervalMinutes != 0 {
		t.Fatalf("list %+v", l)
	}
	if l := decode[gen.ScanTargetList](t, e.do("GET", "/scan-targets?lastResult=ok", nil)); l.Total != 0 {
		t.Fatalf("lastResult filter %+v", l)
	}

	// Update: absent fields kept, scanner set and cleared, host key reset.
	sc, err := e.db.CreateAgent(context.Background(), store.Agent{Kind: store.AgentKindScanner, IdentityKey: []byte("scanner-key"), State: store.AgentApproved})
	if err != nil {
		t.Fatal(err)
	}
	up := decode[gen.ScanTarget](t, e.do("PATCH", "/scan-targets/"+st.Id, map[string]any{"name": "db1-primary", "port": 2222,
		"intervalMinutes": 0, "sudo": false, "scannerId": sc.ID}))
	if up.Name != "db1-primary" || up.Port != 2222 || up.IntervalMinutes != 0 || up.Sudo || deref(up.ScannerId) != sc.ID ||
		up.Address != "10.0.0.1" || !up.HostKeyPinned || up.CredentialId != cred.Id {
		t.Fatalf("updated %+v", up)
	}
	up = decode[gen.ScanTarget](t, e.do("PATCH", "/scan-targets/"+st.Id, map[string]any{"scannerId": nil, "resetHostKey": true}))
	if up.ScannerId != nil || up.HostKeyPinned || up.HostKeyFingerprint != nil || up.Name != "db1-primary" {
		t.Fatalf("cleared %+v", up)
	}
	for _, bad := range []map[string]any{
		{"credentialId": kube.Id},
		{"port": 0},
		{"name": " "},
		{"intervalMinutes": -5},
		{"scannerId": "00000000-0000-0000-0000-000000000000"},
	} {
		e.want(e.do("PATCH", "/scan-targets/"+st.Id, bad), 400, apierr.CodeInvalidArgument)
	}
	e.want(e.do("PATCH", "/scan-targets/00000000-0000-0000-0000-000000000000", map[string]any{}), 404, apierr.CodeNotFound)

	e.want(e.do("POST", "/scan-targets/"+st.Id+"/run", nil), 202, "")
	if len(e.runner.ids) != 1 || e.runner.ids[0] != st.Id {
		t.Fatalf("runner calls %v", e.runner.ids)
	}
	e.want(e.do("POST", "/scan-targets/00000000-0000-0000-0000-000000000000/run", nil), 404, apierr.CodeNotFound)

	noRunner := newEnv(t, false)
	c := decode[gen.Credential](t, noRunner.do("POST", "/credentials", gen.CredentialCreate{Name: "ssh", Kind: gen.CredentialKindSshPassword, Username: ptr("u"), Password: ptr("p")}))
	st2 := decode[gen.ScanTarget](t, noRunner.do("POST", "/scan-targets", gen.ScanTargetCreate{Name: "h", Address: "h", CredentialId: c.Id}))
	noRunner.want(noRunner.do("POST", "/scan-targets/"+st2.Id+"/run", nil), 503, apierr.CodeUnavailable)
}

func releaseBundle(t *testing.T, tr *signtest.Trust, version string, tamper bool) []byte {
	t.Helper()
	now := time.Now()
	m := &sign.Manifest{Version: version, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	elf := tr.SignELF(t, signtest.ELF(t, "amd64"))
	var files []release.File
	for _, n := range []string{"bomcensus-agent", "bomcensus-probe"} {
		m.Files = append(m.Files, signtest.FileEntry("linux", "amd64", n, elf))
		files = append(files, release.File{OS: "linux", Arch: "amd64", Name: n, Data: elf})
	}
	mb, sig := tr.SignManifest(t, m)
	var buf bytes.Buffer
	if err := release.Write(context.Background(), &buf, mb, sig, files); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	if tamper {
		b[len(b)-4096] ^= 0xff
	}
	return b
}

func (e *env) upload(bundle []byte) resp {
	e.t.Helper()
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		_ = mw.WriteField("comment", "ignored")
		w, err := mw.CreateFormFile("bundle", "bomcensus.tar")
		if err == nil {
			_, err = w.Write(bundle)
		}
		if err == nil {
			err = mw.Close()
		}
		pw.CloseWithError(err)
	}()
	req, err := http.NewRequest("POST", e.srv.URL+"/api/v1/releases", pr)
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return e.send(req)
}

func TestReleases(t *testing.T) {
	tr := signtest.Install(t)
	e := newEnv(t, false)

	e.want(e.upload(releaseBundle(t, tr, "1.0.0", true)), 400, CodeVerificationFailed)
	b100 := releaseBundle(t, tr, "1.0.0", false)
	r := e.upload(b100)
	e.want(r, 201, "")
	rel := decode[gen.Release](t, r)
	if rel.Version != "1.0.0" || !rel.Verified || rel.Source != gen.ReleaseSourceUpload || len(rel.Platforms) != 1 || rel.Platforms[0] != "linux-amd64" {
		t.Fatalf("release %+v", rel)
	}
	e.want(e.upload(b100), 409, CodeReleaseExists)
	e.want(e.upload(releaseBundle(t, tr, "1.0.0", false)), 409, apierr.CodeConflict)
	e.want(e.upload(releaseBundle(t, tr, "1.2.0", false)), 201, "")
	if l := decode[gen.ReleaseList](t, e.do("GET", "/releases", nil)); l.Total != 2 || l.Items[0].Version != "1.2.0" {
		t.Fatalf("list %+v", l)
	}
	if l := decode[gen.ReleaseList](t, e.do("GET", "/releases?sort=version&q=1.0", nil)); l.Total != 1 || l.Items[0].Version != "1.0.0" {
		t.Fatalf("filtered %+v", l)
	}

	if s := decode[gen.UpdateSettings](t, e.do("GET", "/update-settings", nil)); s.TargetVersion != nil || s.CheckIntervalMinutes != store.DefaultUpdateCheckIntervalMinutes {
		t.Fatalf("default settings %+v", s)
	}
	e.want(e.do("PUT", "/update-settings", gen.UpdateSettings{TargetVersion: ptr("3.0.0"), CheckIntervalMinutes: 30}), 400, apierr.CodeInvalidArgument)
	e.want(e.do("PUT", "/update-settings", gen.UpdateSettings{TargetVersion: ptr("1.0.0"), CheckIntervalMinutes: 0}), 400, apierr.CodeInvalidArgument)
	s := decode[gen.UpdateSettings](t, e.do("PUT", "/update-settings", gen.UpdateSettings{TargetVersion: ptr("1.0.0"), CheckIntervalMinutes: 30}))
	if deref(s.TargetVersion) != "1.0.0" || s.CheckIntervalMinutes != 30 {
		t.Fatalf("settings %+v", s)
	}
	s = decode[gen.UpdateSettings](t, e.do("PUT", "/update-settings", gen.UpdateSettings{CheckIntervalMinutes: 30}))
	if s.TargetVersion != nil {
		t.Fatalf("cleared settings %+v", s)
	}
}

func TestTLS(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	st := decode[gen.TlsState](t, e.do("GET", "/settings/tls", nil))
	anchor, _ := e.pki.AnchorHash()
	if st.Web.Mode != gen.TlsCertModeAuto || st.Agent.Mode != gen.TlsCertModeAuto || st.AnchorSpkiHash != pkisvc.SPKIString(anchor) ||
		st.Web.ExpiresAt == nil || len(st.Agent.Names) == 0 || st.PendingAnchor != nil {
		t.Fatalf("state %+v", st)
	}
	// Automatic Agent TLS has its own client certificate.
	if st.Agent.ClientSubject == nil || st.Agent.ClientExpiresAt == nil || st.Web.ClientSubject != nil {
		t.Fatalf("client certificate %+v / %+v", st.Agent, st.Web)
	}

	e.want(e.do("PUT", "/settings/tls/web", gen.TlsEndpointUpdate{Mode: gen.TlsCertModeAuto, CertificateChain: ptr("x")}), 400, apierr.CodeInvalidArgument)
	e.want(e.do("PUT", "/settings/tls/web", gen.TlsEndpointUpdate{Mode: gen.TlsCertModeManual}), 400, apierr.CodeInvalidArgument)
	e.want(e.do("PUT", "/settings/tls/web", gen.TlsEndpointUpdate{Mode: gen.TlsCertModeOff}), 400, apierr.CodeInvalidArgument)
	e.want(e.do("PUT", "/settings/tls/web", gen.TlsEndpointUpdate{Mode: gen.TlsCertModeManual, CertificateChain: ptr("x"), PrivateKey: ptr("y"), ClientCertificateChain: ptr("z")}), 400, apierr.CodeInvalidArgument)
	e.want(e.do("PUT", "/settings/tls/web", gen.TlsEndpointUpdate{Mode: gen.TlsCertModeManual, CertificateChain: ptr("x"), PrivateKey: ptr("y")}), 400, apierr.CodeInvalidArgument)

	// A corporate certificate that does not contain the anchor.
	ca, err := pki.NewCA(pki.CAOptions{Subject: pkix.Name{CommonName: "Corp"}})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := pki.GenerateKey()
	leaf, err := ca.IssueServer(&key.PublicKey, pki.LeafOptions{CommonName: "agents.example", DNSNames: []string{"agents.example"}})
	if err != nil {
		t.Fatal(err)
	}
	client, _ := ca.IssueClient(&key.PublicKey, pki.LeafOptions{CommonName: "agents.example", DNSNames: []string{"agents.example"}})
	keyPEM, _ := pki.EncodePrivateKeyPEM(key)
	e.want(e.do("PUT", "/settings/tls/agent", gen.TlsEndpointUpdate{Mode: gen.TlsCertModeManual,
		CertificateChain: ptr(string(pki.EncodeCertificatesPEM(leaf, ca.Cert))), PrivateKey: ptr(string(keyPEM)),
		ClientCertificateChain: ptr(string(pki.EncodeCertificatesPEM(client, ca.Cert))), ClientPrivateKey: ptr(string(keyPEM)),
	}), 409, CodeAnchorMismatch)

	// Anchor change with an agent that has not synchronized.
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := e.db.CreateAgent(ctx, store.Agent{Kind: store.AgentKindAgent, IdentityKey: pub, State: store.AgentApproved}); err != nil {
		t.Fatal(err)
	}
	e.want(e.do("POST", "/settings/tls/agent/anchor", gen.AgentAnchorChange{Action: gen.Activate}), 409, CodeNoPendingAnchor)
	e.want(e.do("POST", "/settings/tls/agent/anchor", gen.AgentAnchorChange{Action: gen.Cancel, Certificate: ptr("x")}), 400, apierr.CodeInvalidArgument)
	st = decode[gen.TlsState](t, e.do("POST", "/settings/tls/agent/anchor", gen.AgentAnchorChange{Action: gen.Prepare}))
	if st.PendingAnchor == nil || st.PendingAnchor.UnsyncedAgents != 1 || st.UnsyncedAgents != 1 {
		t.Fatalf("after prepare %+v", st)
	}
	e.want(e.do("POST", "/settings/tls/agent/anchor", gen.AgentAnchorChange{Action: gen.Prepare}), 409, CodeAnchorPending)
	e.want(e.do("POST", "/settings/tls/agent/anchor", gen.AgentAnchorChange{Action: gen.Activate}), 409, CodeAgentsNotSynced)
	next := st.PendingAnchor.SpkiHash
	st = decode[gen.TlsState](t, e.do("POST", "/settings/tls/agent/anchor", gen.AgentAnchorChange{Action: gen.Activate, Force: ptr(true)}))
	if st.AnchorSpkiHash != next || st.PendingAnchor != nil {
		t.Fatalf("after activate %+v", st)
	}
	// New enrollment strings carry the new anchor.
	created := decode[gen.RegisterKeyCreated](t, e.do("POST", "/register-keys", gen.RegisterKeyCreate{Name: "k", Target: gen.AgentKindAgent, Approval: gen.RegisterKeyApprovalAuto}))
	if !strings.HasPrefix(created.Enrollment, "bc1."+next+".") {
		t.Fatal("enrollment string carries the old anchor")
	}
	srv, _ := e.pki.AgentServerCertificate()
	chain, _ := pki.ParseChain(srv.Certificate)
	var h [32]byte
	raw, _ := base64.RawURLEncoding.DecodeString(next)
	copy(h[:], raw)
	if err := pki.VerifyPinned(chain, h, "localhost", x509.ExtKeyUsageServerAuth); err != nil {
		t.Fatalf("server certificate not under the new anchor: %v", err)
	}
}
