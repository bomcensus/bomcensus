// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package bootstrap

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/bomcensus/bomcensus/internal/server/pkisvc"
	"github.com/bomcensus/bomcensus/internal/server/secret"
	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/internal/server/store/postgres"
	"github.com/bomcensus/bomcensus/internal/token"
)

const (
	testNS     = "bomcensus"
	testSecret = "scanner-enrollment"
)

type env struct {
	db   *postgres.DB
	box  *secret.Box
	kube *fake.Clientset
}

func newEnv(t *testing.T, objects ...runtime.Object) *env {
	t.Helper()
	key := make([]byte, secret.KeySize)
	_, _ = rand.Read(key)
	box, err := secret.New(key)
	if err != nil {
		t.Fatal(err)
	}
	return &env{db: newTestDB(t), box: box, kube: fake.NewClientset(objects...)}
}

// bootstrapPKI does what the server does at start.
func (e *env) bootstrapPKI(t *testing.T) *pkisvc.Service {
	t.Helper()
	svc, err := pkisvc.New(pkisvc.Config{Store: e.db, Box: e.box, AgentServerNames: []string{"agents.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	return svc
}

func (e *env) opts() Options {
	return Options{
		Store: e.db, Box: e.box, Kube: e.kube,
		Namespace: testNS, SecretName: testSecret,
		MaxUses: 2, PollInterval: 20 * time.Millisecond,
	}
}

func (e *env) run(t *testing.T, o Options) Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := Scanner(ctx, o)
	if err != nil {
		t.Fatalf("Scanner: %v", err)
	}
	return res
}

func (e *env) stored(t *testing.T) (token.Token, *corev1.Secret) {
	t.Helper()
	s, err := e.kube.CoreV1().Secrets(testNS).Get(context.Background(), testSecret, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	tok, err := token.Parse(string(s.Data[DefaultSecretKey]))
	if err != nil {
		t.Fatalf("stored token: %v", err)
	}
	return tok, s
}

func TestScannerCreatesAndKeeps(t *testing.T) {
	e := newEnv(t)
	svc := e.bootstrapPKI(t)
	anchor, err := svc.AnchorHash()
	if err != nil {
		t.Fatal(err)
	}

	res := e.run(t, e.opts())
	if res.Outcome != Created {
		t.Fatalf("outcome = %s, want created", res.Outcome)
	}
	tok, s := e.stored(t)
	if tok.CAHash != anchor {
		t.Error("enrollment string does not pin the current anchor")
	}
	if tok.KeyID.String() != res.KeyID {
		t.Errorf("key id %s, result %s", tok.KeyID, res.KeyID)
	}
	if s.Labels["app.kubernetes.io/component"] != "scanner-enrollment" {
		t.Errorf("labels = %v", s.Labels)
	}
	k, err := e.db.GetRegisterKey(context.Background(), res.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	if k.Target != store.AgentKindScanner || k.Approval != store.ApprovalAuto || k.MaxUses != 2 ||
		k.Name != DefaultKeyName || k.CreatedBy != CreatedBy || string(k.PublicKey) != string(tok.PublicKey()) {
		t.Errorf("register key = %+v", k)
	}

	again := e.run(t, e.opts())
	if again.Outcome != Kept || again.KeyID != res.KeyID {
		t.Fatalf("second run = %+v, want kept %s", again, res.KeyID)
	}
	_, total, err := e.db.ListRegisterKeys(context.Background(), store.RegisterKeyFilter{}, store.Page{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Errorf("%d register keys, want 1", total)
	}
}

func TestScannerReplacesUnusable(t *testing.T) {
	cases := []struct {
		name  string
		spoil func(t *testing.T, e *env, id string)
	}{
		{"exhausted", func(t *testing.T, e *env, id string) {
			for range 2 {
				if _, err := e.db.ConsumeRegisterKey(context.Background(), id, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{"revoked", func(t *testing.T, e *env, id string) {
			if err := e.db.RevokeRegisterKey(context.Background(), id, time.Now()); err != nil {
				t.Fatal(err)
			}
		}},
		{"malformed", func(t *testing.T, e *env, id string) {
			e.setData(t, map[string][]byte{DefaultSecretKey: []byte("bc1.nonsense")})
		}},
		{"unknown key", func(t *testing.T, e *env, id string) {
			var anchor [32]byte
			svc := e.bootstrapPKI(t)
			anchor, _ = svc.AnchorHash()
			tok, err := token.New(anchor)
			if err != nil {
				t.Fatal(err)
			}
			e.setData(t, map[string][]byte{DefaultSecretKey: []byte(token.Format(tok))})
		}},
		{"other anchor", func(t *testing.T, e *env, id string) {
			var other [32]byte
			other[0] = 1
			tok, err := token.New(other)
			if err != nil {
				t.Fatal(err)
			}
			e.setData(t, map[string][]byte{DefaultSecretKey: []byte(token.Format(tok))})
		}},
		{"empty", func(t *testing.T, e *env, id string) {
			e.setData(t, map[string][]byte{"other": []byte("x")})
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			e.bootstrapPKI(t)
			first := e.run(t, e.opts())
			c.spoil(t, e, first.KeyID)
			res := e.run(t, e.opts())
			if res.Outcome != Created || res.KeyID == first.KeyID {
				t.Fatalf("result = %+v, want a new key (first %s)", res, first.KeyID)
			}
			tok, _ := e.stored(t)
			if tok.KeyID.String() != res.KeyID {
				t.Errorf("secret holds %s, want %s", tok.KeyID, res.KeyID)
			}
		})
	}
}

func TestScannerKeepsKeyOfEnrolledScanner(t *testing.T) {
	e := newEnv(t)
	e.bootstrapPKI(t)
	o := e.opts()
	o.MaxUses = 1
	first := e.run(t, o)
	ctx := context.Background()
	if _, err := e.db.ConsumeRegisterKey(ctx, first.KeyID, time.Now()); err != nil {
		t.Fatal(err)
	}
	a, err := e.db.CreateAgent(ctx, store.Agent{
		Kind: store.AgentKindScanner, Hostname: "scanner-0", IdentityKey: []byte("identity-" + first.KeyID),
		RegisterKeyID: first.KeyID, State: store.AgentApproved,
	})
	if err != nil {
		t.Fatal(err)
	}

	if res := e.run(t, o); res.Outcome != Kept || res.KeyID != first.KeyID {
		t.Fatalf("with an enrolled scanner: %+v, want kept %s", res, first.KeyID)
	}

	if err := e.db.RevokeAgent(ctx, a.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	res := e.run(t, o)
	if res.Outcome != Created || res.KeyID == first.KeyID {
		t.Fatalf("after the scanner was revoked: %+v, want a new key", res)
	}
}

func (e *env) setData(t *testing.T, data map[string][]byte) {
	t.Helper()
	s, err := e.kube.CoreV1().Secrets(testNS).Get(context.Background(), testSecret, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	s.Data = data
	if _, err := e.kube.CoreV1().Secrets(testNS).Update(context.Background(), s, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestScannerUpdatesForeignSecret(t *testing.T) {
	pre := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: testSecret, Namespace: testNS, Labels: map[string]string{"team": "a"}},
		Data:       map[string][]byte{"note": []byte("keep me")},
	}
	e := newEnv(t, pre)
	e.bootstrapPKI(t)
	if res := e.run(t, e.opts()); res.Outcome != Created {
		t.Fatalf("outcome = %s", res.Outcome)
	}
	_, s := e.stored(t)
	if string(s.Data["note"]) != "keep me" || s.Labels["team"] != "a" || s.Labels["app.kubernetes.io/managed-by"] != "bomcensus-server" {
		t.Errorf("secret = %+v", s)
	}
}

func TestScannerWaitsForPKI(t *testing.T) {
	e := newEnv(t)
	done := make(chan Result, 1)
	errc := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		res, err := Scanner(ctx, e.opts())
		if err != nil {
			errc <- err
			return
		}
		done <- res
	}()
	time.Sleep(150 * time.Millisecond)
	select {
	case res := <-done:
		t.Fatalf("finished before the PKI existed: %+v", res)
	case err := <-errc:
		t.Fatalf("failed before the PKI existed: %v", err)
	default:
	}
	e.bootstrapPKI(t)
	select {
	case res := <-done:
		if res.Outcome != Created {
			t.Errorf("outcome = %s", res.Outcome)
		}
	case err := <-errc:
		t.Fatal(err)
	case <-time.After(20 * time.Second):
		t.Fatal("did not finish after the PKI was bootstrapped")
	}
}

func TestScannerTimesOutWithoutPKI(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := Scanner(ctx, e.opts())
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if _, err := e.kube.CoreV1().Secrets(testNS).Get(context.Background(), testSecret, metav1.GetOptions{}); err == nil {
		t.Error("secret written without PKI")
	}
}

func TestScannerRevokesKeyWhenSecretWriteFails(t *testing.T) {
	e := newEnv(t)
	e.bootstrapPKI(t)
	e.kube.PrependReactor("create", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("forbidden")
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := Scanner(ctx, e.opts()); err == nil {
		t.Fatal("no error")
	}
	keys, total, err := e.db.ListRegisterKeys(context.Background(), store.RegisterKeyFilter{}, store.Page{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || keys[0].RevokedAt == nil {
		t.Fatalf("keys = %+v, want one revoked key", keys)
	}
}

func TestScannerOptions(t *testing.T) {
	ctx := context.Background()
	if _, err := Scanner(ctx, Options{}); err == nil {
		t.Error("empty options accepted")
	}
	key := make([]byte, secret.KeySize)
	box, _ := secret.New(key)
	base := Options{Store: (*postgres.DB)(nil), Box: box, Kube: fake.NewClientset(), Namespace: "n", SecretName: "s"}
	o := base
	o.MaxUses = -1
	if _, err := Scanner(ctx, o); err == nil {
		t.Error("negative max uses accepted")
	}
	o = base
	o.SecretName = ""
	if _, err := Scanner(ctx, o); err == nil {
		t.Error("missing secret name accepted")
	}
}
