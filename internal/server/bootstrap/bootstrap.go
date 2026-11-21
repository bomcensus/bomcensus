// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package bootstrap prepares the enrollment of a scanner that is deployed
// together with the server, for example by the bomcensus-manager Helm chart.
//
// An enrollment string carries the hash of the Agent TLS trust anchor, which
// exists only after a server has started and bootstrapped its PKI. Scanner
// waits for that, creates a Register Key of kind scanner and stores the
// enrollment string in a Kubernetes Secret, where the scanner pod reads it.
// Running it again keeps a stored string as long as it can still enroll, or
// as long as a scanner enrolled with it is active.
package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/bomcensus/bomcensus/internal/server/pkisvc"
	"github.com/bomcensus/bomcensus/internal/server/secret"
	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/internal/server/store/postgres"
	"github.com/bomcensus/bomcensus/internal/token"
)

// Defaults of Options.
const (
	DefaultSecretKey    = "token"
	DefaultKeyName      = "kubernetes scanner"
	DefaultPollInterval = 5 * time.Second
)

// CreatedBy is the created_by value of the Register Keys made here.
const CreatedBy = "bootstrap-scanner"

// Labels put on the Secret written by Scanner.
var secretLabels = map[string]string{
	"app.kubernetes.io/managed-by": "bomcensus-server",
	"app.kubernetes.io/component":  "scanner-enrollment",
}

// Store is what Scanner needs from the database.
type Store interface {
	pkisvc.Store
	store.RegisterKeys
	store.Agents
}

// Options configures Scanner.
type Options struct {
	Store Store
	// Box opens the PKI material; it holds the server's master key.
	Box *secret.Box
	// Kube is the client used to read and write the Secret.
	Kube kubernetes.Interface
	// Namespace and SecretName name the Secret; SecretKey is the data key
	// holding the enrollment string (default DefaultSecretKey).
	Namespace  string
	SecretName string
	SecretKey  string
	// KeyName is the name of a new Register Key (default DefaultKeyName).
	KeyName string
	// MaxUses of a new Register Key; 0 means unlimited.
	MaxUses int
	// PollInterval is how often the PKI is checked while waiting for the
	// server to bootstrap it (default DefaultPollInterval).
	PollInterval time.Duration
	Logger       *slog.Logger
	// Now is the clock (default time.Now).
	Now func() time.Time
}

// Outcome says what Scanner did.
type Outcome string

// Outcomes.
const (
	// Kept means the Secret already held a usable enrollment string.
	Kept Outcome = "kept"
	// Created means a new Register Key was created and stored.
	Created Outcome = "created"
)

// Result is the outcome of Scanner.
type Result struct {
	Outcome Outcome
	// KeyID is the Register Key in the Secret.
	KeyID string
}

// Scanner waits until the PKI is bootstrapped and makes sure the Secret holds
// an enrollment string for a scanner that is still good: its Register Key
// exists, is of kind scanner and pins the current trust anchor, and it is
// either usable (neither revoked, expired nor used up) or used up by a
// scanner that is still enrolled. The second case keeps a single-use key in
// place after the scanner enrolled, instead of minting a new usable key on
// every run. Otherwise Scanner creates a new key with automatic approval and
// writes its string into the Secret, creating the Secret if needed. Waiting
// ends with ctx.
func Scanner(ctx context.Context, o Options) (Result, error) {
	if o.Store == nil || o.Box == nil || o.Kube == nil {
		return Result{}, errors.New("bootstrap: store, secret box and Kubernetes client are required")
	}
	if o.Namespace == "" || o.SecretName == "" {
		return Result{}, errors.New("bootstrap: secret namespace and name are required")
	}
	if o.MaxUses < 0 {
		return Result{}, errors.New("bootstrap: max uses must not be negative")
	}
	if o.SecretKey == "" {
		o.SecretKey = DefaultSecretKey
	}
	if o.KeyName == "" {
		o.KeyName = DefaultKeyName
	}
	if len(o.KeyName) > 200 {
		return Result{}, errors.New("bootstrap: key name must be at most 200 characters")
	}
	if o.PollInterval <= 0 {
		o.PollInterval = DefaultPollInterval
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Now == nil {
		o.Now = time.Now
	}

	anchor, err := waitAnchor(ctx, o)
	if err != nil {
		return Result{}, err
	}

	secrets := o.Kube.CoreV1().Secrets(o.Namespace)
	existing, err := secrets.Get(ctx, o.SecretName, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		existing = nil
	case err != nil:
		return Result{}, fmt.Errorf("bootstrap: read secret %s/%s: %w", o.Namespace, o.SecretName, err)
	}
	if existing != nil {
		id, why := usable(ctx, o, existing.Data[o.SecretKey], anchor)
		if why == "" {
			o.Logger.Info("keeping the enrollment string", "secret", o.Namespace+"/"+o.SecretName, "key_id", id)
			return Result{Outcome: Kept, KeyID: id}, nil
		}
		o.Logger.Info("replacing enrollment string", "secret", o.Namespace+"/"+o.SecretName, "reason", why)
	}

	tok, k, err := createKey(ctx, o, anchor)
	if err != nil {
		return Result{}, err
	}
	o.Logger.Info("register key created", "key_id", k.ID, "name", k.Name, "target", k.Target,
		"approval", k.Approval, "max_uses", k.MaxUses, "by", k.CreatedBy)
	if err := writeSecret(ctx, o, existing, []byte(token.Format(tok))); err != nil {
		// Without the Secret nobody holds the string; revoke the key so it
		// does not linger as usable.
		if rerr := o.Store.RevokeRegisterKey(context.WithoutCancel(ctx), k.ID, o.Now()); rerr != nil {
			o.Logger.Warn("revoking the unused register key failed", "key_id", k.ID, "err", rerr)
		}
		return Result{}, err
	}
	o.Logger.Info("enrollment string stored", "secret", o.Namespace+"/"+o.SecretName, "key_id", k.ID)
	return Result{Outcome: Created, KeyID: k.ID}, nil
}

// waitAnchor loads the PKI through pkisvc until it succeeds and returns the
// hash of the current Agent TLS trust anchor. The server creates the PKI
// (and the tables) at start, so failures are expected for a while.
func waitAnchor(ctx context.Context, o Options) ([32]byte, error) {
	svc, err := pkisvc.New(pkisvc.Config{Store: o.Store, Box: o.Box, Logger: o.Logger, Now: o.Now})
	if err != nil {
		return [32]byte{}, err
	}
	var last error
	for attempt := 0; ; attempt++ {
		if last = svc.Refresh(ctx); last == nil {
			return svc.AnchorHash()
		}
		if attempt%6 == 0 {
			o.Logger.Info("waiting for the server to bootstrap the PKI", "err", last)
		}
		if !sleep(ctx, o.PollInterval) {
			return [32]byte{}, fmt.Errorf("bootstrap: PKI not available: %w", errors.Join(ctx.Err(), last))
		}
	}
}

// usable checks a stored enrollment string. It returns the key ID and an
// empty reason when the string can still enroll a scanner.
func usable(ctx context.Context, o Options, raw []byte, anchor [32]byte) (string, string) {
	if len(raw) == 0 {
		return "", "no enrollment string"
	}
	tok, err := token.Parse(string(bytes.TrimSpace(raw)))
	if err != nil {
		return "", "malformed enrollment string"
	}
	defer clear(tok.Secret[:])
	id := tok.KeyID.String()
	if tok.CAHash != anchor {
		return id, "trust anchor changed"
	}
	k, err := o.Store.GetRegisterKey(ctx, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return id, "register key does not exist"
	case err != nil:
		return id, "register key lookup failed: " + err.Error()
	case k.Target != store.AgentKindScanner:
		return id, "register key is not for scanners"
	case !bytes.Equal(k.PublicKey, tok.PublicKey()):
		return id, "register key does not match"
	}
	err = k.Usable(o.Now())
	if err == nil {
		return id, ""
	}
	if errors.Is(err, store.ErrRegisterKeyExhausted) {
		switch enrolled, lerr := enrolledWith(ctx, o.Store, id); {
		case lerr != nil:
			return id, "scanner lookup failed: " + lerr.Error()
		case enrolled != "":
			o.Logger.Info("register key is used up by an enrolled scanner", "key_id", id, "agent_id", enrolled)
			return id, ""
		}
	}
	return id, err.Error()
}

// enrolledWith returns the ID of a scanner enrolled with the Register Key
// that is not revoked, or "".
func enrolledWith(ctx context.Context, st store.Agents, keyID string) (string, error) {
	const page = 500
	for off := 0; ; off += page {
		agents, total, err := st.ListAgents(ctx, store.AgentFilter{Kind: store.AgentKindScanner}, store.Page{Limit: page, Offset: off})
		if err != nil {
			return "", err
		}
		for _, a := range agents {
			if a.RegisterKeyID == keyID && a.RevokedAt == nil {
				return a.ID, nil
			}
		}
		if len(agents) == 0 || off+len(agents) >= total {
			return "", nil
		}
	}
}

// createKey creates a Register Key the way the console does: a fresh token
// under the current anchor, its ID and public key stored, retried on an ID
// collision.
func createKey(ctx context.Context, o Options, anchor [32]byte) (token.Token, store.RegisterKey, error) {
	k := store.RegisterKey{
		Name:      o.KeyName,
		Target:    store.AgentKindScanner,
		MaxUses:   o.MaxUses,
		Approval:  store.ApprovalAuto,
		CreatedBy: CreatedBy,
	}
	for attempt := 0; ; attempt++ {
		tok, err := token.New(anchor)
		if err != nil {
			return token.Token{}, store.RegisterKey{}, err
		}
		k.ID = tok.KeyID.String()
		k.PublicKey = tok.PublicKey()
		created, err := o.Store.CreateRegisterKey(ctx, k)
		if err == nil {
			return tok, created, nil
		}
		if !errors.Is(err, store.ErrConflict) || attempt == 2 {
			return token.Token{}, store.RegisterKey{}, fmt.Errorf("bootstrap: create register key: %w", err)
		}
	}
}

// writeSecret stores the string in the Secret, creating it when existing is
// nil. A concurrent change makes it fail; the caller runs again.
func writeSecret(ctx context.Context, o Options, existing *corev1.Secret, value []byte) error {
	secrets := o.Kube.CoreV1().Secrets(o.Namespace)
	if existing == nil {
		s := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: o.SecretName, Namespace: o.Namespace, Labels: secretLabels},
			Type:       corev1.SecretTypeOpaque,
			Data:       map[string][]byte{o.SecretKey: value},
		}
		if _, err := secrets.Create(ctx, s, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("bootstrap: create secret %s/%s: %w", o.Namespace, o.SecretName, err)
		}
		return nil
	}
	s := existing.DeepCopy()
	if s.Data == nil {
		s.Data = map[string][]byte{}
	}
	s.Data[o.SecretKey] = value
	if s.Labels == nil {
		s.Labels = map[string]string{}
	}
	for k, v := range secretLabels {
		s.Labels[k] = v
	}
	if _, err := secrets.Update(ctx, s, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("bootstrap: update secret %s/%s: %w", o.Namespace, o.SecretName, err)
	}
	return nil
}

// Connect opens the database, retrying every interval until it answers or
// ctx ends. The server may still be starting, or the database itself.
func Connect(ctx context.Context, url string, interval time.Duration, log *slog.Logger) (*postgres.DB, error) {
	if interval <= 0 {
		interval = DefaultPollInterval
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	for attempt := 0; ; attempt++ {
		db, err := postgres.Open(ctx, url)
		if err == nil {
			return db, nil
		}
		if attempt%6 == 0 {
			log.Info("waiting for the database", "err", err)
		}
		if !sleep(ctx, interval) {
			return nil, fmt.Errorf("bootstrap: database not available: %w", errors.Join(ctx.Err(), err))
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
