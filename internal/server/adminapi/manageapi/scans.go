// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package manageapi

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/oapi-codegen/nullable"
	"golang.org/x/crypto/ssh"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/apierr"
	"github.com/bomcensus/bomcensus/internal/server/secret"
	"github.com/bomcensus/bomcensus/internal/server/integritysvc"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// Size limits of credential secrets.
const (
	maxSSHSecret  = 64 << 10
	maxKubeconfig = 1 << 20
	maxUsername   = 256
)

// SSHFingerprint formats the OpenSSH SHA-256 fingerprint of a public key in
// wire format.
func SSHFingerprint(wire []byte) string {
	sum := sha256.Sum256(wire)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// parseHostKey decodes "<type> <base64> [comment]" into the wire format
// and checks that the encoded type matches.
func parseHostKey(s string) ([]byte, error) {
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return nil, errors.New("hostKey must be \"<type> <base64>\"")
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return nil, errors.New("hostKey is not valid base64")
	}
	if len(blob) < 4 {
		return nil, errors.New("hostKey is too short")
	}
	n := binary.BigEndian.Uint32(blob)
	if uint64(n) > uint64(len(blob)-4) || string(blob[4:4+n]) != fields[0] {
		return nil, errors.New("hostKey type does not match its encoding")
	}
	return blob, nil
}

func scanTargetDTO(t store.ScanTarget, pol integritysvc.Policy) gen.ScanTarget {
	out := gen.ScanTarget{
		Id:              t.ID,
		Name:            t.Name,
		Protocol:        gen.ScanProtocolSsh,
		Address:         t.Address,
		Port:            t.Port,
		CredentialId:    t.CredentialID,
		ScannerId:       optString(t.ScannerID),
		Sudo:            t.Sudo,
		HostKeyPinned:   len(t.HostKey) > 0,
		IntervalMinutes: t.IntervalMinutes,
		AssetId:         optString(t.AssetID),
		CreatedAt:       t.CreatedAt,
		DetectDirIds:    orEmpty(t.DetectDirIDs),
	}
	mode := cmp.Or(t.Integrity, store.IntegrityInherit)
	out.Integrity, out.IntegrityEnabled = gen.IntegrityMode(mode), integritysvc.Enabled(mode, pol.SSH)
	if len(t.HostKey) > 0 {
		fp := SSHFingerprint(t.HostKey)
		out.HostKeyFingerprint = &fp
	}
	if r := t.LastRun; r != nil {
		out.LastRun = &gen.ScanRun{At: r.At, Result: gen.ScanResult(r.Result), Message: optString(r.Message), DurationSec: int(r.Duration.Seconds())}
	}
	return out
}

// ListScanTargets implements listScanTargets.
func (h *Handlers) ListScanTargets(ctx context.Context, req gen.ListScanTargetsRequestObject) (gen.ListScanTargetsResponseObject, error) {
	p := req.Params
	f := store.ScanTargetFilter{Q: deref(p.Q)}
	all, err := collectAll(func(pg store.Page) ([]store.ScanTarget, int, error) { return h.st.ListScanTargets(ctx, f, pg) })
	if err != nil {
		return nil, err
	}
	kept := all[:0]
	for _, t := range all {
		if (p.ScannerId == nil || t.ScannerID == *p.ScannerId) &&
			(p.CredentialId == nil || t.CredentialID == *p.CredentialId) &&
			(p.LastResult == nil || (t.LastRun != nil && string(t.LastRun.Result) == string(*p.LastResult))) {
			kept = append(kept, t)
		}
	}
	field, desc := parseSort(p.Sort, "name")
	sortBy(kept, desc, func(x, y store.ScanTarget) int {
		var c int
		switch field {
		case "address":
			c = cmp.Compare(x.Address, y.Address)
		case "lastRun":
			var xa, ya *store.ScanRun = x.LastRun, y.LastRun
			switch {
			case xa == nil && ya != nil:
				c = -1
			case xa != nil && ya == nil:
				c = 1
			case xa != nil:
				c = xa.At.Compare(ya.At)
			}
		}
		return cmp.Or(c, cmpFold(x.Name, y.Name), cmp.Compare(x.ID, y.ID))
	})
	pol, err := integritysvc.Load(ctx, h.st)
	if err != nil {
		return nil, err
	}
	out := gen.ListScanTargets200JSONResponse{Items: []gen.ScanTarget{}, Total: len(kept)}
	for _, t := range paginate(kept, pageOf(p.Limit, p.Offset)) {
		out.Items = append(out.Items, scanTargetDTO(t, pol))
	}
	return out, nil
}

// CreateScanTarget implements createScanTarget.
func (h *Handlers) CreateScanTarget(ctx context.Context, req gen.CreateScanTargetRequestObject) (gen.CreateScanTargetResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, apierr.Invalid("request body is required")
	}
	t := store.ScanTarget{
		Name:            strings.TrimSpace(b.Name),
		Address:         strings.TrimSpace(b.Address),
		Port:            cmp.Or(deref(b.Port), 22),
		CredentialID:    b.CredentialId,
		ScannerID:       deref(b.ScannerId),
		Sudo:            deref(b.Sudo),
		IntervalMinutes: deref(b.IntervalMinutes),
		Integrity:       string(deref(b.Integrity)),
	}
	switch {
	case b.Integrity != nil && !b.Integrity.Valid():
		return nil, apierr.Invalid("unknown integrity mode %q", *b.Integrity)
	case b.Protocol != nil && *b.Protocol != gen.ScanProtocolSsh:
		return nil, apierr.Invalid("protocol must be ssh")
	case t.Address == "" || len(t.Address) > 512 || strings.ContainsAny(t.Address, " \t\r\n/"):
		return nil, apierr.Invalid("address must be a host name or IP address")
	case deref(b.HostKeyFingerprint) != "":
		return nil, apierr.Invalid("the server pins host keys, not fingerprints; give the key in hostKey")
	}
	if err := checkScanTarget(t); err != nil {
		return nil, err
	}
	if hk := strings.TrimSpace(deref(b.HostKey)); hk != "" {
		key, err := parseHostKey(hk)
		if err != nil {
			return nil, apierr.Invalid("%s", err.Error())
		}
		t.HostKey = key
	}
	if err := h.checkSSHCredential(ctx, t.CredentialID); err != nil {
		return nil, err
	}
	if err := h.checkScanner(ctx, t.ScannerID); err != nil {
		return nil, err
	}
	var dirs []string
	if b.DetectDirIds != nil {
		dirs = *b.DetectDirIds
	}
	if err := h.checkDetectDirs(ctx, dirs); err != nil {
		return nil, err
	}
	var created store.ScanTarget
	err := h.st.WithTx(ctx, func(tx store.Store) error {
		var err error
		if created, err = tx.CreateScanTarget(ctx, t); err != nil || len(dirs) == 0 {
			return err
		}
		if err := tx.SetScanTargetDetectDirs(ctx, created.ID, dirs); err != nil {
			return err
		}
		created, err = tx.GetScanTarget(ctx, created.ID)
		return err
	})
	if err != nil {
		return nil, err
	}
	h.log.Info("scan target added", "scan_target_id", created.ID, "address", created.Address, "by", h.who(ctx))
	pol, err := integritysvc.Load(ctx, h.st)
	if err != nil {
		return nil, err
	}
	return gen.CreateScanTarget201JSONResponse(scanTargetDTO(created, pol)), nil
}

// checkScanTarget validates the fields a scan target shares between create
// and update.
func checkScanTarget(t store.ScanTarget) error {
	switch {
	case t.Name == "" || len(t.Name) > 200:
		return apierr.Invalid("name must be 1 to 200 characters")
	case t.Port < 1 || t.Port > 65535:
		return apierr.Invalid("port must be between 1 and 65535")
	case t.IntervalMinutes < 0:
		return apierr.Invalid("intervalMinutes must not be negative")
	}
	return nil
}

// checkSSHCredential checks that id is a stored SSH credential.
func (h *Handlers) checkSSHCredential(ctx context.Context, id string) error {
	c, err := h.st.GetCredential(ctx, id)
	if err != nil {
		if isNotFound(err) {
			return apierr.Invalid("credential %s does not exist", id)
		}
		return err
	}
	if c.Kind != store.CredentialSSHKey && c.Kind != store.CredentialSSHPassword {
		return apierr.Invalid("credential %s is not an SSH credential", c.Name)
	}
	return nil
}

// checkScanner checks that id is empty (the embedded scanner) or an active
// scanner.
func (h *Handlers) checkScanner(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	a, err := h.st.GetAgent(ctx, id)
	if err != nil {
		if isNotFound(err) {
			return apierr.Invalid("scanner %s does not exist", id)
		}
		return err
	}
	if a.Kind != store.AgentKindScanner || a.State == store.AgentRevoked {
		return apierr.Invalid("%s is not an active scanner", id)
	}
	return nil
}

// patchString reads a nullable PATCH field: ok is false when it is absent;
// null gives "".
func patchString(v nullable.Nullable[string]) (string, bool) {
	if !v.IsSpecified() {
		return "", false
	}
	if v.IsNull() {
		return "", true
	}
	return strings.TrimSpace(v.MustGet()), true
}

// UpdateScanTarget implements updateScanTarget.
func (h *Handlers) UpdateScanTarget(ctx context.Context, req gen.UpdateScanTargetRequestObject) (gen.UpdateScanTargetResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, apierr.Invalid("request body is required")
	}
	t, err := h.st.GetScanTarget(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	if b.Name != nil {
		t.Name = strings.TrimSpace(*b.Name)
	}
	if b.Port != nil {
		t.Port = *b.Port
	}
	if b.Sudo != nil {
		t.Sudo = *b.Sudo
	}
	if b.IntervalMinutes != nil {
		t.IntervalMinutes = *b.IntervalMinutes
	}
	if b.Integrity != nil {
		if !b.Integrity.Valid() {
			return nil, apierr.Invalid("unknown integrity mode %q", *b.Integrity)
		}
		t.Integrity = string(*b.Integrity)
	}
	if err := checkScanTarget(t); err != nil {
		return nil, err
	}
	if b.CredentialId != nil {
		t.CredentialID = *b.CredentialId
		if err := h.checkSSHCredential(ctx, t.CredentialID); err != nil {
			return nil, err
		}
	}
	if v, ok := patchString(b.ScannerId); ok {
		t.ScannerID = v
		if err := h.checkScanner(ctx, t.ScannerID); err != nil {
			return nil, err
		}
	}
	if b.DetectDirIds != nil {
		if err := h.checkDetectDirs(ctx, *b.DetectDirIds); err != nil {
			return nil, err
		}
	}
	reset := deref(b.ResetHostKey)
	err = h.st.WithTx(ctx, func(tx store.Store) error {
		if err := tx.UpdateScanTarget(ctx, t); err != nil {
			return err
		}
		if b.DetectDirIds != nil {
			if err := tx.SetScanTargetDetectDirs(ctx, t.ID, *b.DetectDirIds); err != nil {
				return err
			}
		}
		if reset {
			return tx.ClearScanTargetHostKey(ctx, t.ID)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if t, err = h.st.GetScanTarget(ctx, t.ID); err != nil {
		return nil, err
	}
	h.log.Info("scan target updated", "scan_target_id", t.ID, "host_key_reset", reset, "by", h.who(ctx))
	pol, err := integritysvc.Load(ctx, h.st)
	if err != nil {
		return nil, err
	}
	return gen.UpdateScanTarget200JSONResponse(scanTargetDTO(t, pol)), nil
}

// DeleteScanTarget implements deleteScanTarget.
func (h *Handlers) DeleteScanTarget(ctx context.Context, req gen.DeleteScanTargetRequestObject) (gen.DeleteScanTargetResponseObject, error) {
	if err := h.st.DeleteScanTarget(ctx, req.Id); err != nil {
		return nil, err
	}
	return gen.DeleteScanTarget204Response{}, nil
}

// RunScanTarget implements runScanTarget.
func (h *Handlers) RunScanTarget(ctx context.Context, req gen.RunScanTargetRequestObject) (gen.RunScanTargetResponseObject, error) {
	t, err := h.st.GetScanTarget(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	if h.runner == nil {
		return nil, apierr.Unavailable("scanning is not available")
	}
	if err := h.runner.RequestRun(ctx, t.ID); err != nil {
		return nil, err
	}
	return gen.RunScanTarget202Response{}, nil
}

// ── credentials ─────────────────────────────────────────────────────────

func credentialDTO(c store.Credential, clusters int) gen.Credential {
	return gen.Credential{
		Id:                   c.ID,
		Name:                 c.Name,
		Kind:                 gen.CredentialKind(c.Kind),
		Username:             optString(c.Username),
		PublicKeyFingerprint: optString(c.PublicKeyFingerprint),
		UsedBy:               c.UsedBy + clusters,
		CreatedAt:            c.CreatedAt,
	}
}

// credentialFingerprint is the public key fingerprint of an ssh_key secret
// and "" for other kinds. The public key of an encrypted OpenSSH key is read
// without the passphrase.
func credentialFingerprint(kind store.CredentialKind, s secret.CredentialSecret) (string, error) {
	if kind != store.CredentialSSHKey {
		return "", nil
	}
	var signer ssh.Signer
	var err error
	if s.Passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(s.PrivateKey), []byte(s.Passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey([]byte(s.PrivateKey))
	}
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) && missing.PublicKey != nil {
			return ssh.FingerprintSHA256(missing.PublicKey), nil
		}
		return "", fmt.Errorf("privateKey cannot be read: %w", err)
	}
	return ssh.FingerprintSHA256(signer.PublicKey()), nil
}

// ListCredentials implements listCredentials. Secrets are never read.
func (h *Handlers) ListCredentials(ctx context.Context, req gen.ListCredentialsRequestObject) (gen.ListCredentialsResponseObject, error) {
	p := req.Params
	all, err := h.st.ListCredentials(ctx)
	if err != nil {
		return nil, err
	}
	counts, err := h.clusters.CredentialClusterCounts(ctx)
	if err != nil {
		return nil, err
	}
	kept := all[:0]
	for _, c := range all {
		if (p.Kind == nil || string(c.Kind) == string(*p.Kind)) && matches(p.Q, c.Name, c.Username) {
			kept = append(kept, c)
		}
	}
	field, desc := parseSort(p.Sort, "name")
	sortBy(kept, desc, func(x, y store.Credential) int {
		var c int
		switch field {
		case "kind":
			c = cmp.Compare(x.Kind, y.Kind)
		case "username":
			c = cmpFold(x.Username, y.Username)
		case "usedBy":
			c = cmp.Compare(x.UsedBy+counts[x.ID], y.UsedBy+counts[y.ID])
		case "createdAt":
			c = x.CreatedAt.Compare(y.CreatedAt)
		}
		return cmp.Or(c, cmpFold(x.Name, y.Name))
	})
	out := gen.ListCredentials200JSONResponse{Items: []gen.Credential{}, Total: len(kept)}
	for _, c := range paginate(kept, pageOf(p.Limit, p.Offset)) {
		out.Items = append(out.Items, credentialDTO(c, counts[c.ID]))
	}
	return out, nil
}

func credentialSecret(b *gen.CredentialCreate) (string, secret.CredentialSecret, error) {
	username := strings.TrimSpace(deref(b.Username))
	s := secret.CredentialSecret{
		PrivateKey: deref(b.PrivateKey),
		Passphrase: deref(b.Passphrase),
		Password:   deref(b.Password),
		Kubeconfig: deref(b.Kubeconfig),
	}
	absent := func(field, value string) error {
		if value != "" {
			return fmt.Errorf("%s does not apply to %s credentials", field, b.Kind)
		}
		return nil
	}
	var err error
	switch store.CredentialKind(b.Kind) {
	case store.CredentialSSHKey:
		switch {
		case username == "":
			err = errors.New("username is required")
		case s.PrivateKey == "":
			err = errors.New("privateKey is required")
		case len(s.PrivateKey)+len(s.Passphrase) > maxSSHSecret:
			err = errors.New("privateKey is too large")
		case !strings.Contains(s.PrivateKey, "-----BEGIN ") || !strings.Contains(s.PrivateKey, "PRIVATE KEY-----"):
			err = errors.New("privateKey must be an OpenSSH or PEM private key")
		default:
			err = cmp.Or(absent("password", s.Password), absent("kubeconfig", s.Kubeconfig))
		}
	case store.CredentialSSHPassword:
		switch {
		case username == "":
			err = errors.New("username is required")
		case s.Password == "":
			err = errors.New("password is required")
		case len(s.Password) > maxSSHSecret:
			err = errors.New("password is too long")
		default:
			err = cmp.Or(absent("privateKey", s.PrivateKey), absent("passphrase", s.Passphrase), absent("kubeconfig", s.Kubeconfig))
		}
	case store.CredentialKubeconfig:
		switch {
		case strings.TrimSpace(s.Kubeconfig) == "":
			err = errors.New("kubeconfig is required")
		case len(s.Kubeconfig) > maxKubeconfig:
			err = errors.New("kubeconfig is too large")
		default:
			err = cmp.Or(absent("username", username), absent("privateKey", s.PrivateKey),
				absent("passphrase", s.Passphrase), absent("password", s.Password))
		}
	default:
		err = errors.New("kind must be ssh_key, ssh_password or kubeconfig")
	}
	if err == nil && len(username) > maxUsername {
		err = errors.New("username is too long")
	}
	return username, s, err
}

// CreateCredential implements createCredential. The secret is sealed with
// the master key, bound to the credential ID.
func (h *Handlers) CreateCredential(ctx context.Context, req gen.CreateCredentialRequestObject) (gen.CreateCredentialResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, apierr.Invalid("request body is required")
	}
	name := strings.TrimSpace(b.Name)
	if name == "" || len(name) > 200 {
		return nil, apierr.Invalid("name must be 1 to 200 characters")
	}
	username, sec, err := credentialSecret(b)
	if err != nil {
		return nil, apierr.Invalid("%s", err.Error())
	}
	fingerprint, err := credentialFingerprint(store.CredentialKind(b.Kind), sec)
	if err != nil {
		return nil, apierr.Invalid("%s", err.Error())
	}
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	sealed, err := h.secrets.SealCredential(id.String(), sec)
	if err != nil {
		return nil, err
	}
	c, err := h.st.CreateCredential(ctx, store.Credential{
		ID:                   id.String(),
		Name:                 name,
		Kind:                 store.CredentialKind(b.Kind),
		Username:             username,
		Secret:               sealed,
		PublicKeyFingerprint: fingerprint,
		CreatedBy:            h.who(ctx),
	})
	if err != nil {
		if isConflict(err) {
			return nil, apierr.Conflict("a credential with this name exists").Wrap(err)
		}
		return nil, err
	}
	h.log.Info("credential created", "credential_id", c.ID, "name", c.Name, "kind", c.Kind, "by", c.CreatedBy)
	return gen.CreateCredential201JSONResponse(credentialDTO(c, 0)), nil
}

// RotateCredentialSecret implements rotateCredentialSecret. The new secret
// is validated as on creation for the credential's kind and sealed under
// the same credential ID.
func (h *Handlers) RotateCredentialSecret(ctx context.Context, req gen.RotateCredentialSecretRequestObject) (gen.RotateCredentialSecretResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, apierr.Invalid("request body is required")
	}
	c, err := h.st.GetCredential(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	in := gen.CredentialCreate{
		Name: c.Name, Kind: gen.CredentialKind(c.Kind), Username: b.Username,
		PrivateKey: b.PrivateKey, Passphrase: b.Passphrase, Password: b.Password, Kubeconfig: b.Kubeconfig,
	}
	if in.Username == nil {
		in.Username = optString(c.Username)
	}
	username, sec, err := credentialSecret(&in)
	if err != nil {
		return nil, apierr.Invalid("%s", err.Error())
	}
	fingerprint, err := credentialFingerprint(c.Kind, sec)
	if err != nil {
		return nil, apierr.Invalid("%s", err.Error())
	}
	sealed, err := h.secrets.SealCredential(c.ID, sec)
	if err != nil {
		return nil, err
	}
	updated, err := h.st.UpdateCredentialSecret(ctx, store.Credential{
		ID: c.ID, Username: username, Secret: sealed, PublicKeyFingerprint: fingerprint,
	})
	if err != nil {
		return nil, err
	}
	counts, err := h.clusters.CredentialClusterCounts(ctx)
	if err != nil {
		return nil, err
	}
	h.log.Info("credential secret replaced", "credential_id", c.ID, "name", c.Name, "by", h.who(ctx))
	return gen.RotateCredentialSecret200JSONResponse(credentialDTO(updated, counts[c.ID])), nil
}

// DeleteCredential implements deleteCredential. It is refused while a scan
// target or a Kubernetes cluster uses the credential.
func (h *Handlers) DeleteCredential(ctx context.Context, req gen.DeleteCredentialRequestObject) (gen.DeleteCredentialResponseObject, error) {
	counts, err := h.clusters.CredentialClusterCounts(ctx)
	if err != nil {
		return nil, err
	}
	if n := counts[req.Id]; n > 0 {
		return nil, apierr.New(409, apierr.CodeInUse, fmt.Sprintf("the credential is used by %d Kubernetes clusters", n))
	}
	if err := h.st.DeleteCredential(ctx, req.Id); err != nil {
		if errors.Is(err, store.ErrInUse) {
			return nil, apierr.New(409, apierr.CodeInUse, "the credential is used by a scan target").Wrap(err)
		}
		return nil, err
	}
	h.log.Info("credential deleted", "credential_id", req.Id, "by", h.who(ctx))
	return gen.DeleteCredential204Response{}, nil
}
