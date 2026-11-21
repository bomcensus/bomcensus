// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package secret

import (
	"encoding/json"
	"fmt"
)

// CredentialSecret is the secret part of a remote collection credential, as
// sealed into store.Credential.Secret. Which fields are set depends on the
// credential kind.
type CredentialSecret struct {
	PrivateKey string `json:"private_key,omitempty"` // ssh_key
	Passphrase string `json:"passphrase,omitempty"`  // ssh_key, optional
	Password   string `json:"password,omitempty"`    // ssh_password
	Kubeconfig string `json:"kubeconfig,omitempty"`  // kubeconfig
}

// CredentialAAD is the associated data that binds a sealed secret to the
// credential with the given ID.
func CredentialAAD(id string) []byte { return []byte("credential:" + id) }

// SealCredential encodes and seals s for the credential with the given ID.
func (b *Box) SealCredential(id string, s CredentialSecret) ([]byte, error) {
	plain, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("secret: encode credential: %w", err)
	}
	defer clear(plain)
	return b.Seal(plain, CredentialAAD(id))
}

// OpenCredential opens a secret sealed by SealCredential.
func (b *Box) OpenCredential(id string, ciphertext []byte) (CredentialSecret, error) {
	plain, err := b.Open(ciphertext, CredentialAAD(id))
	if err != nil {
		return CredentialSecret{}, err
	}
	defer clear(plain)
	var s CredentialSecret
	if err := json.Unmarshal(plain, &s); err != nil {
		return CredentialSecret{}, fmt.Errorf("secret: decode credential: %w", err)
	}
	return s, nil
}
