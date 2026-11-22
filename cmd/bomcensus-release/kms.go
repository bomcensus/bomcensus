// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// A manifest key given as gcp-kms://<CryptoKeyVersion resource name> signs
// through the Cloud KMS REST API with an EC_SIGN_ED25519 key (pure Ed25519
// over the data). The access token comes from $GOOGLE_OAUTH_ACCESS_TOKEN.
const (
	kmsScheme   = "gcp-kms://"
	kmsTokenEnv = "GOOGLE_OAUTH_ACCESS_TOKEN"
	kmsEd25519  = "EC_SIGN_ED25519"
)

// kmsEndpoint is the API base URL; tests replace it.
var kmsEndpoint = "https://cloudkms.googleapis.com/v1/"

var kmsVersionName = regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/cryptoKeyVersions/[^/]+$`)

var crc32c = crc32.MakeTable(crc32.Castagnoli)

// openManifestSigner returns the signer for a --manifest-key value: a PEM
// file with an Ed25519 private key, or a Cloud KMS key version.
func openManifestSigner(ctx context.Context, ref string) (crypto.Signer, error) {
	if !strings.HasPrefix(ref, kmsScheme) {
		key, err := readManifestKey(ref)
		if err != nil {
			return nil, err
		}
		return key, nil
	}
	name := strings.TrimPrefix(ref, kmsScheme)
	if !kmsVersionName.MatchString(name) {
		return nil, fmt.Errorf("%s: want gcp-kms://projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/N", ref)
	}
	token := strings.TrimSpace(os.Getenv(kmsTokenEnv))
	if token == "" {
		return nil, fmt.Errorf("%s: set %s (for example $(gcloud auth print-access-token))", ref, kmsTokenEnv)
	}
	s := &kmsSigner{client: &http.Client{Timeout: time.Minute}, token: token, name: name}
	if err := s.loadPublicKey(ctx); err != nil {
		return nil, fmt.Errorf("%s: %w", ref, err)
	}
	return s, nil
}

type kmsSigner struct {
	client *http.Client
	token  string
	name   string
	pub    ed25519.PublicKey
}

func (s *kmsSigner) Public() crypto.PublicKey { return s.pub }

// Sign signs message itself (pure Ed25519); opts must not name a hash.
func (s *kmsSigner) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && opts.HashFunc() != 0 {
		return nil, errors.New("kms: Ed25519 signs the message itself, not a digest")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	req := struct {
		Data       string `json:"data"`
		DataCrc32c string `json:"dataCrc32c"`
	}{
		Data:       base64.StdEncoding.EncodeToString(message),
		DataCrc32c: strconv.FormatUint(uint64(crc32.Checksum(message, crc32c)), 10),
	}
	var resp struct {
		Signature          string `json:"signature"`
		SignatureCrc32c    string `json:"signatureCrc32c"`
		VerifiedDataCrc32c bool   `json:"verifiedDataCrc32c"`
		Name               string `json:"name"`
	}
	if err := s.call(ctx, http.MethodPost, s.name+":asymmetricSign", req, &resp); err != nil {
		return nil, err
	}
	if resp.Name != s.name {
		return nil, fmt.Errorf("kms: signed with %q, not %q", resp.Name, s.name)
	}
	if !resp.VerifiedDataCrc32c {
		return nil, errors.New("kms: the service did not confirm the data checksum")
	}
	sig, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		return nil, fmt.Errorf("kms: signature: %w", err)
	}
	if err := checkCRC32C(sig, resp.SignatureCrc32c); err != nil {
		return nil, fmt.Errorf("kms: signature: %w", err)
	}
	if !ed25519.Verify(s.pub, message, sig) {
		return nil, errors.New("kms: signature does not verify with the key's public key")
	}
	return sig, nil
}

func (s *kmsSigner) loadPublicKey(ctx context.Context) error {
	var resp struct {
		Pem       string `json:"pem"`
		Algorithm string `json:"algorithm"`
		PemCrc32c string `json:"pemCrc32c"`
	}
	if err := s.call(ctx, http.MethodGet, s.name+"/publicKey", nil, &resp); err != nil {
		return err
	}
	if resp.Algorithm != kmsEd25519 {
		return fmt.Errorf("kms: key algorithm is %s, want %s", resp.Algorithm, kmsEd25519)
	}
	if resp.PemCrc32c != "" {
		if err := checkCRC32C([]byte(resp.Pem), resp.PemCrc32c); err != nil {
			return fmt.Errorf("kms: public key: %w", err)
		}
	}
	blk, _ := pem.Decode([]byte(resp.Pem))
	if blk == nil || blk.Type != "PUBLIC KEY" {
		return errors.New("kms: public key is not a PEM PUBLIC KEY")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return fmt.Errorf("kms: public key: %w", err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("kms: public key is %T, not Ed25519", k)
	}
	s.pub = pub
	return nil
}

// call sends one API request, retrying a few times on rate limits and
// server errors. Signing the same data again is harmless.
func (s *kmsSigner) call(ctx context.Context, method, path string, in, out any) error {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	var last error
	for attempt := range 4 {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return errors.Join(last, ctx.Err())
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, method, kmsEndpoint+path, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+s.token)
		if in != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := s.client.Do(req)
		if err != nil {
			last = fmt.Errorf("kms: %w", err)
			continue
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if err != nil {
			last = fmt.Errorf("kms: %w", err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			last = kmsAPIError(resp.StatusCode, data)
			if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
				continue
			}
			return last
		}
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("kms: response: %w", err)
		}
		return nil
	}
	return last
}

func kmsAPIError(status int, data []byte) error {
	var e struct {
		Error struct {
			Message string `json:"message"`
			Status  string `json:"status"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &e) == nil && e.Error.Message != "" {
		return fmt.Errorf("kms: HTTP %d %s: %s", status, e.Error.Status, e.Error.Message)
	}
	return fmt.Errorf("kms: HTTP %d", status)
}

// checkCRC32C compares data with a CRC32C value as the API encodes it (an
// int64 in a JSON string).
func checkCRC32C(data []byte, want string) error {
	v, err := strconv.ParseUint(want, 10, 32)
	if err != nil {
		return fmt.Errorf("bad checksum %q", want)
	}
	if uint32(v) != crc32.Checksum(data, crc32c) {
		return errors.New("checksum mismatch")
	}
	return nil
}
