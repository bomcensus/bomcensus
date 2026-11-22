// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/release"
	"github.com/bomcensus/bomcensus/internal/sign/signtest"
)

const testKMSName = "projects/p/locations/global/keyRings/r/cryptoKeys/manifest/cryptoKeyVersions/1"

type fakeKMS struct {
	key        ed25519.PrivateKey
	algorithm  string
	corruptSig bool
	failFirst  atomic.Int32 // answer this many requests with 503 first
	signs      atomic.Int32
}

func crc(b []byte) string {
	return strconv.FormatUint(uint64(crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli))), 10)
}

func (f *fakeKMS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer test-token" {
		http.Error(w, `{"error":{"message":"bad token","status":"UNAUTHENTICATED"}}`, http.StatusUnauthorized)
		return
	}
	if f.failFirst.Add(-1) >= 0 {
		http.Error(w, `{"error":{"message":"try again","status":"UNAVAILABLE"}}`, http.StatusServiceUnavailable)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	switch {
	case r.Method == http.MethodGet && path == testKMSName+"/publicKey":
		der, _ := x509.MarshalPKIXPublicKey(f.key.Public())
		p := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
		json.NewEncoder(w).Encode(map[string]string{"pem": p, "algorithm": f.algorithm, "pemCrc32c": crc([]byte(p)), "name": testKMSName})
	case r.Method == http.MethodPost && path == testKMSName+":asymmetricSign":
		var req struct {
			Data       string `json:"data"`
			DataCrc32c string `json:"dataCrc32c"`
			Digest     any    `json:"digest"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Digest != nil {
			http.Error(w, `{"error":{"message":"bad request","status":"INVALID_ARGUMENT"}}`, http.StatusBadRequest)
			return
		}
		data, _ := base64.StdEncoding.DecodeString(req.Data)
		if crc(data) != req.DataCrc32c {
			http.Error(w, `{"error":{"message":"checksum","status":"INVALID_ARGUMENT"}}`, http.StatusBadRequest)
			return
		}
		f.signs.Add(1)
		sig := ed25519.Sign(f.key, data)
		sigCRC := crc(sig)
		if f.corruptSig {
			sig[0] ^= 1
		}
		json.NewEncoder(w).Encode(map[string]any{
			"signature": base64.StdEncoding.EncodeToString(sig), "signatureCrc32c": sigCRC,
			"verifiedDataCrc32c": true, "name": testKMSName,
		})
	default:
		http.NotFound(w, r)
	}
}

func startKMS(t *testing.T) *fakeKMS {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeKMS{key: key, algorithm: kmsEd25519}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	old := kmsEndpoint
	kmsEndpoint = srv.URL + "/v1/"
	t.Cleanup(func() { kmsEndpoint = old })
	t.Setenv(kmsTokenEnv, "test-token")
	return f
}

func TestKMSSigner(t *testing.T) {
	ctx := context.Background()
	f := startKMS(t)
	f.failFirst.Store(1)

	s, err := openManifestSigner(ctx, kmsScheme+testKMSName)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Public().(ed25519.PublicKey).Equal(f.key.Public()) {
		t.Fatal("public key differs")
	}
	msg := []byte("manifest")
	sig, err := s.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(f.key.Public().(ed25519.PublicKey), msg, sig) {
		t.Fatal("signature does not verify")
	}
	if _, err := s.Sign(nil, msg, crypto.SHA256); err == nil {
		t.Fatal("signed with a digest option")
	}

	f.corruptSig = true
	if _, err := s.Sign(nil, msg, crypto.Hash(0)); err == nil {
		t.Fatal("accepted a corrupt signature")
	}
}

func TestKMSSignerRejects(t *testing.T) {
	ctx := context.Background()
	f := startKMS(t)
	for _, ref := range []string{
		kmsScheme + "projects/p/locations/global/keyRings/r/cryptoKeys/manifest", // no version
		kmsScheme + "keyRings/r",
	} {
		if _, err := openManifestSigner(ctx, ref); err == nil {
			t.Errorf("%s: accepted", ref)
		}
	}
	f.algorithm = "EC_SIGN_P256_SHA256"
	if _, err := openManifestSigner(ctx, kmsScheme+testKMSName); err == nil || !strings.Contains(err.Error(), kmsEd25519) {
		t.Errorf("other algorithm: %v", err)
	}
	f.algorithm = kmsEd25519
	t.Setenv(kmsTokenEnv, "wrong")
	if _, err := openManifestSigner(ctx, kmsScheme+testKMSName); err == nil || !strings.Contains(err.Error(), "UNAUTHENTICATED") {
		t.Errorf("wrong token: %v", err)
	}
	t.Setenv(kmsTokenEnv, "")
	if _, err := openManifestSigner(ctx, kmsScheme+testKMSName); err == nil || !strings.Contains(err.Error(), kmsTokenEnv) {
		t.Errorf("no token: %v", err)
	}
}

// A bundle signed through KMS verifies with the trust printed for the KMS
// public key.
func TestBundleWithKMS(t *testing.T) {
	ctx := context.Background()
	f := startKMS(t)
	tmp := t.TempDir()
	keys := filepath.Join(tmp, "keys")
	bin := filepath.Join(tmp, "bin", "linux-amd64")
	mustRun := func(args ...string) string {
		t.Helper()
		var out bytes.Buffer
		if err := run(ctx, args, &out, io.Discard); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		return out.String()
	}
	mustRun("keygen", "--out", keys)
	pub := mustRun("manifest-pub", "--manifest-key", kmsScheme+testKMSName)
	if err := os.WriteFile(filepath.Join(keys, fileManifestPub), []byte(pub), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	agent := filepath.Join(bin, "bomcensus-agent")
	if err := os.WriteFile(agent, signtest.ELF(t, "amd64"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustRun("sign-elf", "--key", filepath.Join(keys, fileCodeKey), "--cert", filepath.Join(keys, fileCodeCert), agent)
	bundle := filepath.Join(tmp, "bomcensus-1.0.0.tar")
	mustRun("bundle", "--version", "1.0.0", "--manifest-key", kmsScheme+testKMSName, "--dir", filepath.Dir(bin), "--out", bundle)
	if f.signs.Load() != 1 {
		t.Fatalf("%d sign calls", f.signs.Load())
	}

	flags := strings.Fields(mustRun("print-ldflags", "--keys", keys))
	signtest.SetTrust(t, strings.SplitN(flags[1], "=", 2)[1], strings.SplitN(flags[3], "=", 2)[1])
	data, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := release.Open(ctx, bytes.NewReader(data), time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestKMSSignerStopsWithContext(t *testing.T) {
	f := startKMS(t)
	ctx, cancel := context.WithCancel(context.Background())
	s, err := openManifestSigner(ctx, kmsScheme+testKMSName)
	if err != nil {
		t.Fatal(err)
	}
	f.failFirst.Store(100) // keep answering 503, so Sign would retry
	cancel()
	start := time.Now()
	if _, err := s.Sign(nil, []byte("m"), crypto.Hash(0)); err == nil {
		t.Fatal("signed after cancel")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Sign kept retrying for %v after cancel", d)
	}
}
