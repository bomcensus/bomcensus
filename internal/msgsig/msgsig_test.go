// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package msgsig

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestParseSignatureInputStrict(t *testing.T) {
	good := `sig1=("@method" "@path" "@query" "content-digest" "bomcensus-agent-id" "bomcensus-nonce");created=1700000000;keyid="agent-1";alg="ed25519"`
	p, err := parseSignatureInput(good, requestCovered(false))
	if err != nil {
		t.Fatal(err)
	}
	if p.created != 1700000000 || p.keyID != "agent-1" || p.alg != AlgEd25519 {
		t.Fatalf("unexpected params %+v", p)
	}
	bad := []string{
		strings.Replace(good, "sig1=", "sig2=", 1),
		strings.Replace(good, `"@method" "@path"`, `"@path" "@method"`, 1),
		strings.Replace(good, `"bomcensus-nonce")`, `"bomcensus-nonce" "bomcensus-counter")`, 1),
		strings.Replace(good, `"@query" `, ``, 1),
		strings.Replace(good, `"@method" "@path"`, `"@method"  "@path"`, 1),
		strings.Replace(good, `;created=1700000000;keyid="agent-1"`, `;keyid="agent-1";created=1700000000`, 1),
		strings.Replace(good, `;alg="ed25519"`, ``, 1),
		strings.Replace(good, `;alg="ed25519"`, `;alg="ed25519";expires=1700000100`, 1),
		strings.Replace(good, `;alg="ed25519"`, `;alg="hmac-sha256"`, 1),
		strings.Replace(good, `created=1700000000`, `created=01700000000`, 1),
		strings.Replace(good, `created=1700000000`, `created=-1`, 1),
		strings.Replace(good, `keyid="agent-1"`, `keyid="agent 1"`, 1),
		strings.Replace(good, `keyid="agent-1"`, `keyid=agent-1`, 1),
		strings.Replace(good, `keyid="agent-1"`, `keyid="ag\"ent"`, 1),
		good + ", sig2=()",
		good + " ",
		" " + good,
		strings.ToUpper(good[:4]) + good[4:],
	}
	for _, v := range bad {
		if _, err := parseSignatureInput(v, requestCovered(false)); err == nil {
			t.Errorf("accepted %q", v)
		}
	}
	if _, err := parseSignatureInput(good, requestCovered(true)); err == nil {
		t.Error("accepted input without counter where counter is required")
	}
}

func TestParseSignatureStrict(t *testing.T) {
	sig := make([]byte, 64)
	good := formatSignature(sig)
	if _, err := parseSignature(good); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{
		strings.Replace(good, "sig1", "sig2", 1),
		strings.TrimSuffix(good, ":"),
		good + ", sig2=:AAAA:",
		"sig1=::",
		strings.Replace(good, "=:", "=:  ", 1),
		strings.Replace(good, "A", "-", 1),
		"sig1=:AA=:",
	} {
		if _, err := parseSignature(v); err == nil {
			t.Errorf("accepted %q", v)
		}
	}
}

func TestValidPath(t *testing.T) {
	for _, p := range []string{"/", "/agent/v1/poll", "/agent/v1/update/bundle/1.2.3+build", "/agent/v1/x/"} {
		if !validPath(p) {
			t.Errorf("rejected %q", p)
		}
	}
	for _, p := range []string{"", "agent", "/agent//v1", "/agent/./v1", "/agent/../v1", "/agent/v1/..", "/a%2Fb", "/a b", "/a?b", "/a\x00"} {
		if validPath(p) {
			t.Errorf("accepted %q", p)
		}
	}
}

func TestPaths(t *testing.T) {
	ps := Paths{"/agent/v1/enroll/start", "/agent/v1/update/bundle/"}
	for p, want := range map[string]bool{
		"/agent/v1/enroll/start":       true,
		"/agent/v1/enroll/start/x":     false,
		"/agent/v1/enroll/startx":      false,
		"/agent/v1/update/bundle/1.0":  true,
		"/agent/v1/update/bundle":      false,
		"/agent/v1/update/bundlex/1.0": false,
	} {
		if ps.Match(p) != want {
			t.Errorf("Match(%q) = %v", p, !want)
		}
	}
}

func TestNonceCache(t *testing.T) {
	c := newNonceCache(3, time.Minute)
	now := time.Unix(1000, 0)
	if !c.add("a", now) || c.add("a", now.Add(time.Second)) {
		t.Fatal("duplicate within ttl accepted")
	}
	if !c.add("a", now.Add(2*time.Minute)) {
		t.Fatal("expired entry not forgotten")
	}
	for _, k := range []string{"b", "c", "d"} {
		c.add(k, now.Add(2*time.Minute))
	}
	if c.ll.Len() > 3 || len(c.m) != c.ll.Len() {
		t.Fatalf("cache size %d/%d", c.ll.Len(), len(c.m))
	}
}

func TestAlgorithms(t *testing.T) {
	msg := []byte("signature base")
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, ek, _ := ed25519.GenerateKey(rand.Reader)
	for _, tc := range []struct {
		alg  string
		size int
		sign func() ([]byte, error)
		pub  any
	}{
		{AlgECDSAP256SHA256, 64, func() ([]byte, error) { return sign(p256, AlgECDSAP256SHA256, msg) }, &p256.PublicKey},
		{AlgECDSAP384SHA384, 96, func() ([]byte, error) { return sign(p384, AlgECDSAP384SHA384, msg) }, &p384.PublicKey},
		{AlgRSAPSSSHA512, 256, func() ([]byte, error) { return sign(rk, AlgRSAPSSSHA512, msg) }, &rk.PublicKey},
		{AlgEd25519, 64, func() ([]byte, error) { return sign(ek, AlgEd25519, msg) }, ek.Public()},
	} {
		got, err := algFor(tc.pub)
		if err != nil || got != tc.alg {
			t.Fatalf("algFor: %s %v", got, err)
		}
		sig, err := tc.sign()
		if err != nil {
			t.Fatal(err)
		}
		if len(sig) != tc.size {
			t.Errorf("%s: signature size %d, want %d", tc.alg, len(sig), tc.size)
		}
		if err := verify(tc.pub, tc.alg, msg, sig); err != nil {
			t.Errorf("%s: %v", tc.alg, err)
		}
		if err := verify(tc.pub, tc.alg, append(msg, '!'), sig); err == nil {
			t.Errorf("%s: tampered message verified", tc.alg)
		}
		for _, other := range []string{AlgEd25519, AlgECDSAP256SHA256, AlgECDSAP384SHA384, AlgRSAPSSSHA512} {
			if other != tc.alg && verify(tc.pub, other, msg, sig) == nil {
				t.Errorf("%s key verified under %s", tc.alg, other)
			}
		}
	}
}

// TestProtocolExample pins the worked example in docs/PROTOCOL.md.
func TestProtocolExample(t *testing.T) {
	agentSeed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	serverSeed, _ := hex.DecodeString("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
	agentKey := ed25519.NewKeyFromSeed(agentSeed)
	serverKey := ed25519.NewKeyFromSeed(serverSeed)
	spki, err := x509.MarshalPKIXPublicKey(serverKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	serverKeyID := KeyID(&x509.Certificate{RawSubjectPublicKeyInfo: spki})

	const (
		agentID = "a7Kq2mXr"
		nonce   = "AAECAwQFBgcICQoLDA0ODw"
		created = 1795305600
	)
	reqBody := []byte(`{"version":"1.4.0"}`)
	reqDigest := ContentDigest(reqBody)
	rp := params{covered: requestCovered(true), created: created, keyID: agentID, alg: AlgEd25519}
	reqBase, err := signatureBase(rp, []string{"POST", "/agent/v1/poll", "?", reqDigest, agentID, nonce, "42"})
	if err != nil {
		t.Fatal(err)
	}
	reqSig := formatSignature(ed25519.Sign(agentKey, reqBase))

	respBody := []byte(`{"directives":[]}`)
	respDigest := ContentDigest(respBody)
	sp := params{covered: responseCovered(false), created: created + 1, keyID: serverKeyID, alg: AlgEd25519}
	respBase, err := signatureBase(sp, []string{"200", respDigest, nonce})
	if err != nil {
		t.Fatal(err)
	}
	respSig, err := sign(serverKey, AlgEd25519, respBase)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"request digest":           reqDigest,
		"request signature-input":  Label + "=" + rp.serialize(),
		"request base":             string(reqBase),
		"request signature":        reqSig,
		"server keyid":             serverKeyID,
		"response digest":          respDigest,
		"response signature-input": Label + "=" + sp.serialize(),
		"response base":            string(respBase),
		"response signature":       formatSignature(respSig),
	}
	for k, v := range protocolExample {
		if want[k] != v {
			t.Errorf("%s:\n got %s\nwant %s", k, want[k], v)
		}
	}
	if len(protocolExample) != len(want) {
		for k, v := range want {
			t.Logf("%s:\n%s", k, v)
		}
		t.Fatal("example incomplete")
	}
}

var protocolExample = map[string]string{
	"request digest":          "sha-256=:hHLDpmZRqj18Pee9aZwud5GWiY+vo9LyA9at7ai1alw=:",
	"request signature-input": `sig1=("@method" "@path" "@query" "content-digest" "bomcensus-agent-id" "bomcensus-nonce" "bomcensus-counter");created=1795305600;keyid="a7Kq2mXr";alg="ed25519"`,
	"request base": `"@method": POST
"@path": /agent/v1/poll
"@query": ?
"content-digest": sha-256=:hHLDpmZRqj18Pee9aZwud5GWiY+vo9LyA9at7ai1alw=:
"bomcensus-agent-id": a7Kq2mXr
"bomcensus-nonce": AAECAwQFBgcICQoLDA0ODw
"bomcensus-counter": 42
"@signature-params": ("@method" "@path" "@query" "content-digest" "bomcensus-agent-id" "bomcensus-nonce" "bomcensus-counter");created=1795305600;keyid="a7Kq2mXr";alg="ed25519"`,
	"request signature":        "sig1=:owyZTbCYmk8RuvrCbcNGSZWZPdwg1/Vv5XOG4XlYMR9tFkzYRqRl6Yt1+EF1TYyZkQiOUeDhEXAIclMvcYsHDQ==:",
	"server keyid":             "3rLe053Cb84OYIW2_DS_a1lBkTu_4uphQRPP-eAEwXA",
	"response digest":          "sha-256=:awmRrw3eXfkm3+nMmhZVhqda2RjhepllY0H7Fm+a47o=:",
	"response signature-input": `sig1=("@status" "content-digest" "bomcensus-request-nonce");created=1795305601;keyid="3rLe053Cb84OYIW2_DS_a1lBkTu_4uphQRPP-eAEwXA";alg="ed25519"`,
	"response base": `"@status": 200
"content-digest": sha-256=:awmRrw3eXfkm3+nMmhZVhqda2RjhepllY0H7Fm+a47o=:
"bomcensus-request-nonce": AAECAwQFBgcICQoLDA0ODw
"@signature-params": ("@status" "content-digest" "bomcensus-request-nonce");created=1795305601;keyid="3rLe053Cb84OYIW2_DS_a1lBkTu_4uphQRPP-eAEwXA";alg="ed25519"`,
	"response signature": "sig1=:8L1ck4U7HSnimM9ez0ralZ6OEyNprl1gwPtD2k2bnxpYH7hcqYIt8252FOsABB9OPg+6HbvBomt/rSfwljt/DA==:",
}
