// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package enroll

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/bomcensus/bomcensus/internal/pki"
	"github.com/bomcensus/bomcensus/internal/token"
)

const serverName = "agents.example.test"

type serverSide struct {
	key   crypto.Signer
	chain []*x509.Certificate
	pin   [32]byte
}

func newServer(t *testing.T, kind string) serverSide {
	t.Helper()
	ca, err := pki.NewCA(pki.CAOptions{Subject: pkix.Name{CommonName: "Test Agent TLS CA"}})
	if err != nil {
		t.Fatal(err)
	}
	var key crypto.Signer
	switch kind {
	case "ecdsa":
		key, err = pki.GenerateKey()
	case "rsa":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case "ed25519":
		_, key, err = ed25519.GenerateKey(rand.Reader)
	default:
		t.Fatalf("unknown key kind %s", kind)
	}
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.IssueServer(key.Public(), pki.LeafOptions{DNSNames: []string{serverName}})
	if err != nil {
		t.Fatal(err)
	}
	return serverSide{key: key, chain: []*x509.Certificate{leaf, ca.Cert}, pin: pki.SPKIHash(ca.Cert)}
}

func newToken(t *testing.T, pin [32]byte) token.Token {
	t.Helper()
	tok, err := token.New(pin)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

var (
	startReq  = []byte(`{"key_id":"LqVSSwJDhTo","agent_nonce":"AAAA","csr":"MIIB"}`)
	startResp = []byte(`{"session_id":"s1","server_nonce":"BBBB","server_chain":[]}`)
	finishRes = []byte(`{"status":"approved","agent_id":"a1"}`)
)

func TestHappyPath(t *testing.T) {
	for _, kind := range []string{"ecdsa", "rsa", "ed25519"} {
		t.Run(kind, func(t *testing.T) {
			srv := newServer(t, kind)
			tok := newToken(t, srv.pin)

			// Server: enroll/start.
			st := NewTranscript(startReq, startResp)
			startSig, err := SignServerStart(srv.key, st)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(startSig, map[string]string{"ecdsa": SchemeECDSASHA256, "rsa": SchemeRSAPSSSHA256, "ed25519": SchemeEd25519}[kind]+".") {
				t.Fatalf("unexpected scheme in %q", startSig)
			}

			// Agent: verify start, sign finish.
			at := NewTranscript(startReq, startResp)
			leaf, err := VerifyServerStart(srv.chain, tok.CAHash, serverName, at, startSig)
			if err != nil {
				t.Fatal(err)
			}
			agentSig, err := SignAgent(tok.PrivateKey(), at)
			if err != nil {
				t.Fatal(err)
			}

			// Server: verify finish with the stored transcript, sign result.
			stored, _ := st.MarshalText()
			var loaded Transcript
			if err := loaded.UnmarshalText(stored); err != nil {
				t.Fatal(err)
			}
			if err := VerifyAgent(tok.PublicKey(), loaded, agentSig); err != nil {
				t.Fatal(err)
			}
			resSig, err := SignResult(srv.key, loaded, finishRes)
			if err != nil {
				t.Fatal(err)
			}

			// Agent: verify result.
			if err := VerifyResult(leaf, at, finishRes, resSig); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTamper(t *testing.T) {
	for _, kind := range []string{"ecdsa", "rsa", "ed25519"} {
		t.Run(kind, func(t *testing.T) {
			srv := newServer(t, kind)
			tok := newToken(t, srv.pin)
			st := NewTranscript(startReq, startResp)
			startSig, err := SignServerStart(srv.key, st)
			if err != nil {
				t.Fatal(err)
			}
			agentSig, err := SignAgent(tok.PrivateKey(), st)
			if err != nil {
				t.Fatal(err)
			}
			resSig, err := SignResult(srv.key, st, finishRes)
			if err != nil {
				t.Fatal(err)
			}
			leaf := srv.chain[0]

			mustFail := func(t *testing.T, err error) {
				t.Helper()
				if err == nil {
					t.Fatal("verification succeeded")
				}
			}

			t.Run("changed start request body", func(t *testing.T) {
				bad := NewTranscript(append([]byte(nil), append(startReq, ' ')...), startResp)
				_, err := VerifyServerStart(srv.chain, srv.pin, serverName, bad, startSig)
				mustFail(t, err)
				mustFail(t, VerifyAgent(tok.PublicKey(), bad, agentSig))
				mustFail(t, VerifyResult(leaf, bad, finishRes, resSig))
			})
			t.Run("changed start response body", func(t *testing.T) {
				bad := NewTranscript(startReq, []byte(strings.Replace(string(startResp), "BBBB", "BBBC", 1)))
				_, err := VerifyServerStart(srv.chain, srv.pin, serverName, bad, startSig)
				mustFail(t, err)
				mustFail(t, VerifyAgent(tok.PublicKey(), bad, agentSig))
			})
			t.Run("changed finish response body", func(t *testing.T) {
				mustFail(t, VerifyResult(leaf, st, []byte(`{"status":"approved","agent_id":"a2"}`), resSig))
			})
			t.Run("wrong register key", func(t *testing.T) {
				other := newToken(t, srv.pin)
				mustFail(t, VerifyAgent(other.PublicKey(), st, agentSig))
				otherSig, _ := SignAgent(other.PrivateKey(), st)
				mustFail(t, VerifyAgent(tok.PublicKey(), st, otherSig))
			})
			t.Run("wrong server key", func(t *testing.T) {
				other := newServer(t, kind)
				// Same chain, signature by another key of the same type.
				sig, err := SignServerStart(other.key, st)
				if err != nil {
					t.Fatal(err)
				}
				_, err = VerifyServerStart(srv.chain, srv.pin, serverName, st, sig)
				mustFail(t, err)
				sig, _ = SignResult(other.key, st, finishRes)
				mustFail(t, VerifyResult(leaf, st, finishRes, sig))
				// Chain of another server against our pin.
				sig, _ = SignServerStart(other.key, st)
				_, err = VerifyServerStart(other.chain, srv.pin, serverName, st, sig)
				if !errors.Is(err, pki.ErrPinNotFound) {
					t.Fatalf("got %v, want ErrPinNotFound", err)
				}
			})
			t.Run("wrong server name", func(t *testing.T) {
				_, err := VerifyServerStart(srv.chain, srv.pin, "other.example.test", st, startSig)
				mustFail(t, err)
			})
			t.Run("swapped signatures", func(t *testing.T) {
				_, err := VerifyServerStart(srv.chain, srv.pin, serverName, st, resSig)
				mustFail(t, err)
				mustFail(t, VerifyResult(leaf, st, finishRes, startSig))
				rawStart, _ := base64.RawURLEncoding.DecodeString(startSig[strings.IndexByte(startSig, '.')+1:])
				mustFail(t, VerifyAgent(tok.PublicKey(), st, rawStart))
			})
			t.Run("scheme mismatch", func(t *testing.T) {
				_, enc, _ := strings.Cut(startSig, ".")
				for _, s := range []string{SchemeEd25519, SchemeECDSASHA256, SchemeRSAPSSSHA256, ""} {
					if strings.HasPrefix(startSig, s+".") {
						continue
					}
					_, err := VerifyServerStart(srv.chain, srv.pin, serverName, st, s+"."+enc)
					mustFail(t, err)
				}
				_, err := VerifyServerStart(srv.chain, srv.pin, serverName, st, enc)
				mustFail(t, err)
			})
		})
	}
}

// The Register Key used as an Ed25519 server key must not turn an agent
// signature into a valid server signature: labels separate the domains.
func TestDomainSeparation(t *testing.T) {
	tok := newToken(t, [32]byte{})
	st := NewTranscript(startReq, startResp)
	agentSig, _ := SignAgent(tok.PrivateKey(), st)
	asServer := SchemeEd25519 + "." + base64.RawURLEncoding.EncodeToString(agentSig)
	pub := tok.PublicKey()
	if err := verifyServer(pub, st.message(labelServer), asServer); err == nil {
		t.Fatal("agent signature accepted as server start signature")
	}
	if err := verifyServer(pub, st.message(labelResult, [32]byte{}), asServer); err == nil {
		t.Fatal("agent signature accepted as result signature")
	}
	srvSig, _ := signServer(tok.PrivateKey(), st.message(labelServer))
	raw, _ := base64.RawURLEncoding.DecodeString(srvSig[len(SchemeEd25519)+1:])
	if err := VerifyAgent(pub, st, raw); err == nil {
		t.Fatal("server signature accepted as agent signature")
	}
}

func TestTranscriptEncoding(t *testing.T) {
	st := NewTranscript(startReq, startResp)
	b, _ := st.MarshalBinary()
	if len(b) != TranscriptSize {
		t.Fatalf("len %d", len(b))
	}
	var got Transcript
	if err := got.UnmarshalBinary(b); err != nil || got != st {
		t.Fatalf("binary round trip: %v", err)
	}
	j, err := json.Marshal(struct{ T Transcript }{st})
	if err != nil {
		t.Fatal(err)
	}
	var back struct{ T Transcript }
	if err := json.Unmarshal(j, &back); err != nil || back.T != st {
		t.Fatalf("json round trip: %v", err)
	}
	if err := got.UnmarshalBinary(b[:63]); err == nil {
		t.Fatal("short transcript accepted")
	}
	if err := got.UnmarshalText([]byte("!!")); err == nil {
		t.Fatal("bad text accepted")
	}
}
