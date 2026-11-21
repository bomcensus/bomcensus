// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package enroll implements the three signatures of the enrollment exchange
// (SECURITY §4.3). Each signature covers SHA-256 hashes of exact HTTP body
// bytes behind a fixed domain separation label, so the package needs no
// knowledge of the JSON schemas:
//
//	server start:  "bomcensus enroll v1 server" ‖ H(start req) ‖ H(start resp)
//	agent:         "bomcensus enroll v1 agent"  ‖ H(start req) ‖ H(start resp)
//	server result: "bomcensus enroll v1 result" ‖ H(start req) ‖ H(start resp) ‖ H(finish resp)
//
// The two server signatures are sent as "<scheme>.<base64url>" in the
// Bomcensus-Enroll-Signature header. The agent signature is a raw Ed25519
// signature with the Register Key.
package enroll

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/bomcensus/bomcensus/internal/pki"
)

// HeaderSignature carries the server signatures on enroll/start and
// enroll/finish responses.
const HeaderSignature = "Bomcensus-Enroll-Signature"

// Domain separation labels.
const (
	labelServer = "bomcensus enroll v1 server"
	labelAgent  = "bomcensus enroll v1 agent"
	labelResult = "bomcensus enroll v1 result"
)

// Signature schemes of the server signatures. The scheme is fixed by the
// server key type.
const (
	SchemeEd25519      = "ed25519"        // pure Ed25519
	SchemeECDSASHA256  = "ecdsa-sha256"   // ECDSA over SHA-256, ASN.1 DER signature
	SchemeRSAPSSSHA256 = "rsa-pss-sha256" // RSASSA-PSS, SHA-256, MGF1-SHA-256, salt length 32
)

// ErrVerify is returned (wrapped) for every signature that does not verify.
var ErrVerify = errors.New("enroll: signature verification failed")

var b64 = base64.RawURLEncoding.Strict()

// TranscriptSize is the length of a binary transcript.
const TranscriptSize = 2 * sha256.Size

// Transcript holds the hashes of the enroll/start request and response
// bodies. The server stores it in the enrollment session between
// enroll/start and enroll/finish.
type Transcript struct {
	StartRequest  [sha256.Size]byte
	StartResponse [sha256.Size]byte
}

// NewTranscript hashes the exact bytes of the enroll/start request and
// response bodies.
func NewTranscript(startRequestBody, startResponseBody []byte) Transcript {
	return Transcript{
		StartRequest:  sha256.Sum256(startRequestBody),
		StartResponse: sha256.Sum256(startResponseBody),
	}
}

// MarshalBinary returns the two hashes concatenated (64 bytes).
func (t Transcript) MarshalBinary() ([]byte, error) {
	b := make([]byte, 0, TranscriptSize)
	b = append(b, t.StartRequest[:]...)
	return append(b, t.StartResponse[:]...), nil
}

// UnmarshalBinary is the inverse of MarshalBinary.
func (t *Transcript) UnmarshalBinary(b []byte) error {
	if len(b) != TranscriptSize {
		return fmt.Errorf("enroll: transcript length %d, want %d", len(b), TranscriptSize)
	}
	copy(t.StartRequest[:], b[:sha256.Size])
	copy(t.StartResponse[:], b[sha256.Size:])
	return nil
}

// MarshalText returns the binary form as unpadded base64url.
func (t Transcript) MarshalText() ([]byte, error) {
	b, _ := t.MarshalBinary()
	return []byte(b64.EncodeToString(b)), nil
}

// UnmarshalText is the inverse of MarshalText.
func (t *Transcript) UnmarshalText(s []byte) error {
	b, err := b64.DecodeString(string(s))
	if err != nil {
		return fmt.Errorf("enroll: transcript: %w", err)
	}
	return t.UnmarshalBinary(b)
}

func (t Transcript) message(label string, extra ...[sha256.Size]byte) []byte {
	m := make([]byte, 0, len(label)+TranscriptSize+len(extra)*sha256.Size)
	m = append(m, label...)
	m = append(m, t.StartRequest[:]...)
	m = append(m, t.StartResponse[:]...)
	for _, e := range extra {
		m = append(m, e[:]...)
	}
	return m
}

// SignServerStart signs the enroll/start exchange with the server key and
// returns the Bomcensus-Enroll-Signature header value.
func SignServerStart(key crypto.Signer, t Transcript) (string, error) {
	return signServer(key, t.message(labelServer))
}

// VerifyServerStart is the agent-side check of the enroll/start response.
// It verifies chain (leaf first, as carried in the start response) against
// the pinned ca-hash and serverName with pki.VerifyPinned, then checks sig
// with the leaf public key. It returns the verified leaf, which must be
// passed to VerifyResult.
func VerifyServerStart(chain []*x509.Certificate, pin [32]byte, serverName string, t Transcript, sig string) (*x509.Certificate, error) {
	if err := pki.VerifyPinned(chain, pin, serverName, x509.ExtKeyUsageServerAuth); err != nil {
		return nil, fmt.Errorf("enroll: server chain: %w", err)
	}
	leaf := chain[0]
	if err := verifyServer(leaf.PublicKey, t.message(labelServer), sig); err != nil {
		return nil, err
	}
	return leaf, nil
}

// SignAgent signs the enroll/start exchange with the Register Key
// (token.Token.PrivateKey). The result goes into the enroll/finish body.
func SignAgent(registerKey ed25519.PrivateKey, t Transcript) ([]byte, error) {
	if len(registerKey) != ed25519.PrivateKeySize {
		return nil, errors.New("enroll: invalid Register Key")
	}
	return ed25519.Sign(registerKey, t.message(labelAgent)), nil
}

// VerifyAgent checks the Register Key signature from the enroll/finish body
// against the stored public key of the Register Key.
func VerifyAgent(registerKey ed25519.PublicKey, t Transcript, sig []byte) error {
	if len(registerKey) != ed25519.PublicKeySize {
		return errors.New("enroll: invalid Register Key public key")
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(registerKey, t.message(labelAgent), sig) {
		return fmt.Errorf("%w: agent signature", ErrVerify)
	}
	return nil
}

// SignResult signs the complete exchange including the exact enroll/finish
// response body and returns the Bomcensus-Enroll-Signature header value.
func SignResult(key crypto.Signer, t Transcript, finishResponseBody []byte) (string, error) {
	return signServer(key, t.message(labelResult, sha256.Sum256(finishResponseBody)))
}

// VerifyResult checks the server signature on the enroll/finish response
// with the leaf returned by VerifyServerStart.
func VerifyResult(leaf *x509.Certificate, t Transcript, finishResponseBody []byte, sig string) error {
	if leaf == nil {
		return errors.New("enroll: server certificate is required")
	}
	return verifyServer(leaf.PublicKey, t.message(labelResult, sha256.Sum256(finishResponseBody)), sig)
}

// schemeFor returns the scheme fixed by the public key type.
func schemeFor(pub crypto.PublicKey) (string, error) {
	switch pub.(type) {
	case ed25519.PublicKey:
		return SchemeEd25519, nil
	case *ecdsa.PublicKey:
		return SchemeECDSASHA256, nil
	case *rsa.PublicKey:
		return SchemeRSAPSSSHA256, nil
	default:
		return "", fmt.Errorf("enroll: unsupported server key type %T", pub)
	}
}

var pssOptions = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}

func signServer(key crypto.Signer, msg []byte) (string, error) {
	if key == nil {
		return "", errors.New("enroll: server key is required")
	}
	scheme, err := schemeFor(key.Public())
	if err != nil {
		return "", err
	}
	var sig []byte
	switch scheme {
	case SchemeEd25519:
		sig, err = key.Sign(rand.Reader, msg, crypto.Hash(0))
	case SchemeECDSASHA256:
		h := sha256.Sum256(msg)
		sig, err = key.Sign(rand.Reader, h[:], crypto.SHA256)
	case SchemeRSAPSSSHA256:
		h := sha256.Sum256(msg)
		sig, err = key.Sign(rand.Reader, h[:], pssOptions)
	}
	if err != nil {
		return "", fmt.Errorf("enroll: sign: %w", err)
	}
	return scheme + "." + b64.EncodeToString(sig), nil
}

func verifyServer(pub crypto.PublicKey, msg []byte, value string) error {
	want, err := schemeFor(pub)
	if err != nil {
		return err
	}
	scheme, enc, ok := strings.Cut(value, ".")
	if !ok || scheme != want {
		return fmt.Errorf("%w: scheme %q does not match server key (%s)", ErrVerify, scheme, want)
	}
	sig, err := b64.DecodeString(enc)
	if err != nil || len(sig) == 0 {
		return fmt.Errorf("%w: malformed signature", ErrVerify)
	}
	var good bool
	switch k := pub.(type) {
	case ed25519.PublicKey:
		good = len(sig) == ed25519.SignatureSize && ed25519.Verify(k, msg, sig)
	case *ecdsa.PublicKey:
		h := sha256.Sum256(msg)
		good = ecdsa.VerifyASN1(k, h[:], sig)
	case *rsa.PublicKey:
		h := sha256.Sum256(msg)
		good = rsa.VerifyPSS(k, crypto.SHA256, h[:], sig, pssOptions) == nil
	}
	if !good {
		return fmt.Errorf("%w: server signature", ErrVerify)
	}
	return nil
}
