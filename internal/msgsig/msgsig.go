// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package msgsig implements the subset of HTTP Message Signatures
// (RFC 9421) and Content-Digest (RFC 9530) used on the agent protocol after
// enrollment. Requests are signed by the agent identity key (Ed25519);
// responses are signed by the server key and bound to the request nonce.
//
// Parsing is strict: one signature with the label "sig1", a fixed list of
// covered components in a fixed order and the parameters created, keyid and
// alg in that order. Anything else is rejected. The wire format is
// specified in docs/PROTOCOL.md.
package msgsig

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/bomcensus/bomcensus/internal/pki"
)

// Header names.
const (
	HeaderSignature      = "Signature"
	HeaderSignatureInput = "Signature-Input"
	HeaderContentDigest  = "Content-Digest"
	HeaderAgentID        = "Bomcensus-Agent-Id"
	HeaderNonce          = "Bomcensus-Nonce"
	HeaderCounter        = "Bomcensus-Counter"
	HeaderRequestNonce   = "Bomcensus-Request-Nonce"
)

// Label is the only accepted signature label.
const Label = "sig1"

// NonceSize is the number of random bytes in Bomcensus-Nonce.
const NonceSize = 16

// Signature algorithms (RFC 9421 §6.2.2 registry names).
const (
	AlgEd25519         = "ed25519"
	AlgECDSAP256SHA256 = "ecdsa-p256-sha256"
	AlgECDSAP384SHA384 = "ecdsa-p384-sha384"
	AlgRSAPSSSHA512    = "rsa-pss-sha512"
)

// Default limits.
const (
	DefaultMaxRequestBody  = 256 << 20
	DefaultMaxResponseBody = 64 << 20
)

// ErrResponseVerification is returned (wrapped) by Transport when a
// response is not correctly signed.
var ErrResponseVerification = errors.New("msgsig: response verification failed")

var (
	b64url = base64.RawURLEncoding.Strict()
	b64std = base64.StdEncoding.Strict()
)

// Covered components.
var (
	requestComponents         = []string{"@method", "@path", "@query", "content-digest", "bomcensus-agent-id", "bomcensus-nonce"}
	requestComponentsCounter  = append(append([]string(nil), requestComponents...), "bomcensus-counter")
	responseComponents        = []string{"@status", "content-digest", "bomcensus-request-nonce"}
	responseComponentsCounter = append(append([]string(nil), responseComponents...), "bomcensus-counter")
)

func requestCovered(counter bool) []string {
	if counter {
		return requestComponentsCounter
	}
	return requestComponents
}

func responseCovered(counter bool) []string {
	if counter {
		return responseComponentsCounter
	}
	return responseComponents
}

// Paths is a set of request paths. An entry ending in "/" matches every
// path that starts with it; any other entry matches only itself.
type Paths []string

// Match reports whether p is in the set.
func (ps Paths) Match(p string) bool {
	for _, e := range ps {
		if strings.HasSuffix(e, "/") {
			if strings.HasPrefix(p, e) {
				return true
			}
		} else if p == e {
			return true
		}
	}
	return false
}

// KeyID returns the keyid of a server signing certificate: the unpadded
// base64url SHA-256 of its SubjectPublicKeyInfo.
func KeyID(cert *x509.Certificate) string {
	h := pki.SPKIHash(cert)
	return b64url.EncodeToString(h[:])
}

// ContentDigest returns the Content-Digest field value for body.
func ContentDigest(body []byte) string {
	h := sha256.Sum256(body)
	return "sha-256=:" + b64std.EncodeToString(h[:]) + ":"
}

// NewNonce returns a fresh Bomcensus-Nonce value.
func NewNonce() (string, error) {
	var b [NonceSize]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("msgsig: nonce: %w", err)
	}
	return b64url.EncodeToString(b[:]), nil
}

func validNonce(s string) bool {
	if len(s) != b64url.EncodedLen(NonceSize) || !isBase64URL(s) {
		return false
	}
	b, err := b64url.DecodeString(s)
	return err == nil && len(b) == NonceSize
}

func isBase64URL(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// parseCounter accepts a decimal integer in 1..2^63-1 without sign or
// leading zeros.
func parseCounter(s string) (uint64, error) {
	if s == "" || len(s) > 19 || s[0] == '0' {
		return 0, errors.New("malformed counter")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errors.New("malformed counter")
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 1 {
		return 0, errors.New("malformed counter")
	}
	return uint64(n), nil
}

func formatCounter(n uint64) string { return strconv.FormatUint(n, 10) }

// validKeyID restricts keyid to the agent id alphabet, which also covers
// unpadded base64url, so the value never needs escaping.
func validKeyID(s string) bool { return pki.ValidateAgentID(s) == nil }

// singleHeader returns the value of a header that must appear exactly once.
func singleHeader(h http.Header, name string) (string, error) {
	v := h.Values(name)
	if len(v) != 1 {
		return "", fmt.Errorf("header %s must appear exactly once", name)
	}
	return v[0], nil
}

// optionalHeader returns the value of a header that may appear at most once.
func optionalHeader(h http.Header, name string) (string, bool, error) {
	v := h.Values(name)
	switch len(v) {
	case 0:
		return "", false, nil
	case 1:
		return v[0], true, nil
	default:
		return "", false, fmt.Errorf("header %s must appear at most once", name)
	}
}

// splitTarget splits an origin-form request target at the first "?".
func splitTarget(target string) (path, query string) {
	path, query, _ = strings.Cut(target, "?")
	return path, query
}

// serverTarget returns the request target as received on the wire, so
// that path rewriting by inner handlers cannot change what is verified.
func serverTarget(r *http.Request) (string, string, error) {
	t := r.RequestURI
	switch {
	case t == "":
		t = r.URL.RequestURI()
	case !strings.HasPrefix(t, "/"):
		u, err := url.ParseRequestURI(t)
		if err != nil {
			return "", "", err
		}
		t = u.RequestURI()
	}
	p, q := splitTarget(t)
	return p, q, nil
}

// validPath accepts an absolute path made of unreserved characters,
// sub-delimiters, ":", "@" and "/", without percent-encoding and without
// empty, "." or ".." segments. The raw and decoded forms are then equal, so
// path policies and routing see the same value as the signature.
func validPath(p string) bool {
	if p == "" || p[0] != '/' {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			continue
		}
		if !strings.ContainsRune("-._~!$&'()*+,;=:@/", rune(c)) {
			return false
		}
	}
	segs := strings.Split(p[1:], "/")
	for i, s := range segs {
		if s == "." || s == ".." || (s == "" && i != len(segs)-1) {
			return false
		}
	}
	return true
}

// validValue accepts printable ASCII without control characters, which
// keeps every line of the signature base unambiguous.
func validValue(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// params are the signature parameters of one signature.
type params struct {
	covered []string
	created int64
	keyID   string
	alg     string
}

// serialize returns the inner list with parameters, as used both in
// Signature-Input and in the "@signature-params" line.
func (p params) serialize() string {
	var b strings.Builder
	b.WriteString(innerList(p.covered))
	b.WriteString(";created=")
	b.WriteString(strconv.FormatInt(p.created, 10))
	b.WriteString(`;keyid="`)
	b.WriteString(p.keyID)
	b.WriteString(`";alg="`)
	b.WriteString(p.alg)
	b.WriteByte('"')
	return b.String()
}

// innerList serializes the covered component identifiers.
func innerList(covered []string) string {
	var b strings.Builder
	b.WriteByte('(')
	for i, c := range covered {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteByte('"')
		b.WriteString(c)
		b.WriteByte('"')
	}
	b.WriteByte(')')
	return b.String()
}

// signatureBase builds the RFC 9421 signature base for the covered values,
// given in the order of p.covered.
func signatureBase(p params, values []string) ([]byte, error) {
	if len(values) != len(p.covered) {
		return nil, errors.New("msgsig: component count mismatch")
	}
	var b bytes.Buffer
	for i, c := range p.covered {
		if !validValue(values[i]) {
			return nil, fmt.Errorf("msgsig: invalid value for %s", c)
		}
		b.WriteByte('"')
		b.WriteString(c)
		b.WriteString(`": `)
		b.WriteString(values[i])
		b.WriteByte('\n')
	}
	b.WriteString(`"@signature-params": `)
	b.WriteString(p.serialize())
	return b.Bytes(), nil
}

// parseSignatureInput parses a Signature-Input value that must cover
// exactly the given components. It returns the parameters.
func parseSignatureInput(v string, covered []string) (params, error) {
	p := params{covered: covered}
	rest, ok := strings.CutPrefix(v, Label+"="+innerList(covered))
	if !ok {
		return params{}, errors.New("unexpected label or covered components")
	}
	rest, ok = strings.CutPrefix(rest, ";created=")
	if !ok {
		return params{}, errors.New("missing created")
	}
	i := 0
	for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
		i++
	}
	if i == 0 || i > 15 || (rest[0] == '0' && i > 1) {
		return params{}, errors.New("malformed created")
	}
	created, err := strconv.ParseInt(rest[:i], 10, 64)
	if err != nil {
		return params{}, errors.New("malformed created")
	}
	p.created = created
	rest, ok = strings.CutPrefix(rest[i:], `;keyid="`)
	if !ok {
		return params{}, errors.New("missing keyid")
	}
	keyID, rest, ok := strings.Cut(rest, `"`)
	if !ok || !validKeyID(keyID) {
		return params{}, errors.New("malformed keyid")
	}
	p.keyID = keyID
	rest, ok = strings.CutPrefix(rest, `;alg="`)
	if !ok {
		return params{}, errors.New("missing alg")
	}
	alg, ok := strings.CutSuffix(rest, `"`)
	if !ok {
		return params{}, errors.New("malformed alg")
	}
	switch alg {
	case AlgEd25519, AlgECDSAP256SHA256, AlgECDSAP384SHA384, AlgRSAPSSSHA512:
	default:
		return params{}, errors.New("unsupported alg")
	}
	p.alg = alg
	if Label+"="+p.serialize() != v {
		return params{}, errors.New("non-canonical signature input")
	}
	return p, nil
}

// parseSignature parses `sig1=:<base64>:`.
func parseSignature(v string) ([]byte, error) {
	enc, ok := strings.CutPrefix(v, Label+"=:")
	if !ok {
		return nil, errors.New("unexpected signature label")
	}
	enc, ok = strings.CutSuffix(enc, ":")
	if !ok {
		return nil, errors.New("malformed signature")
	}
	sig, err := b64std.DecodeString(enc)
	if err != nil || len(sig) == 0 || b64std.EncodeToString(sig) != enc {
		return nil, errors.New("malformed signature")
	}
	return sig, nil
}

func formatSignature(sig []byte) string {
	return Label + "=:" + b64std.EncodeToString(sig) + ":"
}

// algFor returns the algorithm fixed by the public key type.
func algFor(pub crypto.PublicKey) (string, error) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return AlgEd25519, nil
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return AlgECDSAP256SHA256, nil
		case elliptic.P384():
			return AlgECDSAP384SHA384, nil
		}
		return "", errors.New("msgsig: unsupported ECDSA curve")
	case *rsa.PublicKey:
		return AlgRSAPSSSHA512, nil
	default:
		return "", fmt.Errorf("msgsig: unsupported key type %T", pub)
	}
}

var pssOptions = &rsa.PSSOptions{SaltLength: 64, Hash: crypto.SHA512}

func digestFor(alg string, msg []byte) []byte {
	switch alg {
	case AlgECDSAP256SHA256:
		h := sha256.Sum256(msg)
		return h[:]
	case AlgECDSAP384SHA384:
		h := sha512.Sum384(msg)
		return h[:]
	case AlgRSAPSSSHA512:
		h := sha512.Sum512(msg)
		return h[:]
	}
	return nil
}

// sign signs msg with key under alg, producing the RFC 9421 encoding
// (raw r‖s for ECDSA).
func sign(key crypto.Signer, alg string, msg []byte) ([]byte, error) {
	switch alg {
	case AlgEd25519:
		return key.Sign(rand.Reader, msg, crypto.Hash(0))
	case AlgECDSAP256SHA256, AlgECDSAP384SHA384:
		h, size := crypto.SHA256, 32
		if alg == AlgECDSAP384SHA384 {
			h, size = crypto.SHA384, 48
		}
		der, err := key.Sign(rand.Reader, digestFor(alg, msg), h)
		if err != nil {
			return nil, err
		}
		var rs struct{ R, S *big.Int }
		rest, err := asn1.Unmarshal(der, &rs)
		if err != nil || len(rest) != 0 || rs.R.Sign() <= 0 || rs.S.Sign() <= 0 ||
			rs.R.BitLen() > size*8 || rs.S.BitLen() > size*8 {
			return nil, errors.New("msgsig: malformed ECDSA signature from signer")
		}
		out := make([]byte, 2*size)
		rs.R.FillBytes(out[:size])
		rs.S.FillBytes(out[size:])
		return out, nil
	case AlgRSAPSSSHA512:
		return key.Sign(rand.Reader, digestFor(alg, msg), pssOptions)
	}
	return nil, fmt.Errorf("msgsig: unsupported alg %q", alg)
}

// verify checks sig over msg. alg must be the one fixed by the key type.
func verify(pub crypto.PublicKey, alg string, msg, sig []byte) error {
	want, err := algFor(pub)
	if err != nil {
		return err
	}
	if alg != want {
		return fmt.Errorf("alg %q does not match key (%s)", alg, want)
	}
	ok := false
	switch k := pub.(type) {
	case ed25519.PublicKey:
		ok = len(sig) == ed25519.SignatureSize && ed25519.Verify(k, msg, sig)
	case *ecdsa.PublicKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) == 2*size {
			r := new(big.Int).SetBytes(sig[:size])
			s := new(big.Int).SetBytes(sig[size:])
			ok = ecdsa.Verify(k, digestFor(alg, msg), r, s)
		}
	case *rsa.PublicKey:
		ok = rsa.VerifyPSS(k, crypto.SHA512, digestFor(alg, msg), sig, pssOptions) == nil
	}
	if !ok {
		return errors.New("bad signature")
	}
	return nil
}

// ServerSigner is the key the server signs responses with: the key of a
// certificate that chains to the Agent TLS trust anchor.
type ServerSigner struct {
	keyID string
	key   crypto.Signer
	alg   string
}

// NewServerSigner checks that key belongs to cert and that its type is
// supported (Ed25519, ECDSA P-256/P-384, RSA).
func NewServerSigner(cert *x509.Certificate, key crypto.Signer) (*ServerSigner, error) {
	if !pki.KeyMatches(cert, key) {
		return nil, errors.New("msgsig: key does not match certificate")
	}
	alg, err := algFor(key.Public())
	if err != nil {
		return nil, err
	}
	return &ServerSigner{keyID: KeyID(cert), key: key, alg: alg}, nil
}

// KeyID returns the keyid placed in response signatures.
func (s *ServerSigner) KeyID() string { return s.keyID }

// Alg returns the signature algorithm.
func (s *ServerSigner) Alg() string { return s.alg }
