// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package sign

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// The jsign fixtures are signtest.MinimalPE("amd64") signed by jsign 7.6
// with an RSA key under testdata/jsign-ca.crt:
//
//	jsign --keyfile key.pem --certfile cert.pem --alg SHA-256 \
//	    --tsmode RFC3161 --tsaurl http://timestamp.digicert.com jsign-rfc3161.pe
//	jsign --keyfile key.pem --certfile cert.pem --alg SHA-512 jsign-sha512.pe
//
// The signer certificate is valid from 2026-11-22 12:41 to 2026-12-22 12:41
// UTC; the timestamp is 2026-11-22 14:00:23 UTC.

func readPool(t testing.TB, name string) *x509.CertPool {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	for {
		var blk *pem.Block
		if blk, b = pem.Decode(b); blk == nil {
			break
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		pool.AddCert(c)
	}
	return pool
}

func mustPEM(t testing.TB, name string) []byte {
	t.Helper()
	blk, _ := pem.Decode(readFixture(t, name))
	if blk == nil {
		t.Fatalf("%s: no PEM block", name)
	}
	return blk.Bytes
}

func readFixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPEJsignTimestamped(t *testing.T) {
	data := readFixture(t, "jsign-rfc3161.pe")
	roots := readPool(t, "jsign-ca.crt")
	tsRoots := readPool(t, "digicert-trusted-root-g4.crt")
	// Long after the signer certificate expired: the timestamp keeps the
	// signature valid.
	later := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)

	res, err := verifyPEPools(data, roots, tsRoots, later)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].hash != crypto.SHA256 {
		t.Fatalf("results %+v", res)
	}
	want := time.Date(2026, 11, 22, 14, 0, 23, 0, time.UTC)
	if !res[0].timestamp.Equal(want) {
		t.Fatalf("timestamp %v, want %v", res[0].timestamp, want)
	}
	if res[0].signer.Subject.CommonName != "bomcensus test code signing" {
		t.Fatalf("signer %v", res[0].signer.Subject)
	}

	p, err := parsePE(data)
	if err != nil {
		t.Fatal(err)
	}
	// jsign writes the checksum of the signed file.
	cs := bytes.Clone(data)
	clear(cs[p.checksumOff : p.checksumOff+4])
	if got, want := peChecksum(cs), le.Uint32(data[p.checksumOff:]); got != want {
		t.Fatalf("checksum %#x, jsign wrote %#x", got, want)
	}

	sig, err := p.signature(data)
	if err != nil {
		t.Fatal(err)
	}
	sigOff := p.certOff + 8
	find := func(needle []byte) int {
		i := bytes.Index(sig, needle)
		if i < 0 {
			t.Fatal("marker not found")
		}
		return sigOff + i
	}

	tamper := map[string][]byte{
		"code":              flipAt(data, 0x200),
		"dos header":        flipAt(data, 0x10),
		"section table":     flipAt(data, 0x148+8),
		"appended":          append(bytes.Clone(data), make([]byte, 8)...),
		"image digest":      flipAt(data, find([]byte("\x04\x20\x77\x31\x82\x06"))+4),
		"tsa genTime":       flipAt(data, find([]byte("20261122140023Z"))+3),
		"timestamp imprint": flipAt(data, find([]byte{0x04, 0x20, 0xa2, 0x1c, 0xee})+4),
		"signature value":   flipAt(data, p.certOff+1200),
	}
	for name, d := range tamper {
		t.Run(name, func(t *testing.T) {
			_, err := verifyPEPools(d, roots, tsRoots, later)
			if err == nil {
				t.Fatal("accepted")
			}
			t.Log(err)
		})
	}
	t.Run("unknown TSA root", func(t *testing.T) {
		_, err := verifyPEPools(data, roots, x509.NewCertPool(), later)
		if err == nil || !strings.Contains(err.Error(), "timestamp") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("other code-signing root", func(t *testing.T) {
		if _, err := verifyPEPools(data, tsRoots, tsRoots, later); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("timestamp removed", func(t *testing.T) {
		// Without its timestamp the signature is checked at the current
		// time; long after the certificate expired that fails.
		d := stripTimestamp(t, data)
		if _, err := verifyPEPools(d, roots, tsRoots, later); err == nil || !strings.Contains(err.Error(), "certificate") {
			t.Fatalf("got %v", err)
		}
		res, err := verifyPEPools(d, roots, tsRoots, time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC))
		if err != nil || !res[0].timestamp.IsZero() {
			t.Fatalf("within the certificate validity: %v", err)
		}
	})
	t.Run("system roots", func(t *testing.T) {
		ca, err := x509.ParseCertificate(mustPEM(t, "jsign-ca.crt"))
		if err != nil {
			t.Fatal(err)
		}
		err = verifyPE(data, []*x509.Certificate{ca}, later)
		if err != nil && strings.Contains(err.Error(), "timestamp authority certificate") {
			t.Skipf("DigiCert root not in the system trust store: %v", err)
		}
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestPEJsignUntimestamped(t *testing.T) {
	data := readFixture(t, "jsign-sha512.pe")
	roots := readPool(t, "jsign-ca.crt")
	inValidity := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	res, err := verifyPEPools(data, roots, x509.NewCertPool(), inValidity)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].hash != crypto.SHA512 || !res[0].timestamp.IsZero() {
		t.Fatalf("results %+v", res)
	}
	if _, err := verifyPEPools(data, roots, x509.NewCertPool(), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("accepted after the signer certificate expired")
	}
	if _, err := verifyPEPools(flipAt(data, 0x201), roots, x509.NewCertPool(), inValidity); err == nil {
		t.Fatal("accepted modified code")
	}
}

// stripTimestamp rewrites the jsign fixture without the unsigned
// attributes of its signer.
func stripTimestamp(t *testing.T, data []byte) []byte {
	t.Helper()
	p, err := parsePE(data)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := p.signature(data)
	if err != nil {
		t.Fatal(err)
	}
	// ContentInfo { oid, [0] { SignedData { ..., signerInfos SET { SignerInfo { ..., [1] } } } } }
	ci := children(t, sig)
	wrapped := children(t, ci[1])
	sd := children(t, wrapped[0])
	set := children(t, sd[len(sd)-1])
	si := children(t, set[0])
	if si[len(si)-1][0] != 0xa1 {
		t.Fatal("signer has no unsigned attributes")
	}
	si = si[:len(si)-1]
	set[0] = join(set[0][0], si)
	sd[len(sd)-1] = join(sd[len(sd)-1][0], set)
	wrapped[0] = join(wrapped[0][0], sd)
	ci[1] = join(ci[1][0], wrapped)
	der := join(sig[0], ci)

	out := bytes.Clone(data[:p.certOff])
	size := (8 + len(der) + 7) &^ 7
	entry := make([]byte, size)
	le.PutUint32(entry, uint32(size))
	le.PutUint16(entry[4:], winCertRevision2)
	le.PutUint16(entry[6:], winCertTypePKCSSigned)
	copy(entry[8:], der)
	le.PutUint32(out[p.certDirOff+4:], uint32(size))
	return append(out, entry...)
}

func children(t *testing.T, elem []byte) [][]byte {
	t.Helper()
	var body cryptobyte.String
	var tag cbasn1.Tag
	if s := cryptobyte.String(elem); !s.ReadAnyASN1(&body, &tag) || !s.Empty() {
		t.Fatal("malformed element")
	}
	var out [][]byte
	for !body.Empty() {
		var c cryptobyte.String
		if !body.ReadAnyASN1Element(&c, nil) {
			t.Fatal("malformed child")
		}
		out = append(out, c)
	}
	return out
}

func join(tag byte, elems [][]byte) []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.Tag(tag), func(b *cryptobyte.Builder) {
		for _, e := range elems {
			b.AddBytes(e)
		}
	})
	return b.BytesOrPanic()
}

func flipAt(b []byte, i int) []byte {
	b = bytes.Clone(b)
	b[i] ^= 0x01
	return b
}

func FuzzVerifyPE(f *testing.F) {
	for _, name := range []string{"jsign-rfc3161.pe", "jsign-sha512.pe"} {
		f.Add(readFixture(f, name))
	}
	roots := readPool(f, "jsign-ca.crt")
	tsRoots := readPool(f, "digicert-trusted-root-g4.crt")
	now := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = verifyPEPools(data, roots, tsRoots, now)
		_ = IsPE(data)
	})
}
