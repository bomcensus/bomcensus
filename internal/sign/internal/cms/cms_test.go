// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package cms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// jsignBlob returns the PKCS#7 blob of the jsign fixture of package sign.
func jsignBlob(t testing.TB) []byte {
	t.Helper()
	data, err := os.ReadFile("../../testdata/jsign-rfc3161.pe")
	if err != nil {
		t.Fatal(err)
	}
	// The fixture is a 1 KiB image followed by the certificate table.
	s := cryptobyte.String(data[1024+8:])
	var der cryptobyte.String
	if !s.ReadASN1Element(&der, cbasn1.SEQUENCE) {
		t.Fatal("no PKCS#7 data in the fixture")
	}
	return der
}

func TestParseJsign(t *testing.T) {
	sd, err := Parse(jsignBlob(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(sd.Signers) != 1 || len(sd.Certificates) != 1 {
		t.Fatalf("%d signers, %d certificates", len(sd.Signers), len(sd.Certificates))
	}
	si := sd.Signers[0]
	if _, err := sd.Verify(si); err != nil {
		t.Fatal(err)
	}
	if len(si.UnsignedAttrs) != 1 {
		t.Fatalf("%d unsigned attributes", len(si.UnsignedAttrs))
	}
	tok, err := ParseToken(si.UnsignedAttrs[0].Values[0])
	if err != nil {
		t.Fatal(err)
	}
	if tok.Hash != crypto.SHA256 || !tok.GenTime.Equal(time.Date(2026, 11, 22, 14, 0, 23, 0, time.UTC)) {
		t.Fatalf("token %v %v", tok.Hash, tok.GenTime)
	}
	// No roots: the TSA chain must not verify.
	if err := tok.Verify(x509.NewCertPool()); err == nil {
		t.Fatal("TSA chain verified without roots")
	}
}

func TestSignRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "cms test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	content := Build(func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1Int64(42) })
	})
	ct := asn1.ObjectIdentifier{1, 2, 3, 4}
	for _, h := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		s, err := Sign(&SignOptions{ContentType: ct, Content: content, Key: key, Cert: cert, Hash: h})
		if err != nil {
			t.Fatal(err)
		}
		out, err := s.Encode([]Attribute{{Type: asn1.ObjectIdentifier{1, 2, 3, 5}, Values: [][]byte{{0x05, 0x00}}}})
		if err != nil {
			t.Fatal(err)
		}
		sd, err := Parse(out)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sd.Verify(sd.Signers[0]); err != nil {
			t.Fatalf("%v: %v", h, err)
		}
		if !sd.ContentType.Equal(ct) || len(sd.Signers[0].UnsignedAttrs) != 1 {
			t.Fatal("content type or unsigned attributes lost")
		}
	}
	if _, err := Sign(&SignOptions{ContentType: ct, Content: content, Key: key, Cert: cert, Hash: crypto.SHA1}); err == nil {
		t.Fatal("signed with SHA-1")
	}
}

func TestParseGeneralizedTime(t *testing.T) {
	for in, want := range map[string]time.Time{
		"20261122140023Z":     time.Date(2026, 11, 22, 14, 0, 23, 0, time.UTC),
		"20261122140023.5Z":   time.Date(2026, 11, 22, 14, 0, 23, 5e8, time.UTC),
		"20261122140023.120Z": time.Date(2026, 11, 22, 14, 0, 23, 12e7, time.UTC),
	} {
		got, err := parseGeneralizedTime(in)
		if err != nil || !got.Equal(want) {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
	for _, in := range []string{"", "Z", "20261122140023", "2026112214002Z", "20261122140023.Z", "20261122140023.-1Z", "20261122140023+0900"} {
		if _, err := parseGeneralizedTime(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func FuzzParse(f *testing.F) {
	blob := jsignBlob(f)
	f.Add(blob)
	if sd, err := Parse(blob); err == nil {
		f.Add(sd.Signers[0].UnsignedAttrs[0].Values[0])
	}
	f.Fuzz(func(t *testing.T, der []byte) {
		sd, err := Parse(der)
		if err == nil {
			for _, si := range sd.Signers {
				_, _ = sd.Verify(si)
			}
		}
		if tok, err := ParseToken(der); err == nil {
			_ = tok.Verify(x509.NewCertPool())
		}
	})
}
