// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package token

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

const example = "bc1.G8R7VVe0OqdFPuyDNuhf9ybu_SInPxoLzh801xR3LeU.LqVSSwJDhTo.2TsFaobRZXyaZajjGC_lZwnlwXXj1PuOEbmBKf5ICPE"

func TestParseExample(t *testing.T) {
	tok, err := Parse(example)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := tok.String(); got != example {
		t.Fatalf("String = %q, want %q", got, example)
	}
	if got := tok.KeyID.String(); got != "LqVSSwJDhTo" {
		t.Fatalf("KeyID = %q", got)
	}
	if len(example) != Len || Len != 103 {
		t.Fatalf("Len = %d, example %d", Len, len(example))
	}
}

func TestNewRoundTrip(t *testing.T) {
	var ca [CAHashSize]byte
	for i := range ca {
		ca[i] = byte(i)
	}
	for i := 0; i < 64; i++ {
		tok, err := New(ca)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if tok.CAHash != ca {
			t.Fatal("CAHash not kept")
		}
		s := tok.String()
		if len(s) != Len {
			t.Fatalf("len = %d", len(s))
		}
		if Format(tok) != s {
			t.Fatal("Format differs from String")
		}
		back, err := Parse(s)
		if err != nil {
			t.Fatalf("Parse(%q): %v", s, err)
		}
		if back != tok {
			t.Fatalf("round trip mismatch for %q", s)
		}
	}
}

func TestNewIsRandom(t *testing.T) {
	a, err := New([CAHashSize]byte{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New([CAHashSize]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if a.KeyID == b.KeyID || a.Secret == b.Secret {
		t.Fatal("two tokens share key id or secret")
	}
}

func TestRegisterKey(t *testing.T) {
	tok, err := Parse(example)
	if err != nil {
		t.Fatal(err)
	}
	priv := tok.PrivateKey()
	pub := tok.PublicKey()
	if !bytes.Equal(priv.Seed(), tok.Secret[:]) {
		t.Fatal("seed mismatch")
	}
	if !pub.Equal(priv.Public()) {
		t.Fatal("public key mismatch")
	}
	msg := []byte("enrollment transcript")
	if !ed25519.Verify(pub, msg, ed25519.Sign(priv, msg)) {
		t.Fatal("signature does not verify")
	}
}

func TestParseMalformed(t *testing.T) {
	parts := strings.Split(example, ".")
	join := func(p ...string) string { return strings.Join(p, ".") }
	// Last character of a 43-char field carries 2 padding bits; 'F' (000101)
	// sets them, so the strict decoder must refuse it.
	nonCanonical := parts[1][:42] + "F"

	cases := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"prefix only", "bc1"},
		{"wrong version", join("bc2", parts[1], parts[2], parts[3])},
		{"upper version", join("BC1", parts[1], parts[2], parts[3])},
		{"three fields", join(parts[0], parts[1], parts[2]+"A"+parts[3])},
		{"five fields", join(parts[0], parts[1][:42], parts[2], parts[3], "")},
		{"trailing newline", example[:Len-1] + "\n"},
		{"leading space", " " + example[1:]},
		{"padded field", join(parts[0], parts[1][:41]+"=", parts[2], parts[3]+"A")},
		{"std alphabet", join(parts[0], strings.Replace(parts[1], "_", "/", 1), parts[2], parts[3])},
		{"plus sign", join(parts[0], parts[1], parts[2], strings.Replace(parts[3], "_", "+", 1))},
		{"cr in field", join(parts[0], parts[1][:20]+"\r"+parts[1][21:], parts[2], parts[3])},
		{"short ca-hash", join(parts[0], parts[1][:42], parts[2]+"A", parts[3])},
		{"long key-id", join(parts[0], parts[1], parts[2]+"A", parts[3][:42])},
		{"short secret", join(parts[0], parts[1]+"A", parts[2], parts[3][:42])},
		{"non-canonical bits", join(parts[0], nonCanonical, parts[2], parts[3])},
		{"too long", example + "A"},
		{"too short", example[:Len-1]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(tc.in); !errors.Is(err, ErrMalformed) {
				t.Fatalf("Parse(%q) err = %v, want ErrMalformed", tc.in, err)
			}
		})
	}
}

func TestKeyIDText(t *testing.T) {
	tok, err := Parse(example)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(struct{ ID KeyID }{tok.KeyID})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"ID":"LqVSSwJDhTo"}` {
		t.Fatalf("json = %s", b)
	}
	var v struct{ ID KeyID }
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if v.ID != tok.KeyID {
		t.Fatal("key id round trip")
	}
	for _, bad := range []string{"", "LqVSSwJDhT", "LqVSSwJDhToA", "LqVSSwJDhT=", "LqVSSwJDhT/"} {
		if _, err := ParseKeyID(bad); err == nil {
			t.Errorf("ParseKeyID(%q) succeeded", bad)
		}
	}
}

func TestLogValueHidesSecret(t *testing.T) {
	tok, err := Parse(example)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("enroll", "token", tok)
	out := buf.String()
	if strings.Contains(out, strings.Split(example, ".")[3]) {
		t.Fatalf("secret leaked into log: %s", out)
	}
	if !strings.Contains(out, "LqVSSwJDhTo") {
		t.Fatalf("key id missing from log: %s", out)
	}
}
