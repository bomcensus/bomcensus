// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package sign_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/sign"
	"github.com/bomcensus/bomcensus/internal/sign/signtest"
)

func testManifest(now time.Time) *sign.Manifest {
	return &sign.Manifest{
		Version:   "1.2.3",
		IssuedAt:  now.Add(-time.Hour),
		ExpiresAt: now.Add(24 * time.Hour),
		Files: []sign.File{
			signtest.FileEntry("linux", "amd64", "bomcensus-agent", []byte("agent")),
			signtest.FileEntry("linux", "arm64", "bomcensus-agent", []byte("agent-arm")),
		},
	}
}

func TestManifestRoundTrip(t *testing.T) {
	tr := signtest.Install(t)
	now := time.Now()
	b, sig := tr.SignManifest(t, testManifest(now))
	m, err := sign.VerifyManifest(b, sig, now)
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != "1.2.3" || len(m.Files) != 2 {
		t.Fatalf("unexpected manifest %+v", m)
	}
	if f, ok := m.Lookup("linux", "arm64", "bomcensus-agent"); !ok || f.Size != int64(len("agent-arm")) {
		t.Fatalf("lookup: %+v %v", f, ok)
	}
	if got := m.FilesFor("linux", "amd64"); len(got) != 1 {
		t.Fatalf("FilesFor: %d", len(got))
	}
}

func TestManifestRejects(t *testing.T) {
	tr := signtest.Install(t)
	now := time.Now()
	b, sig := tr.SignManifest(t, testManifest(now))

	t.Run("bad signature", func(t *testing.T) {
		bad := bytes.Clone(sig)
		bad[0] ^= 1
		if _, err := sign.VerifyManifest(b, bad, now); !errors.Is(err, sign.ErrManifestSignature) {
			t.Fatalf("got %v", err)
		}
		if _, err := sign.VerifyManifest(b, sig[:10], now); !errors.Is(err, sign.ErrManifestSignature) {
			t.Fatalf("short: got %v", err)
		}
	})
	t.Run("modified manifest", func(t *testing.T) {
		mod := bytes.Replace(b, []byte("1.2.3"), []byte("9.2.3"), 1)
		if _, err := sign.VerifyManifest(mod, sig, now); !errors.Is(err, sign.ErrManifestSignature) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("expired", func(t *testing.T) {
		if _, err := sign.VerifyManifest(b, sig, now.Add(25*time.Hour)); !errors.Is(err, sign.ErrManifestExpired) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("not yet valid", func(t *testing.T) {
		if _, err := sign.VerifyManifest(b, sig, now.Add(-2*time.Hour)); !errors.Is(err, sign.ErrManifestNotYetValid) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		other := signtest.NewTrust(t)
		b2, sig2 := other.SignManifest(t, testManifest(now))
		if _, err := sign.VerifyManifest(b2, sig2, now); !errors.Is(err, sign.ErrManifestSignature) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("second key accepted", func(t *testing.T) {
		next := signtest.NewTrust(t)
		signtest.SetTrust(t, tr.ReleaseKeys()+","+next.ReleaseKeys(), tr.CodeSigningRoots())
		b2, sig2 := next.SignManifest(t, testManifest(now))
		if _, err := sign.VerifyManifest(b2, sig2, now); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("no keys compiled in", func(t *testing.T) {
		signtest.SetTrust(t, "", "")
		if _, err := sign.VerifyManifest(b, sig, now); !errors.Is(err, sign.ErrNoReleaseKeys) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("malformed keys", func(t *testing.T) {
		signtest.SetTrust(t, "not-base64!", "")
		if _, err := sign.VerifyManifest(b, sig, now); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("signed but malformed", func(t *testing.T) {
		raw := []byte(`{"version":"1.0","issued_at":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z","files":[]}`)
		if _, err := sign.VerifyManifest(raw, sign.SignManifest(tr.ManifestKey, raw), now); err == nil {
			t.Fatal("accepted")
		}
		good := append(bytes.Clone(b), []byte("{}")...)
		if _, err := sign.VerifyManifest(good, sign.SignManifest(tr.ManifestKey, good), now); err == nil || !strings.Contains(err.Error(), "trailing") {
			t.Fatalf("trailing data: got %v", err)
		}
	})
}

func TestManifestValidate(t *testing.T) {
	now := time.Now()
	cases := map[string]func(m *sign.Manifest){
		"version":   func(m *sign.Manifest) { m.Version = "v1.2.3" },
		"expiry":    func(m *sign.Manifest) { m.ExpiresAt = m.IssuedAt },
		"no files":  func(m *sign.Manifest) { m.Files = nil },
		"name":      func(m *sign.Manifest) { m.Files[0].Name = "../agent" },
		"os":        func(m *sign.Manifest) { m.Files[0].OS = "Linux" },
		"hash":      func(m *sign.Manifest) { m.Files[0].SHA256 = strings.ToUpper(m.Files[0].SHA256) },
		"size":      func(m *sign.Manifest) { m.Files[0].Size = 0 },
		"duplicate": func(m *sign.Manifest) { m.Files[1] = m.Files[0] },
	}
	for name, mod := range cases {
		m := testManifest(now)
		mod(m)
		if err := m.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := sign.EncodeManifest(m); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
	if err := testManifest(now).Validate(); err != nil {
		t.Fatal(err)
	}
}
