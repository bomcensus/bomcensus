// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/release"
	"github.com/bomcensus/bomcensus/internal/sign/signtest"
)

func TestPipeline(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()
	keys := filepath.Join(tmp, "keys")
	bin := filepath.Join(tmp, "bin")

	mustRun := func(args ...string) string {
		t.Helper()
		var out bytes.Buffer
		if err := run(ctx, args, &out, io.Discard); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		return out.String()
	}

	mustRun("keygen", "--out", keys)
	if err := run(ctx, []string{"keygen", "--out", keys}, io.Discard, io.Discard); err == nil {
		t.Fatal("keygen overwrote existing keys")
	}
	// Windows has no Unix modes; os.Stat reports 0666 or 0444 there.
	if st, err := os.Stat(filepath.Join(keys, fileManifestKey)); err != nil || (runtime.GOOS != "windows" && st.Mode().Perm() != 0o600) {
		t.Fatalf("manifest key mode: %v %v", st, err)
	}

	var targets []string
	for _, arch := range []string{"amd64", "arm64"} {
		d := filepath.Join(bin, "linux-"+arch)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(d, "bomcensus-agent")
		if err := os.WriteFile(p, signtest.ELF(t, arch), 0o755); err != nil {
			t.Fatal(err)
		}
		targets = append(targets, p)
	}
	mustRun(append([]string{"sign-elf", "--key", filepath.Join(keys, fileCodeKey), "--cert", filepath.Join(keys, fileCodeCert)}, targets...)...)
	if st, err := os.Stat(targets[0]); err != nil || (runtime.GOOS != "windows" && st.Mode().Perm() != 0o755) {
		t.Fatalf("signed file mode: %v %v", st, err)
	}

	var peTargets []string
	for _, arch := range []string{"amd64", "arm64"} {
		d := filepath.Join(bin, "windows-"+arch)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(d, "bomcensus-agent.exe")
		if err := os.WriteFile(p, signtest.PE(t, arch), 0o755); err != nil {
			t.Fatal(err)
		}
		peTargets = append(peTargets, p)
	}
	if err := run(ctx, append([]string{"sign-elf", "--key", filepath.Join(keys, fileCodeKey), "--cert", filepath.Join(keys, fileCodeCert)}, peTargets...), io.Discard, io.Discard); err == nil {
		t.Fatal("sign-elf signed a PE file")
	}
	mustRun(append([]string{"sign-pe", "--key", filepath.Join(keys, fileCodeKey), "--cert", filepath.Join(keys, fileCodeCert)}, peTargets...)...)

	bundle := filepath.Join(tmp, "bomcensus-1.2.3.tar")
	mustRun("bundle", "--version", "1.2.3", "--manifest-key", filepath.Join(keys, fileManifestKey), "--dir", bin, "--out", bundle)

	flags := mustRun("print-ldflags", "--keys", keys)
	m := regexp.MustCompile(`^-X ` + regexp.QuoteMeta(ldflagReleaseKeys) + `=(\S+) -X ` + regexp.QuoteMeta(ldflagCodeSigningRoots) + `=(\S+)\n$`).FindStringSubmatch(flags)
	if m == nil {
		t.Fatalf("unexpected ldflags %q", flags)
	}
	signtest.SetTrust(t, m[1], m[2])

	data, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	b, err := release.Open(ctx, bytes.NewReader(data), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if b.Version() != "1.2.3" || len(b.Platforms()) != 4 {
		t.Fatalf("version %s platforms %v", b.Version(), b.Platforms())
	}
	if out := mustRun("verify", bundle); !regexp.MustCompile(`platforms linux-amd64 linux-arm64 windows-amd64 windows-arm64: OK`).MatchString(out) {
		t.Fatalf("verify output %q", out)
	}

	signtest.SetTrust(t, signtest.NewTrust(t).ReleaseKeys(), m[2])
	if err := run(ctx, []string{"verify", bundle}, io.Discard, io.Discard); err == nil {
		t.Fatal("verify accepted a bundle signed with another key")
	}
}
