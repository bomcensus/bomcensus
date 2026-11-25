// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package pkgdb

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/bomcensus/bomcensus/internal/collect"
)

func expectedPkg(t *testing.T, e *Expected, key string) ([]ExpectedFile, int) {
	t.Helper()
	for _, p := range e.Packages {
		if p.Key() == key {
			files, excluded, err := e.Files(p)
			if err != nil {
				t.Fatalf("%s: %v", key, err)
			}
			return files, excluded
		}
	}
	var keys []string
	for _, p := range e.Packages {
		keys = append(keys, p.Key())
	}
	t.Fatalf("package %s not found in %v", key, keys)
	return nil, 0
}

func wantExpected(t *testing.T, files []ExpectedFile, want ExpectedFile) {
	t.Helper()
	for _, f := range files {
		if f.Path == want.Path {
			if f != want {
				t.Errorf("%s:\n got %+v\nwant %+v", want.Path, f, want)
			}
			return
		}
	}
	t.Errorf("%s not among the expected files", want.Path)
}

func noExpected(t *testing.T, files []ExpectedFile, p string) {
	t.Helper()
	for _, f := range files {
		if f.Path == p {
			t.Errorf("%s is checked: %+v", p, f)
		}
	}
}

func TestExpectedRPM(t *testing.T) {
	for _, fx := range []string{"rpm-sqlite", "rpm-bdb", "rpm-ndb"} {
		t.Run(fx, func(t *testing.T) {
			e := ReadExpected(context.Background(), fixtureEnv(t, fx))
			if len(e.Problems) > 0 || len(e.Databases) != 1 {
				t.Fatalf("problems %v, databases %v", e.Problems, e.Databases)
			}
			if !slices.IsSortedFunc(e.Packages, func(a, b *ExpectedPackage) int {
				return compareStrings(a.Key(), b.Key())
			}) {
				t.Error("packages not sorted by key")
			}
		})
	}
	e := ReadExpected(context.Background(), fixtureEnv(t, "rpm-sqlite"))
	files, excluded := expectedPkg(t, e, "rpm/bash/x86_64/5.1.8-9.el9")
	wantExpected(t, files, ExpectedFile{Path: "/usr/bin/bash", Algo: AlgoSHA256,
		Digest: "ec6d007d48ef11bc47ad3f372b4b20ff2f0d4e63867e7e4cc0f1b17b19fa88b2"})
	// /etc/skel/.bashrc and the other skeleton files are %config.
	if excluded != 3 {
		t.Errorf("bash excluded %d files, want 3", excluded)
	}
	noExpected(t, files, "/etc/skel/.bashrc")
	noExpected(t, files, "/usr/bin") // directories are not files
	files, _ = expectedPkg(t, e, "rpm/shadow-utils/x86_64/2:4.9-17.el9")
	noExpected(t, files, "/etc/login.defs")
}

func TestExpectedAPK(t *testing.T) {
	e := ReadExpected(context.Background(), fixtureEnv(t, "apk"))
	if len(e.Problems) > 0 {
		t.Fatalf("problems %v", e.Problems)
	}
	files, excluded := expectedPkg(t, e, "apk/busybox/x86_64/1.36.1-r31")
	wantExpected(t, files, ExpectedFile{Path: "/bin/busybox", Algo: AlgoSHA1,
		Digest: "2934fd3324a3e2195200402a528ebeab94c68dca", MaySymlink: true})
	if excluded == 0 {
		t.Error("busybox's files in /etc were not left out")
	}
	for _, f := range files {
		if f.Path == "/etc" || len(f.Path) > 5 && f.Path[:5] == "/etc/" {
			t.Errorf("%s is checked", f.Path)
		}
	}
}

func TestAPKChecksum(t *testing.T) {
	for _, c := range []struct{ in, algo, digest string }{
		{"Q1KTT9MySj4hlSAEAqUo6+q5TGjco=", AlgoSHA1, "2934fd3324a3e2195200402a528ebeab94c68dca"},
		{"Q2qFLIPLfjIG3Rnxcnj5gP4pNSMvEHXxdELYnHiX8R4g8=", AlgoSHA256, "a852c83cb7e3206dd19f17278f980fe2935232f1075f17442d89c7897f11e20f"},
		{"0123456789ABCDEF0123456789abcdef", AlgoMD5, "0123456789abcdef0123456789abcdef"},
		{"Q1short", "", ""},
		{"garbage", "", ""},
	} {
		algo, digest, ok := apkChecksum(c.in)
		if c.algo == "" {
			if ok {
				t.Errorf("%q accepted", c.in)
			}
			continue
		}
		if !ok || algo != c.algo || digest != c.digest {
			t.Errorf("%q = %s %s %v, want %s %s", c.in, algo, digest, ok, c.algo, c.digest)
		}
	}
}

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, content := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestExpectedDpkg(t *testing.T) {
	root := t.TempDir()
	const sumA = "11111111111111111111111111111111"
	const sumB = "22222222222222222222222222222222"
	writeFiles(t, root, map[string]string{
		"var/lib/dpkg/status": `Package: alpha
Status: install ok installed
Architecture: all
Version: 1.0
Conffiles:
 /etc/alpha.conf 33333333333333333333333333333333
 /etc/alpha-old.conf 44444444444444444444444444444444 obsolete
Description: a package

Package: beta
Status: install ok installed
Architecture: amd64
Multi-Arch: same
Version: 2:2.0-1

Package: half
Status: install reinstreq half-installed
Architecture: all
Version: 0.1

Package: divert
Status: install ok installed
Architecture: all
Version: 3

Package: removed
Status: deinstall ok config-files
Architecture: all
Version: 1
`,
		"var/lib/dpkg/info/alpha.list":    "/.\n/etc\n/etc/alpha.conf\n/usr\n/usr/bin\n/usr/bin/alpha\n/usr/bin/tool\n",
		"var/lib/dpkg/info/alpha.md5sums": sumA + "  usr/bin/alpha\n" + sumA + "  usr/bin/tool\n" + sumA + "  etc/alpha.conf\n" + sumA + "  usr/share/taken-over\nnot a line\n",
		"var/lib/dpkg/info/beta:amd64.list":    "/usr/lib/libbeta.so.2\n",
		"var/lib/dpkg/info/beta:amd64.md5sums": sumB + "  usr/lib/libbeta.so.2\n",
		"var/lib/dpkg/info/half.list":          "/usr/bin/half\n",
		"var/lib/dpkg/info/half.md5sums":       sumA + "  usr/bin/half\n",
		"var/lib/dpkg/info/divert.list":        "/usr/bin/tool\n",
		"var/lib/dpkg/info/divert.md5sums":     sumB + "  usr/bin/tool\n",
		"var/lib/dpkg/diversions":              "/usr/bin/tool\n/usr/bin/tool.real\ndivert\n",
	})
	e := ReadExpected(context.Background(), collect.NewEnv().WithRoot(root))
	if len(e.Problems) > 0 {
		t.Fatalf("problems %v", e.Problems)
	}
	var keys []string
	for _, p := range e.Packages {
		keys = append(keys, p.Key())
	}
	if want := []string{"deb/alpha/all/1.0", "deb/beta/amd64/2:2.0-1", "deb/divert/all/3"}; !slices.Equal(keys, want) {
		t.Fatalf("packages %v, want %v", keys, want)
	}

	files, excluded := expectedPkg(t, e, "deb/alpha/all/1.0")
	wantExpected(t, files, ExpectedFile{Path: "/usr/bin/alpha", Algo: AlgoMD5, Digest: sumA})
	// alpha's copy of the diverted file is at the diversion target.
	wantExpected(t, files, ExpectedFile{Path: "/usr/bin/tool.real", Algo: AlgoMD5, Digest: sumA})
	noExpected(t, files, "/etc/alpha.conf")
	noExpected(t, files, "/usr/share/taken-over")
	if excluded != 1 || len(files) != 2 {
		t.Errorf("alpha: %d files, %d excluded; want 2 and 1", len(files), excluded)
	}

	files, _ = expectedPkg(t, e, "deb/beta/amd64/2:2.0-1")
	wantExpected(t, files, ExpectedFile{Path: "/usr/lib/libbeta.so.2", Algo: AlgoMD5, Digest: sumB})

	// The diverting package's own file stays where it is.
	files, _ = expectedPkg(t, e, "deb/divert/all/3")
	wantExpected(t, files, ExpectedFile{Path: "/usr/bin/tool", Algo: AlgoMD5, Digest: sumB})

	if p := e.Find("deb", "beta", "amd64"); p == nil || p.Version != "2:2.0-1" {
		t.Errorf("Find(beta) = %+v", p)
	}
	if p := e.Find("deb", "half", "all"); p != nil {
		t.Errorf("half-installed package listed: %+v", p)
	}
}

func TestExpectedNoDatabase(t *testing.T) {
	e := ReadExpected(context.Background(), collect.NewEnv().WithRoot(t.TempDir()))
	if len(e.Packages) != 0 || len(e.Databases) != 0 || len(e.Problems) != 0 {
		t.Errorf("empty root: %+v", e)
	}
}

func compareStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
