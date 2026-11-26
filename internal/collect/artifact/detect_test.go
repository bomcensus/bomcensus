// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package artifact

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bomcensus/bomcensus/internal/report"
)

// readTxtar parses the txtar format: "-- name --" lines start sections, text
// before the first section is a comment.
func readTxtar(t *testing.T, file string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	var name string
	var body strings.Builder
	flush := func() {
		if name != "" {
			out[name] = body.String()
		}
		body.Reset()
	}
	for _, line := range strings.SplitAfter(string(b), "\n") {
		trim := strings.TrimSuffix(line, "\n")
		if strings.HasPrefix(trim, "-- ") && strings.HasSuffix(trim, " --") && len(trim) > 6 {
			flush()
			name = trim[3 : len(trim)-3]
			continue
		}
		body.WriteString(line)
	}
	flush()
	return out
}

func detectorByID(t *testing.T, id string) *Detector {
	t.Helper()
	for _, d := range Detectors {
		if d.ID == id {
			return d
		}
	}
	t.Fatalf("no detector %q", id)
	return nil
}

func TestDetectorTable(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range Detectors {
		if d.ID == "" || d.Name == "" || len(d.Names) == 0 {
			t.Errorf("incomplete detector %+v", d)
		}
		if seen[d.ID] {
			t.Errorf("duplicate id %q", d.ID)
		}
		seen[d.ID] = true
		if len(d.Exec) > 0 && len(d.Parse) == 0 {
			t.Errorf("%s: exec without parse rules", d.ID)
		}
		if len(d.Exec) == 0 && len(d.Static) == 0 {
			t.Errorf("%s: no way to find a version", d.ID)
		}
		for _, r := range append(append([]Rule{}, d.Parse...), staticRules(d)...) {
			if r.Pattern.NumSubexp() < 1 {
				t.Errorf("%s: pattern %q has no group", d.ID, r.Pattern)
			}
		}
	}
}

func staticRules(d *Detector) []Rule {
	var out []Rule
	for _, s := range d.Static {
		out = append(out, s.Rules...)
	}
	return out
}

func TestDetectorParseRealOutputs(t *testing.T) {
	fx := readTxtar(t, filepath.Join("testdata", "versions.txtar"))
	cases := []struct {
		detector, fixture, name, version string
	}{
		{"openjdk", "temurin-21-alpine", "openjdk", "21.0.13"},
		{"openjdk", "temurin-8", "openjdk", "1.8.0_512"},
		{"nodejs", "node-22-alpine", "node", "22.23.5"},
		{"php", "php-8.3-cli-alpine", "php", "8.3.37"},
		{"php-fpm", "php-8.3-fpm-alpine", "php", "8.3.37"},
		{"python", "python-3.12-alpine", "python", "3.12.16"},
		{"python", "python-2.7-alpine", "python", "2.7.18"},
		{"ruby", "ruby-3.3-alpine", "ruby", "3.3.14"},
		{"perl", "perl-5.40-slim", "perl", "5.40.5"},
		{"nginx", "nginx-1.27-alpine", "nginx", "1.27.5"},
		{"httpd", "httpd-2.4-alpine", "httpd", "2.4.71"},
		{"redis", "redis-7-alpine", "redis", "7.4.12"},
		{"postgresql", "postgres-17", "postgresql", "17.12"},
		{"mysql", "mysql-8.4", "mysql", "8.4.13"},
		{"mysql", "mariadb-11", "mariadb", "11.8.9"},
		{"mongodb", "mongo-7", "mongodb", "7.0.45"},
		{"openssl", "debian-13", "openssl", "3.5.7"},
		{"openssl", "ubuntu-22.04", "openssl", "3.0.2"},
	}
	used := map[string]bool{}
	for _, tc := range cases {
		t.Run(tc.detector+"/"+tc.fixture, func(t *testing.T) {
			key := tc.detector + "/" + tc.fixture
			stdout, okOut := fx[key+".stdout"]
			stderr, okErr := fx[key+".stderr"]
			if !okOut && !okErr {
				t.Fatalf("no fixture %s", key)
			}
			used[key+".stdout"], used[key+".stderr"] = true, true
			d := detectorByID(t, tc.detector)
			m, ok := firstMatch(d.Parse, []byte(stdout+"\n"+stderr))
			if !ok || m.Version != tc.version || cmpOr(m.Name, d.Name) != tc.name {
				t.Fatalf("got %+v ok=%v, want %s %s", m, ok, tc.name, tc.version)
			}
		})
	}
	for k := range fx {
		if !used[k] {
			t.Errorf("fixture %s is not checked", k)
		}
	}
}

// Byte snippets around the version strings of the real binaries the static
// rules were written against (same images as testdata/versions.txtar).
func TestDetectorStaticSnippets(t *testing.T) {
	cases := []struct {
		detector, snippet, name, version string
	}{
		{"nodejs", "\x00https://nodejs.org/download/release/v22.23.5/node-v22.23.5-headers.tar.gz\x00", "node", "22.23.5"},
		{"php", "\x00X-Powered-By: PHP/8.3.37\x00", "php", "8.3.37"},
		{"php-fpm", "\x00X-Powered-By: PHP/8.3.37\x00", "php", "8.3.37"},
		{"python", "must be %.50s, not %.50s\x003.12.16\x00%.80s (%.80s) %.80s\x00PYTHONDEVMODE", "python", "3.12.16"},
		{"ruby", "\x00ruby 3.3.14 (2026-11-19 revision f4c37f481b) [x86_64-linux-musl]\x00", "ruby", "3.3.14"},
		{"perl", "\x00/usr/local/lib/perl5/5.40.5/x86_64-linux-gnu/CORE\x00", "perl", "5.40.5"},
		{"perl", "Builtin version bundle \"%s\" is not supported by Perl 5.40.5\x00", "perl", "5.40.5"},
		{"nginx", "\x00nginx version: nginx/1.27.5\x00", "nginx", "1.27.5"},
		{"httpd", "\x00Apache/2.4.71 (Unix)\x00", "httpd", "2.4.71"},
		{"redis", "with: %s\x00\x007.4.12buildkitsandbox-1794254934000000000\x00\x00", "redis", "7.4.12"},
		{"postgresql", "\x00PostgreSQL 17.12 (Debian 17.12-1.pgdg13+1) on x86_64-pc-linux-gnu, compiled by gcc\x00", "postgresql", "17.12"},
		{"mysql", "\x00../../mysql-8.4.13/mysys/my_file.cc\x00", "mysql", "8.4.13"},
		{"mysql", "\x0011.8.9-MariaDB\x00../../mysql-8.4.13/x\x00", "mariadb", "11.8.9"},
		{"openssl", "\x00OpenSSL 3.5.7 9 Jun 2026\x00", "openssl", "3.5.7"},
		{"openssl", "\x00OpenSSL 1.1.1w  11 Sep 2023\x00", "openssl", "1.1.1w"},
		{"genian-nac", "2.1.2=\x005.0.54\x00License version mismatched\x001.3.6.", "genian-nac", "5.0.54"},
		{"genian-nac", "2.1.2=\x006.0.15\x00License version mismatched\x001.3.6.", "genian-ztna", "6.0.15"},
	}
	for _, tc := range cases {
		t.Run(tc.detector+"/"+tc.version, func(t *testing.T) {
			d := detectorByID(t, tc.detector)
			for _, r := range d.Static {
				if r.File != "" || r.Entry != "" || r.BuildSetting != "" || r.GoMain {
					continue
				}
				// Pad so that the match crosses a chunk boundary.
				data := strings.Repeat("\x01", scanChunk-len(tc.snippet)/2) + tc.snippet
				m, ok := scanReader(strings.NewReader(data), r.Rules, limitOr(r.Limit, defaultBinaryLimit))
				if ok {
					if m.Version != tc.version || cmpOr(m.Name, d.Name) != tc.name {
						t.Fatalf("got %+v, want %s %s", m, tc.name, tc.version)
					}
					return
				}
			}
			t.Fatalf("no static rule matched")
		})
	}
}

func TestDetectorGoRules(t *testing.T) {
	dockerd := &goInfo{
		Main: goMod{Path: "github.com/moby/moby/v2", Version: "(devel)"},
		Settings: map[string]string{"-ldflags": `-w -X "github.com/moby/moby/v2/dockerversion.Version=29.10.0" ` +
			`-X "github.com/moby/moby/v2/dockerversion.GitCommit=06db173"`},
	}
	cli := &goInfo{Settings: map[string]string{"-ldflags": `-w  -X "github.com/docker/cli/cli/version.GitCommit=fdd4b8e" ` +
		`-X "github.com/docker/cli/cli/version.Version=29.10.0"`}}
	runc := &goInfo{Main: goMod{Path: "github.com/opencontainers/runc", Version: "v1.5.3"}}
	ctr := &goInfo{Main: goMod{Path: "github.com/containerd/containerd/v2", Version: "v2.4.2"}}
	c := newCollector(testEnv("/"), Inputs{})
	for _, tc := range []struct {
		id      string
		gi      *goInfo
		version string
	}{
		{"dockerd", dockerd, "29.10.0"},
		{"docker-cli", cli, "29.10.0"},
		{"runc", runc, "1.5.3"},
		{"containerd", ctr, "2.4.2"},
	} {
		m, ok := c.static(detectorByID(t, tc.id), staticSource{goInfo: tc.gi}, nil)
		if !ok || m.Version != tc.version {
			t.Errorf("%s: got %+v ok=%v", tc.id, m, ok)
		}
	}
}

func TestDetectorMatches(t *testing.T) {
	cases := []struct {
		id, path string
		want     bool
	}{
		{"openjdk", "/usr/lib/jvm/java-17/bin/java", true},
		{"openjdk", "/opt/jdk8/jre/bin/java", true},
		{"openjdk", "/usr/share/java", false},
		{"php", "/usr/bin/php8.2", true},
		{"php", "/usr/sbin/php-fpm8.2", false},
		{"php-fpm", "/usr/sbin/php-fpm8.2", true},
		{"python", "/usr/bin/python3.11", true},
		{"python", "/usr/bin/python3-config", false},
		{"tomcat", "/opt/tomcat/lib/catalina.jar", true},
		{"tomcat", "/opt/app/catalina.jar", false},
		{"containerd", "/usr/bin/containerd-shim-runc-v2", true},
		{"genian-nac", "/usr/geni/centerd", true},
		{"genian-nac", "/opt/x/centerd", false},
	}
	for _, tc := range cases {
		if got := detectorByID(t, tc.id).matches(tc.path); got != tc.want {
			t.Errorf("%s %s = %v", tc.id, tc.path, got)
		}
	}
}

func TestDetectorSideFiles(t *testing.T) {
	root := t.TempDir()
	write := func(p, content string, mode os.FileMode) {
		t.Helper()
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	// A JDK whose launcher has no version string; the release file has it.
	write("opt/jdk/bin/java", string(tinyELF(t, "x", "", 0)), 0o755)
	write("opt/jdk/release", "IMPLEMENTOR=\"Eclipse Adoptium\"\nJAVA_VERSION=\"17.0.21\"\n", 0o644)
	// JDK 8 layout: jre/bin/java, release two levels up.
	write("opt/jdk8/jre/bin/java", string(tinyELF(t, "x", "", 0)), 0o755)
	write("opt/jdk8/release", "JAVA_VERSION=\"1.8.0_512\"\n", 0o644)
	// Ruby whose version lives in the shared library.
	write("usr/local/bin/ruby", string(tinyELF(t, "x", "", 0)), 0o755)
	write("usr/local/lib/libruby.so.3.3.14", "\x00ruby 3.3.14 (2026-11-19 revision f4c37f481b) [x86_64-linux-musl]\x00", 0o755)
	// Tomcat: version in the catalina.jar manifest and in RELEASE-NOTES.
	var jar bytes.Buffer
	zw := zip.NewWriter(&jar)
	w, _ := zw.Create("META-INF/MANIFEST.MF")
	w.Write([]byte("Manifest-Version: 1.0\r\nImplementation-Title: Apache Tomcat\r\nImplementation-Version: 10.1.62\r\n\r\n"))
	zw.Close()
	write("usr/local/tomcat/lib/catalina.jar", jar.String(), 0o644)
	write("usr/local/tomcat/RELEASE-NOTES", "  Apache Tomcat Version 10.1.62\n", 0o644)
	// Tomcat whose catalina.jar has no manifest version.
	var jar2 bytes.Buffer
	zw = zip.NewWriter(&jar2)
	zw.Create("org/")
	zw.Close()
	write("srv/tc9/lib/catalina.jar", jar2.String(), 0o644)
	write("srv/tc9/RELEASE-NOTES", "                     Apache Tomcat Version 9.0.83\n", 0o644)

	// Genian NAC: build tag in /.version (Docker image layout).
	write("usr/geni/centerd", string(tinyELF(t, "x", "", 0)), 0o755)
	write(".version", "NAC-CLOUD-R-117458-5.0.54.0720\n", 0o644)

	env := testEnv(root)
	sec := testCollector(env, Inputs{}, "/", Detectors...).run(context.Background())
	want := map[string]string{
		"/usr/geni/centerd":                  "5.0.54.0720",
		"/opt/jdk/bin/java":                  "17.0.21",
		"/opt/jdk8/jre/bin/java":             "1.8.0_512",
		"/usr/local/bin/ruby":                "3.3.14",
		"/usr/local/tomcat/lib/catalina.jar": "10.1.62",
		"/srv/tc9/lib/catalina.jar":          "9.0.83",
	}
	got := map[string]string{}
	for _, a := range sec.Artifacts {
		if a.Kind == report.ArtifactSoftware {
			if a.Method != report.MethodStatic {
				t.Errorf("%s: method %s", a.Path, a.Method)
			}
			got[a.Path] = a.Version
		}
	}
	for p, v := range want {
		if got[p] != v {
			t.Errorf("%s: version %q, want %q", p, got[p], v)
		}
	}
}

func TestEscapes(t *testing.T) {
	if got := expand("pkg:generic/x@{version}", "1.0+build 2", purlEscape); got != "pkg:generic/x@1.0%2Bbuild%202" {
		t.Errorf("purl = %q", got)
	}
	if got := expand("cpe:2.3:a:x:y:{version}:*", "1.0:rc1", cpeEscape); got != `cpe:2.3:a:x:y:1.0\:rc1:*` {
		t.Errorf("cpe = %q", got)
	}
	if got := expand("pkg:generic/x@{version}", "", purlEscape); got != "" {
		t.Errorf("empty version gives %q", got)
	}
}

// TestDetectorRealBinaries runs the static rules against real binaries in
// the directory named by BOMCENSUS_TEST_BINARIES, laid out as
// <detector-id>/<file>. It is a tool for writing new rules.
func TestDetectorRealBinaries(t *testing.T) {
	dir := os.Getenv("BOMCENSUS_TEST_BINARIES")
	if dir == "" {
		t.Skip("BOMCENSUS_TEST_BINARIES is not set")
	}
	c := newCollector(testEnv("/"), Inputs{})
	for _, d := range Detectors {
		files, _ := filepath.Glob(filepath.Join(dir, d.ID, "*"))
		for _, p := range files {
			if !d.matches(p) {
				continue
			}
			f, err := os.Open(p)
			if err != nil {
				t.Fatal(err)
			}
			fi, _ := f.Stat()
			var gi *goInfo
			if !d.Archive {
				gi = c.goInfo(f, fi)
			}
			m, ok := c.static(d, staticSource{logical: p, file: f, size: fi.Size(), goInfo: gi}, fi)
			f.Close()
			t.Logf("%s %s: %+v ok=%v", d.ID, p, m, ok)
		}
	}
}
