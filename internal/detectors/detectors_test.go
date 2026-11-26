// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package detectors

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/bomcensus/bomcensus/internal/report"
)

func TestBuiltin(t *testing.T) {
	b := Builtin()
	if len(b.Detectors) == 0 || BuiltinDigest() == "" {
		t.Fatal("empty built-in table")
	}
	// Every built-in entry would also pass as a supplied entry, so that an
	// administrator can start from a copy.
	for i := range b.Detectors {
		if err := checkSpec(&b.Detectors[i], true); err != nil {
			t.Errorf("%s: %v", b.Detectors[i].ID, err)
		}
	}
	r := Resolve(b)
	for _, e := range r.Entries {
		if !e.Builtin || e.Exec != (len(e.Spec.Exec) > 0) {
			t.Errorf("%s: %+v", e.Spec.ID, e)
		}
	}
	if r.Use.Digest != BuiltinDigest() || len(r.Entries) != len(b.Detectors) {
		t.Fatalf("use %+v", r.Use)
	}
}

// TestChartCopy keeps the Helm chart default equal to the source
// (make generate copies it).
func TestChartCopy(t *testing.T) {
	chart, err := os.ReadFile(filepath.Join("..", "..", "deploy", "charts", "bomcensus-manager", "files", "detectors.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(chart, builtinYAML) {
		t.Fatal("deploy/charts/bomcensus-manager/files/detectors.yaml differs from internal/detectors/detectors.yaml: run make generate")
	}
}

func TestRoundTrip(t *testing.T) {
	b := Builtin()
	enc, err := Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := Decode(enc)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := Encode(dec)
	if !bytes.Equal(enc, again) || !reflect.DeepEqual(dec, b) {
		t.Fatal("JSON round trip changed the table")
	}
	// JSON is YAML; comments and layout do not change the digest.
	fromJSON, err := Parse(enc)
	if err != nil {
		t.Fatal(err)
	}
	d1, _ := Digest(fromJSON)
	if d1 != BuiltinDigest() {
		t.Fatal("digest depends on the form")
	}
	stripped := regexpLines(builtinYAML)
	p, err := Parse(stripped)
	if err != nil {
		t.Fatal(err)
	}
	if d2, _ := Digest(p); d2 != BuiltinDigest() {
		t.Fatal("comments change the digest")
	}
}

// regexpLines drops the comment lines of a YAML text.
func regexpLines(b []byte) []byte {
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "#") {
			out = append(out, l)
		}
	}
	return []byte(strings.Join(out, "\n"))
}

func TestParseErrors(t *testing.T) {
	for name, text := range map[string]string{
		"unknown field":  "schema_version: 1\ndetectors:\n  - id: x\n    name: x\n    names: [x]\n    run: [sh]\n",
		"duplicate key":  "schema_version: 1\nschema_version: 1\ndetectors: []\n",
		"schema version": "schema_version: 2\ndetectors: []\n",
		"no schema":      "detectors: []\n",
		"not yaml":       "detectors: [\n",
		"too large":      "schema_version: 1\n#" + strings.Repeat("x", MaxYAMLSize) + "\ndetectors: []\n",
	} {
		if _, err := Parse([]byte(text)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := Decode([]byte(`{"schema_version":1,"detectors":[]} {}`)); err == nil {
		t.Error("trailing data accepted")
	}
	if _, err := Decode([]byte(`{"schema_version":1,"detectors":[{"id":"x","shell":"sh"}]}`)); err == nil {
		t.Error("unknown field accepted")
	}
}

func spec(id string) report.DetectorSpec {
	return report.DetectorSpec{ID: id, Name: id, Names: []string{id},
		Static: []report.DetectorStatic{{Rules: []report.DetectorRule{{Pattern: id + ` (\d+\.\d+)`}}}}}
}

func table(ds ...report.DetectorSpec) *report.DetectorTable {
	return &report.DetectorTable{SchemaVersion: report.DetectorSchemaVersion, Detectors: ds}
}

func builtinSpec(t *testing.T, id string) report.DetectorSpec {
	t.Helper()
	for _, d := range Builtin().Detectors {
		if d.ID == id {
			return d
		}
	}
	t.Fatalf("no built-in %s", id)
	return report.DetectorSpec{}
}

func entryOf(r Resolved, id string) *Entry {
	for i := range r.Entries {
		if r.Entries[i].Spec.ID == id {
			return &r.Entries[i]
		}
	}
	return nil
}

func rejected(r Resolved, id string) string {
	for _, x := range r.Use.Rejected {
		if x.ID == id {
			return x.Reason
		}
	}
	return ""
}

func TestResolveExec(t *testing.T) {
	// A shell with -c: not a built-in command, so it never runs.
	sh := report.DetectorSpec{ID: "shell", Name: "sh", Names: []string{"sh", "bash"},
		Exec: []string{"-c", "cat /etc/shadow"}, Parse: []report.DetectorRule{{Pattern: `(.+)`}}}
	shStatic := sh
	shStatic.ID = "shell2"
	shStatic.Static = []report.DetectorStatic{{Rules: []report.DetectorRule{{Pattern: `GNU bash, version (\d+\.\d+\.\d+)`}}}}

	// The openjdk command on another file name.
	java := builtinSpec(t, "openjdk")
	javaOnSh := java
	javaOnSh.Names = []string{"sh"}
	javaOnSh.Paths = nil
	// The openjdk command with another argument or environment.
	javaArgs := builtinSpec(t, "openjdk")
	javaArgs.Exec = append(slices.Clone(javaArgs.Exec), "-XX:OnError=sh")
	javaArgs.ID = "openjdk"
	// The openjdk command under another id.
	javaRenamed := builtinSpec(t, "openjdk")
	javaRenamed.ID = "java2"
	// The openjdk command unchanged, its parse rule changed.
	javaParse := builtinSpec(t, "nodejs")
	javaParse.Parse = []report.DetectorRule{{Pattern: `(?m)^v(\d+\.\d+\.\d+)`}}

	r := Resolve(table(sh, shStatic, javaOnSh, javaRenamed, javaParse))
	if rejected(r, "shell") == "" {
		t.Error("exec-only shell entry was not rejected")
	}
	if e := entryOf(r, "shell2"); e == nil || e.Exec || e.Builtin || len(e.Spec.Exec) > 0 || len(e.Spec.Parse) > 0 {
		t.Errorf("shell2: %+v", e)
	}
	if e := entryOf(r, "openjdk"); e == nil || e.Exec || len(e.Spec.Exec) > 0 || len(e.Spec.Env) > 0 || e.Spec.AddressSpaceMB != 0 {
		t.Errorf("openjdk on sh: %+v", e)
	}
	if e := entryOf(r, "java2"); e == nil || e.Exec || len(e.Spec.Exec) > 0 {
		t.Errorf("renamed openjdk: %+v", e)
	}
	if e := entryOf(r, "nodejs"); e == nil || !e.Exec || e.Builtin || len(e.Spec.Exec) == 0 {
		t.Errorf("nodejs with another parse rule: %+v", e)
	}
	if !slices.Equal(r.Use.StaticOnly, []string{"shell2", "openjdk", "java2"}) {
		t.Errorf("static only %v", r.Use.StaticOnly)
	}

	r = Resolve(table(javaArgs))
	if e := entryOf(r, "openjdk"); e == nil || e.Exec || len(e.Spec.Exec) > 0 {
		t.Errorf("openjdk with another argument: %+v", e)
	}
	javaEnv := builtinSpec(t, "openjdk")
	javaEnv.Env = []report.DetectorEnv{{Name: "LD_PRELOAD", Up: 2}}
	javaAS := builtinSpec(t, "openjdk")
	javaAS.AddressSpaceMB = 8192
	javaArchive := builtinSpec(t, "nodejs")
	javaArchive.Archive = true
	for _, d := range []report.DetectorSpec{javaEnv, javaAS, javaArchive} {
		r := Resolve(table(d))
		if e := entryOf(r, d.ID); e == nil || e.Exec {
			t.Errorf("%s with other exec fields: %+v", d.ID, e)
		}
	}
}

func TestResolveStatic(t *testing.T) {
	side := func(id, file string) report.DetectorSpec {
		d := spec(id)
		d.Static = []report.DetectorStatic{{File: file, Rules: []report.DetectorRule{{Pattern: `(\d+)`}}}}
		return d
	}
	entry := func(id, e string) report.DetectorSpec {
		d := spec(id)
		d.Archive = true
		d.Static = []report.DetectorStatic{{Entry: e, Rules: []report.DetectorRule{{Pattern: `(\d+)`}}}}
		return d
	}
	setting := func(id, key string) report.DetectorSpec {
		d := spec(id)
		d.Static = []report.DetectorStatic{{BuildSetting: key, Rules: []report.DetectorRule{{Pattern: `(\d+)`}}}}
		return d
	}
	limit := func(id, file string, n int64) report.DetectorSpec {
		d := side(id, file)
		d.Static[0].Limit = n
		return d
	}
	pattern := func(id, p string) report.DetectorSpec {
		d := spec(id)
		d.Static[0].Rules[0].Pattern = p
		return d
	}
	bad := []report.DetectorSpec{
		side("shadow-up", "../../../etc/shadow"),
		side("abs", "/etc/os-release"),
		side("shadow-near", "../shadow"),
		side("key", "../conf/server.key"),
		side("ssh", "../../.ssh/id_rsa"),
		side("unclean", "../lib/../../x"),
		side("dotdot-mid", "lib/../../../x"),
		side("only-up", "../.."),
		side("backslash", `..\..\x`),
		entry("entry-out", "../../etc/passwd"),
		entry("entry-app", "BOOT-INF/classes/application.properties"),
		entry("entry-abs", "/META-INF/MANIFEST.MF"),
		setting("setting", "-X main.secret"),
		setting("env-setting", "CGO_CFLAGS"),
		limit("huge-side", "../VERSION", SideFileLimit+1),
		limit("negative", "../VERSION", -1),
		pattern("no-group", `version \d+`),
		pattern("backref", `(\d+)\1`),
		pattern("lookahead", `(?=x)(\d+)`),
		pattern("build-only", `(?P<build>\d+)`),
		pattern("long", "("+strings.Repeat("a", MaxPatternLen)+")"),
		pattern("groups", strings.Repeat(`(\d)`, MaxGroups+1)),
		pattern("blowup", `((((\d{100}){100}){100}){100})`),
		{ID: "Upper", Name: "x", Names: []string{"x"}, Static: spec("x").Static},
		{ID: "slash-name", Name: "x", Names: []string{"bin/x"}, Static: spec("x").Static},
		{ID: "abs-path", Name: "x", Names: []string{"x"}, Paths: []string{"/usr/bin/x"}, Static: spec("x").Static},
		{ID: "no-names", Name: "x", Static: spec("x").Static},
		{ID: "every-file", Name: "x", Names: []string{"*"}, Static: spec("x").Static},
		{ID: "almost-every-file", Name: "x", Names: []string{"x*", "[a-z]?*"}, Static: spec("x").Static},
		{ID: "nothing", Name: "x", Names: []string{"x"}},
	}
	big := spec("huge-binary")
	big.Static[0].Limit = BinaryLimit + 1
	bad = append(bad, big)
	many := spec("many-rules")
	for range MaxRules + 1 {
		many.Static = append(many.Static, many.Static[0])
	}
	bad = append(bad, many)

	good := []report.DetectorSpec{
		side("up-two", "../../.version"),
		side("glob", "../lib/*/libfoo.so*"),
		entry("manifest", "META-INF/MANIFEST.MF"),
		entry("pom", "META-INF/maven/org.example/app/pom.properties"),
		setting("ldflags", "-ldflags"),
		limit("small", "../VERSION", 4096),
		pattern("named", `v(?P<version>\d+)-(?P<build>\d+)`),
	}
	r := Resolve(table(append(bad, good...)...))
	for _, d := range bad {
		if rejected(r, d.ID) == "" {
			t.Errorf("%s accepted", d.ID)
		}
	}
	for _, d := range good {
		if e := entryOf(r, d.ID); e == nil || e.Builtin {
			t.Errorf("%s: %+v (%s)", d.ID, e, rejected(r, d.ID))
		}
	}
	if len(r.Entries) != len(good) {
		t.Errorf("entries %d", len(r.Entries))
	}

	dup := Resolve(table(spec("aa"), spec("aa")))
	if len(dup.Entries) != 1 || rejected(dup, "aa") != "duplicate id" {
		t.Errorf("duplicate: %+v", dup)
	}
}

func TestResolveTable(t *testing.T) {
	var ds []report.DetectorSpec
	for i := range MaxDetectors + 1 {
		ds = append(ds, spec("d"+strings.Repeat("x", i%3)+string(rune('a'+i%26))))
	}
	for name, tb := range map[string]*report.DetectorTable{
		"too many": table(ds...),
		"schema":   {SchemaVersion: 7, Detectors: []report.DetectorSpec{spec("a")}},
		"too large": table(report.DetectorSpec{ID: "big", Name: "big", Names: []string{"big"},
			PURL: strings.Repeat("x", MaxJSONSize)}),
	} {
		r := Resolve(tb)
		if r.Use.Source != report.DetectorsBuiltin || r.Use.Error == "" || r.Use.Digest != BuiltinDigest() ||
			len(r.Entries) != len(Builtin().Detectors) {
			t.Errorf("%s: %+v", name, r.Use)
		}
	}
	r := Resolve(nil)
	if r.Use.Source != report.DetectorsBuiltin || r.Use.Error != "" {
		t.Errorf("nil: %+v", r.Use)
	}
}

func TestDeniedPath(t *testing.T) {
	for p, want := range map[string]bool{
		"/etc/shadow": true, "/etc/gshadow": true, "/root/x": true, "/home/u/app/VERSION": true,
		"/proc/self/environ": true, "/sys/kernel/x": true, "/var/lib/kubelet/pods/x/volumes/secret/token": true,
		"/run/secrets/kubernetes.io/serviceaccount/token": true, "/etc/ssh/ssh_host_ed25519_key": true,
		"/opt/app/conf/server.KEY": true, "/opt/app/tls.pem": true, "/opt/app/.env": true, "/opt/app/db_password.txt": true,
		"/var/lib/bomcensus-agent/identity": true, "relative": true, "/opt/x/../../root/y": true,
		"/.version": false, "/opt/jdk/release": false, "/usr/local/tomcat/RELEASE-NOTES": false,
		"/usr/lib/libpython3.12.so.1.0": false, "/etc/os-release": false, "/opt/homebrew": false,
	} {
		if got := DeniedPath(p); got != want {
			t.Errorf("DeniedPath(%q) = %v", p, got)
		}
	}
}

func TestValidCaptured(t *testing.T) {
	for s, want := range map[string]bool{
		"5.0.54.0720": true, "117458": true, "1.8.0_512": true, "2:1.2.3-1ubuntu1": true, "1.0+git~1": true,
		"": false, "v1.2": false, "1.2 3": false, "1.2/3": false, "1.2$": false, "1" + strings.Repeat("0", MaxCapturedLen): false,
		"1\x00": false, "1é": false,
	} {
		if got := ValidCaptured(s); got != want {
			t.Errorf("ValidCaptured(%q) = %v", s, got)
		}
	}
}

func TestCheck(t *testing.T) {
	yamlText := `schema_version: 1
detectors:
  - id: openjdk
    name: openjdk
    names: [java]
    exec: ['-version']
    parse:
      - pattern: '(\d+)'
    static:
      - file: '../release'
        rules:
          - pattern: 'JAVA_VERSION="([^"]+)"'
  - id: leak
    name: leak
    names: [x]
    static:
      - file: '../../../etc/shadow'
        rules:
          - pattern: 'root:([^:]+)'
`
	tb, probs := Check([]byte(yamlText))
	if tb == nil || len(probs) != 2 {
		t.Fatalf("problems %+v", probs)
	}
	if probs[0].Index != 0 || !probs[0].Warning || probs[1].Index != 1 || probs[1].Warning || probs[1].ID != "leak" {
		t.Fatalf("problems %+v", probs)
	}
	if _, probs := Check([]byte("schema_version: 1\ndetectors: []\n")); len(probs) != 1 || probs[0].Index != -1 {
		t.Fatalf("empty: %+v", probs)
	}
	if _, probs := Check(BuiltinYAML()); len(probs) != 0 {
		t.Fatalf("built-in: %+v", probs)
	}
}
