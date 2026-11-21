// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package updater

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/release"
	"github.com/bomcensus/bomcensus/internal/sign"
	"github.com/bomcensus/bomcensus/internal/sign/signtest"
)

// fileNames are the files of an agent installation; bundles also carry
// scannerName, which is not installed.
var fileNames = []string{"bomcensus-agent", "bomcensus-probe", "bomcensus-updater"}

const scannerName = "bomcensus-scanner"

type env struct {
	t       *testing.T
	trust   *signtest.Trust
	install string
	spool   string
	now     time.Time
	arch    string
	other   string
	signed  map[string][]byte
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Helper()
	w.t.Log(string(bytes.TrimRight(p, "\n")))
	return len(p), nil
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, now: time.Now(), arch: runtime.GOARCH, signed: map[string][]byte{}}
	switch e.arch {
	case "amd64":
		e.other = "arm64"
	case "arm64":
		e.other = "amd64"
	default:
		t.Skipf("unsupported test architecture %s", e.arch)
	}
	e.trust = signtest.Install(t)
	dir := t.TempDir()
	e.install = filepath.Join(dir, "install")
	e.spool = filepath.Join(dir, "spool")
	for _, d := range []string{e.install, e.spool} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func (e *env) elf(arch string) []byte {
	if b, ok := e.signed[arch]; ok {
		return b
	}
	b := e.trust.SignELF(e.t, signtest.ELF(e.t, arch))
	e.signed[arch] = b
	return b
}

func (e *env) opts() Options {
	return Options{
		InstallDir: e.install,
		Arch:       e.arch,
		Logger:     slog.New(slog.NewTextHandler(testWriter{e.t}, nil)),
		Now:        func() time.Time { return e.now },
	}
}

func (e *env) bundle(version string, archs ...string) []byte {
	e.t.Helper()
	m := &sign.Manifest{Version: version, IssuedAt: e.now.Add(-time.Minute), ExpiresAt: e.now.Add(24 * time.Hour)}
	var files []release.File
	for _, arch := range archs {
		data := e.elf(arch)
		for _, n := range append(slices.Clone(fileNames), scannerName) {
			files = append(files, release.File{OS: "linux", Arch: arch, Name: n, Data: data})
			m.Files = append(m.Files, signtest.FileEntry("linux", arch, n, data))
		}
	}
	mb, sig := e.trust.SignManifest(e.t, m)
	var buf bytes.Buffer
	if err := release.Write(context.Background(), &buf, mb, sig, files); err != nil {
		e.t.Fatal(err)
	}
	return buf.Bytes()
}

func (e *env) spoolFile(name string, data []byte) {
	e.t.Helper()
	if err := os.WriteFile(filepath.Join(e.spool, name), data, 0o644); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) put(version string) {
	e.t.Helper()
	e.spoolFile(BundleName(version), e.bundle(version, e.arch, e.other))
}

func (e *env) apply() *Result {
	e.t.Helper()
	res, err := Apply(context.Background(), e.opts(), e.spool)
	if err != nil {
		e.t.Fatalf("apply: %v", err)
	}
	return res
}

func (e *env) bootCheck() *Result {
	e.t.Helper()
	res, err := BootCheck(context.Background(), e.opts(), BootLimits{})
	if err != nil {
		e.t.Fatalf("boot-check: %v", err)
	}
	return res
}

func (e *env) state() *State {
	e.t.Helper()
	st, err := Status(context.Background(), e.install)
	if err != nil {
		e.t.Fatalf("status: %v", err)
	}
	return st
}

func (e *env) link() string {
	e.t.Helper()
	target, err := os.Readlink(filepath.Join(e.install, currentName))
	if err != nil {
		e.t.Fatal(err)
	}
	return target
}

func (e *env) versionDirs() []string {
	e.t.Helper()
	ents, err := os.ReadDir(filepath.Join(e.install, versionsDir))
	if err != nil {
		e.t.Fatal(err)
	}
	var out []string
	for _, d := range ents {
		out = append(out, d.Name())
	}
	return out
}

func (e *env) spoolNames() []string {
	e.t.Helper()
	ents, err := os.ReadDir(e.spool)
	if err != nil {
		e.t.Fatal(err)
	}
	var out []string
	for _, d := range ents {
		out = append(out, d.Name())
	}
	return out
}

// installConfirmed installs version and confirms it.
func (e *env) installConfirmed(version string) {
	e.t.Helper()
	e.put(version)
	if res := e.apply(); res.Installed != version {
		e.t.Fatalf("installed %q, want %s (rejected %v)", res.Installed, version, res.Rejected)
	}
	e.spoolFile(ConfirmName(version), nil)
	if res := e.apply(); res.Confirmed != version {
		e.t.Fatalf("confirmed %q, want %s", res.Confirmed, version)
	}
}

func wantState(t *testing.T, st *State, current, previous, pending string) {
	t.Helper()
	gotPending := ""
	if st.Pending != nil {
		gotPending = st.Pending.Version
	}
	if st.Current != current || st.Previous != previous || gotPending != pending {
		t.Fatalf("state current=%q previous=%q pending=%q, want %q %q %q", st.Current, st.Previous, gotPending, current, previous, pending)
	}
}

func TestApplyFresh(t *testing.T) {
	e := newEnv(t)
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)

	e.put("1.0.0")
	res := e.apply()
	if res.Installed != "1.0.0" || len(res.Rejected) != 0 {
		t.Fatalf("result %+v", res)
	}
	st := e.state()
	wantState(t, st, "1.0.0", "", "1.0.0")
	if st.Pending.Attempts != 0 || !st.Pending.Since.Equal(e.now.UTC()) {
		t.Fatalf("pending %+v", st.Pending)
	}
	if in := st.Installed["1.0.0"]; in.Source != SourceBundle || len(in.Files) != len(fileNames) {
		t.Fatalf("installed %+v", in)
	}
	if got := e.link(); got != "versions/1.0.0" {
		t.Fatalf("link %q", got)
	}
	if len(e.spoolNames()) != 0 {
		t.Fatalf("spool not emptied: %v", e.spoolNames())
	}
	dir := filepath.Join(e.install, "versions", "1.0.0")
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("version dir: %v %v", fi, err)
	}
	if _, err := os.Lstat(filepath.Join(dir, scannerName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s installed: %v", scannerName, err)
	}
	for _, n := range fileNames {
		p := filepath.Join(e.install, "current", n)
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm() != 0o755 {
			t.Fatalf("%s: %v %v", n, fi, err)
		}
		b, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(b, e.elf(e.arch)) {
			t.Fatalf("%s content differs", n)
		}
	}
	if fi, err := os.Stat(filepath.Join(e.install, stateName)); err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("state.json: %v %v", fi, err)
	}
}

func TestUpgradeFromBootstrapKeepsPrevious(t *testing.T) {
	e := newEnv(t)
	// Installer layout: one version directory, a link, no state.json.
	dir := filepath.Join(e.install, "versions", "1.0.0")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range fileNames {
		if err := os.WriteFile(filepath.Join(dir, n), e.elf(e.arch), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("versions/1.0.0", filepath.Join(e.install, "current")); err != nil {
		t.Fatal(err)
	}
	if st := e.state(); st.Current != "1.0.0" {
		t.Fatalf("derived current %q", st.Current)
	}

	e.put("1.1.0")
	if res := e.apply(); res.Installed != "1.1.0" {
		t.Fatalf("result %+v", res)
	}
	st := e.state()
	wantState(t, st, "1.1.0", "1.0.0", "1.1.0")
	if in, ok := st.Installed["1.0.0"]; !ok || in.Source != SourceAdopted {
		t.Fatalf("bootstrap version not adopted: %+v", st.Installed)
	}
	if got := e.versionDirs(); !slices.Equal(got, []string{"1.0.0", "1.1.0"}) {
		t.Fatalf("versions %v", got)
	}

	// The adopted version is a valid rollback target.
	e.spoolFile(RollbackName, nil)
	if res := e.apply(); res.RolledBack != "1.1.0" {
		t.Fatalf("result %+v", res)
	}
	wantState(t, e.state(), "1.0.0", "", "")
	if got := e.link(); got != "versions/1.0.0" {
		t.Fatalf("link %q", got)
	}
}

func TestOlderAndEqualRefused(t *testing.T) {
	e := newEnv(t)
	e.installConfirmed("1.1.0")
	before := e.state()

	e.put("1.0.0")
	e.put("1.1.0")
	e.put("1.1.0-rc.1")
	res := e.apply()
	if res.Installed != "" || len(res.Rejected) != 3 {
		t.Fatalf("result %+v", res)
	}
	if len(e.spoolNames()) != 0 {
		t.Fatalf("refused bundles not deleted: %v", e.spoolNames())
	}
	after := e.state()
	wantState(t, after, before.Current, before.Previous, "")
	if got := e.versionDirs(); !slices.Equal(got, []string{"1.1.0"}) {
		t.Fatalf("versions %v", got)
	}
}

func TestTamperedRefusedValidApplied(t *testing.T) {
	e := newEnv(t)
	e.installConfirmed("1.0.0")

	bad := e.bundle("1.2.0", e.arch)
	bad[len(bad)/2] ^= 0xff
	e.spoolFile(BundleName("1.2.0"), bad)
	// Valid content under a name that does not match the manifest.
	e.spoolFile(BundleName("1.3.0"), e.bundle("1.2.0", e.arch))
	e.put("1.1.0")

	res := e.apply()
	if res.Installed != "1.1.0" {
		t.Fatalf("result %+v", res)
	}
	if len(res.Rejected) != 2 {
		t.Fatalf("rejected %+v", res.Rejected)
	}
	if len(e.spoolNames()) != 0 {
		t.Fatalf("spool %v", e.spoolNames())
	}
	wantState(t, e.state(), "1.1.0", "1.0.0", "1.1.0")
}

func TestWrongArchitectureRefused(t *testing.T) {
	e := newEnv(t)
	e.installConfirmed("1.0.0")
	e.spoolFile(BundleName("1.1.0"), e.bundle("1.1.0", e.other))
	res := e.apply()
	if res.Installed != "" || len(res.Rejected) != 1 {
		t.Fatalf("result %+v", res)
	}
	if len(e.spoolNames()) != 0 {
		t.Fatalf("spool %v", e.spoolNames())
	}
	wantState(t, e.state(), "1.0.0", "", "")
}

func TestConfirmClearsPending(t *testing.T) {
	e := newEnv(t)
	e.installConfirmed("1.0.0")
	e.put("1.1.0")
	e.apply()

	e.spoolFile(ConfirmName("1.0.0"), nil)
	if res := e.apply(); res.Confirmed != "" {
		t.Fatalf("wrong version confirmed: %+v", res)
	}
	wantState(t, e.state(), "1.1.0", "1.0.0", "1.1.0")
	if len(e.spoolNames()) != 0 {
		t.Fatalf("spool %v", e.spoolNames())
	}

	e.spoolFile(ConfirmName("1.1.0"), []byte("ignored"))
	if res := e.apply(); res.Confirmed != "1.1.0" {
		t.Fatalf("result %+v", res)
	}
	wantState(t, e.state(), "1.1.0", "1.0.0", "")
	if res := e.bootCheck(); res.RolledBack != "" {
		t.Fatalf("boot-check without pending rolled back: %+v", res)
	}

	// A rollback request without a pending version is refused.
	e.spoolFile(RollbackName, nil)
	if res := e.apply(); res.RolledBack != "" {
		t.Fatalf("result %+v", res)
	}
	wantState(t, e.state(), "1.1.0", "1.0.0", "")
}

func (e *env) upgradePending() {
	e.t.Helper()
	e.installConfirmed("1.0.0")
	e.put("1.1.0")
	if res := e.apply(); res.Installed != "1.1.0" {
		e.t.Fatalf("result %+v", res)
	}
}

func TestBootCheckAttemptsRollback(t *testing.T) {
	e := newEnv(t)
	e.upgradePending()
	for i := 1; i <= DefaultMaxAttempts; i++ {
		if res := e.bootCheck(); res.RolledBack != "" {
			t.Fatalf("attempt %d rolled back", i)
		}
		if st := e.state(); st.Pending == nil || st.Pending.Attempts != i {
			t.Fatalf("attempt %d: pending %+v", i, st.Pending)
		}
	}
	if res := e.bootCheck(); res.RolledBack != "1.1.0" {
		t.Fatalf("result %+v", res)
	}
	st := e.state()
	wantState(t, st, "1.0.0", "", "")
	if len(st.Failed) != 1 || st.Failed[0].Version != "1.1.0" {
		t.Fatalf("failed %+v", st.Failed)
	}
	if _, ok := st.Installed["1.1.0"]; ok {
		t.Fatal("failed version still recorded as installed")
	}
	if got := e.link(); got != "versions/1.0.0" {
		t.Fatalf("link %q", got)
	}
	if got := e.versionDirs(); !slices.Equal(got, []string{"1.0.0"}) {
		t.Fatalf("versions %v", got)
	}
}

func TestBootCheckTimeoutRollback(t *testing.T) {
	e := newEnv(t)
	e.upgradePending()
	e.now = e.now.Add(DefaultPendingTimeout + time.Minute)
	if res := e.bootCheck(); res.RolledBack != "1.1.0" {
		t.Fatalf("result %+v", res)
	}
	wantState(t, e.state(), "1.0.0", "", "")
}

func TestRollbackRefusesTamperedPrevious(t *testing.T) {
	cases := map[string]func(t *testing.T, dir string){
		"modified": func(t *testing.T, dir string) {
			p := filepath.Join(dir, "bomcensus-agent")
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			b[len(b)-1] ^= 1
			if err := os.WriteFile(p, b, 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"extra file": func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "extra"), []byte("x"), 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"missing file": func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, "bomcensus-probe")); err != nil {
				t.Fatal(err)
			}
		},
		"replaced by symlink": func(t *testing.T, dir string) {
			p := filepath.Join(dir, "bomcensus-agent")
			moved := filepath.Join(t.TempDir(), "agent")
			if err := os.Rename(p, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(moved, p); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.upgradePending()
			tamper(t, filepath.Join(e.install, "versions", "1.0.0"))
			e.now = e.now.Add(DefaultPendingTimeout + time.Minute)
			if res := e.bootCheck(); res.RolledBack != "" {
				t.Fatalf("result %+v", res)
			}
			wantState(t, e.state(), "1.1.0", "1.0.0", "1.1.0")
			if got := e.link(); got != "versions/1.1.0" {
				t.Fatalf("link %q", got)
			}
		})
	}
}

// Version directories written before only agent files were installed hold
// the scanner too, recorded in state.json or not; they stay valid rollback
// targets.
func TestRollbackToVersionWithScanner(t *testing.T) {
	for _, recorded := range []bool{true, false} {
		t.Run(map[bool]string{true: "recorded", false: "unrecorded"}[recorded], func(t *testing.T) {
			e := newEnv(t)
			e.upgradePending()
			dir := filepath.Join(e.install, "versions", "1.0.0")
			if err := os.WriteFile(filepath.Join(dir, scannerName), e.elf(e.arch), 0o755); err != nil {
				t.Fatal(err)
			}
			if recorded {
				st := e.state()
				in := st.Installed["1.0.0"]
				in.Files[scannerName] = in.Files[AgentName]
				st.Installed["1.0.0"] = in
				b, err := json.Marshal(st)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(e.install, stateName), b, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			e.spoolFile(RollbackName, nil)
			if res := e.apply(); res.RolledBack != "1.1.0" {
				t.Fatalf("result %+v", res)
			}
			wantState(t, e.state(), "1.0.0", "", "")
		})
	}
	// A recorded scanner that is gone does not matter either.
	e := newEnv(t)
	e.upgradePending()
	st := e.state()
	in := st.Installed["1.0.0"]
	in.Files[scannerName] = in.Files[AgentName]
	b, _ := json.Marshal(st)
	if err := os.WriteFile(filepath.Join(e.install, stateName), b, 0o644); err != nil {
		t.Fatal(err)
	}
	e.spoolFile(RollbackName, nil)
	if res := e.apply(); res.RolledBack != "1.1.0" {
		t.Fatalf("result %+v", res)
	}
}

func TestAdoptBootstrapWithScanner(t *testing.T) {
	e := newEnv(t)
	dir := filepath.Join(e.install, "versions", "1.0.0")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range append(slices.Clone(fileNames), scannerName) {
		if err := os.WriteFile(filepath.Join(dir, n), e.elf(e.arch), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("versions/1.0.0", filepath.Join(e.install, "current")); err != nil {
		t.Fatal(err)
	}
	e.put("1.1.0")
	e.apply()
	in, ok := e.state().Installed["1.0.0"]
	if !ok || len(in.Files) != len(fileNames) {
		t.Fatalf("adopted %+v", in)
	}
	e.spoolFile(RollbackName, nil)
	if res := e.apply(); res.RolledBack != "1.1.0" {
		t.Fatalf("result %+v", res)
	}
}

func TestRollbackRefusesUnverifiedBootstrap(t *testing.T) {
	e := newEnv(t)
	dir := filepath.Join(e.install, "versions", "1.0.0")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Unsigned executable: the bootstrap version cannot be adopted.
	if err := os.WriteFile(filepath.Join(dir, "bomcensus-agent"), signtest.ELF(t, e.arch), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("versions/1.0.0", filepath.Join(e.install, "current")); err != nil {
		t.Fatal(err)
	}
	e.put("1.1.0")
	e.apply()
	st := e.state()
	wantState(t, st, "1.1.0", "1.0.0", "1.1.0")
	if _, ok := st.Installed["1.0.0"]; ok {
		t.Fatal("unsigned bootstrap version adopted")
	}
	e.spoolFile(RollbackName, nil)
	if res := e.apply(); res.RolledBack != "" {
		t.Fatalf("result %+v", res)
	}
	wantState(t, e.state(), "1.1.0", "1.0.0", "1.1.0")
}

func TestFailedVersionRemembered(t *testing.T) {
	e := newEnv(t)
	e.upgradePending()
	e.spoolFile(RollbackName, nil)
	if res := e.apply(); res.RolledBack != "1.1.0" {
		t.Fatalf("result %+v", res)
	}

	e.put("1.1.0")
	if res := e.apply(); res.Installed != "" || len(res.Rejected) != 1 {
		t.Fatalf("failed version installed again: %+v", res)
	}
	wantState(t, e.state(), "1.0.0", "", "")

	e.put("1.2.0")
	if res := e.apply(); res.Installed != "1.2.0" {
		t.Fatalf("result %+v", res)
	}
	st := e.state()
	wantState(t, st, "1.2.0", "1.0.0", "1.2.0")
	if len(st.Failed) != 0 {
		t.Fatalf("failed list not pruned: %+v", st.Failed)
	}
}

func TestUpgradeWhilePendingKeepsConfirmedPrevious(t *testing.T) {
	e := newEnv(t)
	e.upgradePending()
	e.put("1.2.0")
	e.apply()
	wantState(t, e.state(), "1.2.0", "1.0.0", "1.2.0")
	if got := e.versionDirs(); !slices.Equal(got, []string{"1.0.0", "1.2.0"}) {
		t.Fatalf("versions %v", got)
	}
}

func TestCleanupOlderVersions(t *testing.T) {
	e := newEnv(t)
	e.installConfirmed("1.0.0")
	e.installConfirmed("1.1.0")
	if err := os.Mkdir(filepath.Join(e.install, "versions", ".tmp-leftover"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.install, ".state.json.tmp-leftover"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	e.installConfirmed("1.2.0")
	if got := e.versionDirs(); !slices.Equal(got, []string{"1.1.0", "1.2.0"}) {
		t.Fatalf("versions %v", got)
	}
	if _, err := os.Lstat(filepath.Join(e.install, ".state.json.tmp-leftover")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary file left: %v", err)
	}
	st := e.state()
	wantState(t, st, "1.2.0", "1.1.0", "")
	if len(st.Installed) != 2 {
		t.Fatalf("installed %v", st.Installed)
	}
}

func TestSpoolEntries(t *testing.T) {
	e := newEnv(t)
	outside := filepath.Join(t.TempDir(), "bundle.tar")
	if err := os.WriteFile(outside, e.bundle("1.0.0", e.arch), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(e.spool, BundleName("1.0.0"))); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(e.spool, BundleName("1.1.0")), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(e.spool, BundleName("1.2.0")), 0o644); err != nil {
		t.Fatal(err)
	}
	unknown := []string{"notes.txt", ".bomcensus-1.3.0.tar.part", "bomcensus-latest.tar", "confirm-x"}
	for _, n := range unknown {
		e.spoolFile(n, []byte("x"))
	}
	res := e.apply()
	if res.Installed != "" || len(res.Rejected) != 3 {
		t.Fatalf("result %+v", res)
	}
	want := append([]string{BundleName("1.0.0"), BundleName("1.1.0"), BundleName("1.2.0")}, unknown...)
	slices.Sort(want)
	if got := e.spoolNames(); !slices.Equal(got, want) {
		t.Fatalf("spool %v, want %v", got, want)
	}
	if st := e.state(); st.Current != "" {
		t.Fatalf("state %+v", st)
	}
}

func TestLockPreventsConcurrentRuns(t *testing.T) {
	e := newEnv(t)
	s, err := openSession(context.Background(), e.opts())
	if err != nil {
		t.Fatal(err)
	}
	e.put("1.0.0")
	if _, err := Apply(context.Background(), e.opts(), e.spool); !errors.Is(err, ErrLocked) {
		t.Fatalf("apply while locked: %v", err)
	}
	if _, err := BootCheck(context.Background(), e.opts(), BootLimits{}); !errors.Is(err, ErrLocked) {
		t.Fatalf("boot-check while locked: %v", err)
	}
	if len(e.spoolNames()) != 1 {
		t.Fatal("spool touched while locked")
	}

	time.AfterFunc(200*time.Millisecond, s.close)
	o := e.opts()
	o.LockWait = 5 * time.Second
	res, err := Apply(context.Background(), o, e.spool)
	if err != nil || res.Installed != "1.0.0" {
		t.Fatalf("apply after unlock: %+v %v", res, err)
	}
}

func TestSwitchCurrentAtomic(t *testing.T) {
	e := newEnv(t)
	versions := []string{"1.0.0", "1.1.0"}
	for _, v := range versions {
		dir := filepath.Join(e.install, "versions", v)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, AgentName), []byte(v), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("versions/1.0.0", filepath.Join(e.install, currentName)); err != nil {
		t.Fatal(err)
	}
	s, err := openSession(context.Background(), e.opts())
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()

	// The reader resolves the link like Current does: read the target, then
	// open the file below it. Opening current/<file> in one path walk can
	// fail transiently with ENOENT while a rename replaces the link; that
	// happens with plain rename(2) too and is why Current exists.
	var stop atomic.Bool
	var reads, bad atomic.Int64
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			link := filepath.Join(e.install, currentName)
			for !stop.Load() {
				reads.Add(1)
				target, err := os.Readlink(link)
				if err != nil || (target != "versions/1.0.0" && target != "versions/1.1.0") {
					t.Logf("readlink %q %v", target, err)
					bad.Add(1)
					continue
				}
				v, dir, err := Current(context.Background(), e.install)
				if err != nil || !slices.Contains(versions, v) {
					t.Logf("current %q %v", v, err)
					bad.Add(1)
					continue
				}
				b, err := os.ReadFile(filepath.Join(dir, AgentName))
				if err != nil || string(b) != v {
					t.Logf("read %s: %q %v", dir, b, err)
					bad.Add(1)
				}
			}
		}()
	}
	for i := range 500 {
		if err := s.switchCurrent(versions[i%2]); err != nil {
			t.Fatal(err)
		}
	}
	stop.Store(true)
	wg.Wait()
	if bad.Load() != 0 {
		t.Fatalf("%d of %d reads saw an invalid current link", bad.Load(), reads.Load())
	}
	if reads.Load() == 0 {
		t.Fatal("reader did not run")
	}
	ents, err := os.ReadDir(e.install)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range ents {
		if d.Name() != currentName && d.Name() != versionsDir && d.Name() != lockName {
			t.Fatalf("leftover entry %q", d.Name())
		}
	}
}

func TestReconcileRepairsLink(t *testing.T) {
	e := newEnv(t)
	e.installConfirmed("1.0.0")
	e.put("1.1.0")
	e.apply()
	// Simulate a stop between writing the state and switching the link.
	link := filepath.Join(e.install, currentName)
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("versions/1.0.0", link); err != nil {
		t.Fatal(err)
	}
	e.apply()
	if got := e.link(); got != "versions/1.1.0" {
		t.Fatalf("link %q", got)
	}
}
