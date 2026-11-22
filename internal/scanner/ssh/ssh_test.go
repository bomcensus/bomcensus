// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/sign/signtest"
)

var (
	probeOnce sync.Once
	probeBin  []byte
	probeErr  error
)

// fakeProbeELF builds testdata/fakeprobe once per test binary.
func fakeProbeELF(t testing.TB, goarch string) []byte {
	t.Helper()
	if goarch != runtime.GOARCH {
		return buildFakeProbe(t, goarch)
	}
	probeOnce.Do(func() { probeBin, probeErr = buildFakeProbeErr(goarch) })
	if probeErr != nil {
		t.Fatal(probeErr)
	}
	return bytes.Clone(probeBin)
}

func buildFakeProbe(t testing.TB, goarch string) []byte {
	b, err := buildFakeProbeErr(goarch)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func buildFakeProbeErr(goarch string) ([]byte, error) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		return nil, fmt.Errorf("go toolchain not available: %w", err)
	}
	dir, err := os.MkdirTemp("", "fakeprobe-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	out := filepath.Join(dir, "fakeprobe")
	cmd := exec.Command(goBin, "build", "-trimpath", "-ldflags=-s -w", "-o", out, "./testdata/fakeprobe")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+goarch, "GOFLAGS=")
	if b, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("build fake probe: %w\n%s", err, b)
	}
	return os.ReadFile(out)
}

type fixture struct {
	tr     *signtest.Trust
	srv    *testServer
	key    []byte // client private key PEM
	pub    gossh.PublicKey
	signed []byte
	calls  int
}

func newKey(t *testing.T) ([]byte, gossh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	sp, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block), sp
}

func newFixture(t *testing.T, o serverOptions) *fixture {
	t.Helper()
	tr := signtest.Install(t)
	key, pub := newKey(t)
	if o.authorized == nil {
		o.authorized = pub
	}
	f := &fixture{tr: tr, key: key, pub: pub}
	f.srv = newTestServer(t, o)
	f.signed = tr.SignELF(t, fakeProbeELF(t, runtime.GOARCH))
	return f
}

func (f *fixture) target() Target {
	return Target{
		Address: f.srv.host(),
		Port:    f.srv.port(),
		User:    "scan",
		Auth:    Auth{PrivateKey: f.key},
		Request: report.Request{Sections: []string{"host", "packages"}, Policy: report.DefaultPolicy(), Cache: json.RawMessage(`{"k":1}`)},
		Timeout: time.Minute,
	}
}

func (f *fixture) deps(t *testing.T) Deps {
	return Deps{
		Probe: func(_ context.Context, goos, arch string) ([]byte, error) {
			f.calls++
			if goos != "linux" || arch != runtime.GOARCH {
				return nil, fmt.Errorf("unexpected platform %s/%s", goos, arch)
			}
			return f.signed, nil
		},
		Logger: slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelDebug})),
		dirs:   []string{"$XDG_RUNTIME_DIR", f.srv.tmp, "$HOME"},
	}
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

func checkReport(t *testing.T, res *Result, wantLevel string) {
	t.Helper()
	if res.Report == nil || res.Report.Host == nil {
		t.Fatalf("no report: %+v", res)
	}
	if got := res.Report.Host.Hostname; got != "fake:host,packages" {
		t.Errorf("hostname %q", got)
	}
	if res.Report.Subject != nil {
		t.Errorf("subject not cleared: %+v", res.Report.Subject)
	}
	if string(res.Report.Cache) != `{"k":1}` {
		t.Errorf("cache %q", res.Report.Cache)
	}
	if res.Report.Privilege.Level != wantLevel {
		t.Errorf("privilege %q, want %q", res.Report.Privilege.Level, wantLevel)
	}
	if !strings.Contains(res.Stderr, "fakeprobe: collected") {
		t.Errorf("stderr %q", res.Stderr)
	}
}

func checkClean(t *testing.T, srv *testServer) {
	t.Helper()
	if left := srv.leftovers(); len(left) > 0 {
		t.Errorf("probe files left on target: %v", left)
	}
}

func TestKeyAuthTrustOnFirstUse(t *testing.T) {
	f := newFixture(t, serverOptions{noise: true})
	res, err := Collect(context.Background(), f.target(), f.deps(t))
	if err != nil {
		t.Fatal(err)
	}
	checkReport(t, res, report.PrivilegeNonRoot)
	if !bytes.Equal(res.HostKey, f.srv.hostKeyWire()) {
		t.Error("returned host key differs from the server key")
	}
	if res.Privileged || res.SudoFallback != "" {
		t.Errorf("privileged %v, fallback %q", res.Privileged, res.SudoFallback)
	}
	if strings.Contains(res.Stderr, "stderr noise") == false {
		t.Errorf("stderr tail lost login output: %q", res.Stderr)
	}
	checkClean(t, f.srv)
	for _, c := range f.srv.recorded() {
		if strings.Contains(c, "\n") {
			t.Errorf("command contains a newline: %q", c)
		}
	}
}

func TestPasswordAuth(t *testing.T) {
	f := newFixture(t, serverOptions{password: "s3cret pass"})
	tg := f.target()
	tg.Auth = Auth{Password: "s3cret pass"}
	res, err := Collect(context.Background(), tg, f.deps(t))
	if err != nil {
		t.Fatal(err)
	}
	checkReport(t, res, report.PrivilegeNonRoot)
	checkClean(t, f.srv)

	tg.Auth = Auth{Password: "wrong"}
	if _, err := Collect(context.Background(), tg, f.deps(t)); err == nil {
		t.Fatal("wrong password accepted")
	}
}

func TestEncryptedKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := gossh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("phrase"))
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := gossh.NewPublicKey(priv.Public())
	f2 := newFixture(t, serverOptions{authorized: pub})
	tg := f2.target()
	tg.Auth = Auth{PrivateKey: pem.EncodeToMemory(block)}
	if _, err := Collect(context.Background(), tg, f2.deps(t)); err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Fatalf("missing passphrase: %v", err)
	}
	tg.Auth.Passphrase = []byte("phrase")
	if _, err := Collect(context.Background(), tg, f2.deps(t)); err != nil {
		t.Fatal(err)
	}
}

func TestPinnedHostKey(t *testing.T) {
	f := newFixture(t, serverOptions{})
	tg := f.target()

	tg.HostKey = f.srv.hostKeyWire()
	if _, err := Collect(context.Background(), tg, f.deps(t)); err != nil {
		t.Fatalf("wire format pin: %v", err)
	}
	tg.HostKey = gossh.MarshalAuthorizedKey(f.srv.hostKey.PublicKey())
	if _, err := Collect(context.Background(), tg, f.deps(t)); err != nil {
		t.Fatalf("authorized_keys pin: %v", err)
	}

	before := len(f.srv.recorded())
	_, other := newKey(t)
	tg.HostKey = other.Marshal()
	_, err := Collect(context.Background(), tg, f.deps(t))
	if !errors.Is(err, ErrHostKeyChanged) {
		t.Fatalf("want ErrHostKeyChanged, got %v", err)
	}
	var hk *HostKeyChangedError
	if !errors.As(err, &hk) {
		t.Fatalf("not a *HostKeyChangedError: %T", err)
	}
	if want := gossh.FingerprintSHA256(f.srv.hostKey.PublicKey()); hk.Fingerprint != want {
		t.Errorf("fingerprint %q, want %q", hk.Fingerprint, want)
	}
	if !bytes.Equal(hk.Key, f.srv.hostKeyWire()) {
		t.Error("error does not carry the offered key")
	}
	if n := len(f.srv.recorded()); n != before {
		t.Errorf("%d commands ran after a host key mismatch", n-before)
	}
}

func TestNoExecFallsThrough(t *testing.T) {
	f := newFixture(t, serverOptions{})
	f.srv.env = append(f.srv.env, "NOEXEC_DIR="+f.srv.xdg)
	res, err := Collect(context.Background(), f.target(), f.deps(t))
	if err != nil {
		t.Fatal(err)
	}
	checkReport(t, res, report.PrivilegeNonRoot)
	checkClean(t, f.srv)
	// The execute test runs before the upload, so the probe crossed the wire
	// only once (plus the small request).
	if n := f.srv.stdinBytes.Load(); n >= 2*int64(len(f.signed)) {
		t.Errorf("%d bytes uploaded for a %d byte probe", n, len(f.signed))
	}

	// Every candidate unusable.
	d := f.deps(t)
	d.dirs = []string{"$XDG_RUNTIME_DIR", "/nonexistent-dir", "$UNSET_VARIABLE"}
	_, err = Collect(context.Background(), f.target(), d)
	if !errors.Is(err, ErrNoExecDir) {
		t.Fatalf("want ErrNoExecDir, got %v", err)
	}
	if !strings.Contains(err.Error(), "noexec") {
		t.Errorf("reason missing: %v", err)
	}
	checkClean(t, f.srv)
}

func TestProbeRejectedNeverSent(t *testing.T) {
	f := newFixture(t, serverOptions{})
	unsigned := fakeProbeELF(t, runtime.GOARCH)
	tampered := bytes.Clone(f.signed)
	tampered[len(tampered)/2] ^= 0xff
	other := "arm64"
	if runtime.GOARCH == "arm64" {
		other = "amd64"
	}
	tr := signtest.NewTrust(t)
	cases := map[string][]byte{
		"unsigned":       unsigned,
		"tampered":       tampered,
		"foreign signer": tr.SignELF(t, unsigned),
		"wrong arch":     f.tr.SignELF(t, buildFakeProbe(t, other)),
	}
	for name, probe := range cases {
		t.Run(name, func(t *testing.T) {
			before := len(f.srv.recorded())
			d := f.deps(t)
			d.Probe = func(context.Context, string, string) ([]byte, error) { return probe, nil }
			bytesBefore := f.srv.stdinBytes.Load()
			_, err := Collect(context.Background(), f.target(), d)
			if !errors.Is(err, ErrProbeRejected) {
				t.Fatalf("want ErrProbeRejected, got %v", err)
			}
			cmds := f.srv.recorded()[before:]
			if len(cmds) != 1 || !strings.Contains(cmds[0], "uname") {
				t.Errorf("commands after rejection: %q", cmds)
			}
			if n := f.srv.stdinBytes.Load() - bytesBefore; n != 0 {
				t.Errorf("%d bytes sent", n)
			}
		})
	}
}

func TestProbeFailureCleansUp(t *testing.T) {
	f := newFixture(t, serverOptions{})
	tg := f.target()
	tg.Request.Policy.ExcludePaths = []string{"test:fail"}
	_, err := Collect(context.Background(), tg, f.deps(t))
	if err == nil || !strings.Contains(err.Error(), "failing on request") {
		t.Fatalf("want probe failure with stderr, got %v", err)
	}
	checkClean(t, f.srv)
}

func TestCancelMidRun(t *testing.T) {
	f := newFixture(t, serverOptions{})
	tg := f.target()
	tg.Request.Policy.ExcludePaths = []string{"test:sleep"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := Collect(ctx, tg, f.deps(t))
		done <- err
	}()
	pidFile := filepath.Join(f.srv.home, "probe.pid")
	var pid int
	deadline := time.Now().Add(30 * time.Second)
	for pid == 0 {
		if time.Now().After(deadline) {
			t.Fatal("probe did not start")
		}
		if b, err := os.ReadFile(pidFile); err == nil && len(b) > 0 {
			pid, _ = strconv.Atoi(string(b))
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(f.srv.leftovers()) != 1 {
		t.Fatalf("expected the uploaded probe while it runs, got %v", f.srv.leftovers())
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("want context.Canceled, got %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Collect did not return after cancellation")
	}
	checkClean(t, f.srv)
	if !waitGone(pid, 10*time.Second) {
		t.Errorf("probe process %d still running after cancellation", pid)
	}
}

// waitGone reports whether pid exits (or is a zombie) within d.
func waitGone(pid int, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			return true
		}
		if i := bytes.LastIndexByte(b, ')'); i > 0 && len(b) > i+2 && b[i+2] == 'Z' {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func TestReportSizeCap(t *testing.T) {
	f := newFixture(t, serverOptions{})
	tg := f.target()
	tg.Request.Policy.ExcludePaths = []string{"test:big"}
	d := f.deps(t)
	d.MaxReportBytes = 256 << 10
	_, err := Collect(context.Background(), tg, d)
	if !errors.Is(err, ErrReportTooLarge) {
		t.Fatalf("want ErrReportTooLarge, got %v", err)
	}
	checkClean(t, f.srv)
}

func TestSudo(t *testing.T) {
	const loginPW = "login pw 'quoted' $(x)"
	cases := []struct {
		name         string
		mode         string
		shimPassword string
		auth         func(f *fixture) Auth
		sudoPassword string
		privileged   bool
		fallback     string
	}{
		{name: "password", shimPassword: loginPW, auth: func(*fixture) Auth { return Auth{Password: loginPW} }, privileged: true},
		{name: "separate password", shimPassword: "other", auth: func(f *fixture) Auth { return Auth{PrivateKey: f.key} }, sudoPassword: "other", privileged: true},
		{name: "wrong password", shimPassword: "nope", auth: func(*fixture) Auth { return Auth{Password: loginPW} }, fallback: "password rejected"},
		{name: "nopasswd", mode: "nopasswd", auth: func(f *fixture) Auth { return Auth{PrivateKey: f.key} }, privileged: true},
		{name: "password required", auth: func(f *fixture) Auth { return Auth{PrivateKey: f.key} }, fallback: "a password is required"},
		{name: "refused", mode: "refuse", auth: func(*fixture) Auth { return Auth{Password: loginPW} }, fallback: "not in the sudoers file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, serverOptions{password: loginPW, env: map[string]string{
				"SUDO_SHIM_MODE": tc.mode, "SUDO_SHIM_PASSWORD": tc.shimPassword,
			}})
			tg := f.target()
			tg.Auth = tc.auth(f)
			tg.Sudo = true
			tg.SudoPassword = tc.sudoPassword
			res, err := Collect(context.Background(), tg, f.deps(t))
			if err != nil {
				t.Fatal(err)
			}
			want := report.PrivilegeNonRoot
			if tc.privileged {
				want = report.PrivilegePrivileged
			}
			checkReport(t, res, want)
			if res.Privileged != tc.privileged {
				t.Errorf("privileged %v", res.Privileged)
			}
			if tc.fallback == "" && res.SudoFallback != "" || !strings.Contains(res.SudoFallback, tc.fallback) {
				t.Errorf("fallback %q, want %q", res.SudoFallback, tc.fallback)
			}
			for _, pw := range []string{loginPW, tc.sudoPassword, tc.shimPassword} {
				if pw == "" {
					continue
				}
				for _, c := range f.srv.recorded() {
					if strings.Contains(c, pw) {
						t.Errorf("password in command line %q", c)
					}
				}
				if strings.Contains(res.Stderr, pw) || strings.Contains(res.SudoFallback, pw) {
					t.Errorf("password in captured output")
				}
			}
			checkClean(t, f.srv)
		})
	}
}

func TestUnsupportedPlatform(t *testing.T) {
	f := newFixture(t, serverOptions{})
	shim := filepath.Join(f.srv.sandbox, "shim", "uname")
	writeExec(t, shim, "#!/bin/sh\necho Linux riscv64\n")
	_, err := Collect(context.Background(), f.target(), f.deps(t))
	var pe *UnsupportedPlatformError
	if !errors.Is(err, ErrUnsupportedPlatform) || !errors.As(err, &pe) || pe.Machine != "riscv64" {
		t.Fatalf("want unsupported platform, got %v", err)
	}
	if f.calls != 0 {
		t.Error("probe requested for an unsupported platform")
	}
}

func TestCommandLines(t *testing.T) {
	scripts := map[string]string{
		"platform": platformScript,
		"transfer": "d=$XDG_RUNTIME_DIR; " + transferScript,
		"remove":   removeScript,
	}
	for _, m := range []sudoMode{{}, {enabled: true}, {enabled: true, password: "x"}} {
		scripts["collect"+m.prefix()] = strings.Replace(collectScript, runPlaceholder, m.prefix(), 1)
		scripts["sudocheck"+m.prefix()] = strings.Replace(sudoCheckScript, runPlaceholder, m.prefix(), 1)
	}
	for name, s := range scripts {
		cmd := shellCommand(s, "arg")
		if strings.ContainsAny(cmd, "\n\r") {
			t.Errorf("%s: newline in command line", name)
		}
		if strings.Contains(strings.ReplaceAll(cmd, `'\''`, ""), `\`) {
			t.Errorf("%s: backslash inside quotes: %s", name, cmd)
		}
		if out, err := exec.Command("/bin/sh", "-n", "-c", s).CombinedOutput(); err != nil {
			t.Errorf("%s: syntax: %v %s", name, err, out)
		}
	}
	for _, arg := range []string{"", "a b", "it's", `"$(id)"`, "`id`", `back\slash`, "-n", "line\nbreak", "*"} {
		out, err := exec.Command("/bin/sh", "-c", shellCommand(`printf %s "$1"`, arg)).Output()
		if err != nil || string(out) != arg {
			t.Errorf("quote %q: got %q, %v", arg, out, err)
		}
	}
	for _, d := range []string{"$XDG_RUNTIME_DIR", "/tmp", "/a/b-c_d.e"} {
		if !validDirExpr(d) {
			t.Errorf("%q rejected", d)
		}
	}
	for _, d := range []string{"tmp", "/tmp;rm", "$(id)", "/a b", "${X}"} {
		if validDirExpr(d) {
			t.Errorf("%q accepted", d)
		}
	}
}

func TestReportSinkSkipsNoise(t *testing.T) {
	s := newReportSink("M", 10)
	for _, p := range []string{"noise\nM", "\nabc", "def"} {
		if _, err := s.Write([]byte(p)); err != nil {
			t.Fatal(err)
		}
	}
	if out, ok := s.result(); !ok || string(out) != "abcdef" {
		t.Fatalf("got %q %v", out, ok)
	}
	if _, err := s.Write([]byte("12345")); err == nil || !s.overflowed() {
		t.Fatal("limit not enforced")
	}
}
