// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package ssh collects a report from a Linux host over SSH without an
// installed agent: it connects, uploads the signed probe over a session's
// standard input, runs it (optionally through sudo), reads the encoded report
// from its standard output and removes the uploaded file again.
//
// Remote commands are always run as "exec /bin/sh -c '<script>' sh <args>",
// so the login shell only has to parse one single-quoted word and a few
// arguments. Scripts contain no newlines and no backslashes inside quotes, so
// POSIX login shells and fish both pass them through unchanged; csh-family
// login shells are not supported. Every value that comes from outside the
// package (file names, markers, sizes, digests, remote paths) is passed as a
// quoted positional parameter, never spliced into the script text. The only
// spliced text is the candidate directory, a constant validated against a
// strict pattern.
//
// The login account is trusted: code running as that account (for example
// from its shell start-up files) can observe the sudo password or replace the
// uploaded file before it is executed.
package ssh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/sign"
)

// DefaultTimeout bounds one collection when Target.Timeout is zero.
const DefaultTimeout = 30 * time.Minute

// DefaultMaxReportBytes bounds the encoded report read from the probe when
// Deps.MaxReportBytes is zero.
const DefaultMaxReportBytes = 256 << 20

// Auth holds the credentials for one SSH login. A private key, a password or
// both may be given; the key is tried first.
type Auth struct {
	// PrivateKey is a PEM encoded private key (OpenSSH, PKCS#1, PKCS#8 or
	// SEC 1).
	PrivateKey []byte
	// Passphrase decrypts PrivateKey when it is encrypted.
	Passphrase []byte
	// Password is used for the "password" and "keyboard-interactive"
	// methods.
	Password string
}

// Target describes the host to collect from.
type Target struct {
	Address string
	// Port defaults to 22.
	Port int
	User string
	Auth Auth
	// Sudo runs the probe through sudo. When sudo is unavailable or refused
	// the probe runs without it and Result.SudoFallback says why.
	Sudo bool
	// SudoPassword is sent to sudo when it asks for one. Empty means
	// Auth.Password.
	SudoPassword string
	// HostKey is the pinned host key, either in SSH wire format or as an
	// authorized_keys line. Empty means trust on first use: any key is
	// accepted and returned in Result.HostKey for the caller to pin.
	HostKey []byte
	// Request is written to the probe's standard input.
	Request report.Request
	// Timeout bounds the whole collection. Zero means DefaultTimeout.
	Timeout time.Duration
}

// Deps are the collaborators supplied by the caller.
type Deps struct {
	// Probe returns the signed probe executable for a platform ("linux",
	// "amd64" or "arm64"). The bytes are verified before anything is sent.
	Probe func(ctx context.Context, goos, arch string) ([]byte, error)
	// Logger receives progress at debug level. Nil discards.
	Logger *slog.Logger
	// MaxReportBytes bounds the encoded report. Zero means
	// DefaultMaxReportBytes.
	MaxReportBytes int64

	// dirs replaces defaultDirs in tests.
	dirs []string
}

// Result is a successful collection.
type Result struct {
	// Report is the decoded probe output. Subject is always nil: whatever
	// the remote side put there is discarded and the caller fills it in.
	Report *report.Report
	// HostKey is the target's host key in SSH wire format. When no key was
	// pinned the caller should store it.
	HostKey []byte
	// Privileged is true when the probe ran as root (through sudo or because
	// the login user is root).
	Privileged bool
	// SudoFallback is set when Target.Sudo was requested but sudo could not
	// be used; the report then has non-root coverage.
	SudoFallback string
	Duration     time.Duration
	// Stderr is the tail of the probe's standard error.
	Stderr string
}

var (
	// ErrHostKeyChanged is matched by a *HostKeyChangedError.
	ErrHostKeyChanged = errors.New("ssh: host key does not match the pinned key")
	// ErrUnsupportedPlatform is matched by a *UnsupportedPlatformError.
	ErrUnsupportedPlatform = errors.New("ssh: unsupported remote platform")
	// ErrProbeRejected means the probe from Deps.Probe failed verification.
	// Nothing was sent to the target.
	ErrProbeRejected = errors.New("ssh: probe rejected")
	// ErrNoExecDir means no candidate directory allowed creating and
	// executing the probe.
	ErrNoExecDir = errors.New("ssh: no directory on the target can hold an executable probe")
	// ErrReportTooLarge means the probe wrote more than the report limit.
	ErrReportTooLarge = errors.New("ssh: report exceeds the size limit")
)

// HostKeyChangedError reports a host key that differs from the pinned one.
type HostKeyChangedError struct {
	Address string
	// Fingerprint is the SHA256 fingerprint of the offered key
	// ("SHA256:<base64>").
	Fingerprint string
	// Key is the offered key in SSH wire format.
	Key []byte
}

func (e *HostKeyChangedError) Error() string {
	return fmt.Sprintf("ssh: host key of %s changed: offered %s does not match the pinned key", e.Address, e.Fingerprint)
}

func (e *HostKeyChangedError) Is(target error) bool { return target == ErrHostKeyChanged }

// UnsupportedPlatformError reports the output of uname on an unsupported
// target.
type UnsupportedPlatformError struct {
	Kernel  string
	Machine string
}

func (e *UnsupportedPlatformError) Error() string {
	return fmt.Sprintf("ssh: unsupported remote platform %q %q", e.Kernel, e.Machine)
}

func (e *UnsupportedPlatformError) Is(target error) bool { return target == ErrUnsupportedPlatform }

// Collect runs the probe on target and returns its report. See the package
// documentation and SECURITY.md section 5.3 for the procedure.
func Collect(ctx context.Context, target Target, deps Deps) (*Result, error) {
	begin := time.Now()
	if err := validateTarget(&target); err != nil {
		return nil, err
	}
	if deps.Probe == nil {
		return nil, errors.New("ssh: Deps.Probe is required")
	}
	dirs := deps.dirs
	if dirs == nil {
		dirs = defaultDirs
	}
	for _, d := range dirs {
		if !validDirExpr(d) {
			return nil, fmt.Errorf("ssh: invalid candidate directory %q", d)
		}
	}
	log := deps.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	log = log.With("target", target.addr())
	maxReport := deps.MaxReportBytes
	if maxReport <= 0 {
		maxReport = DefaultMaxReportBytes
	}
	payload, err := json.Marshal(target.Request)
	if err != nil {
		return nil, fmt.Errorf("ssh: encode request: %w", err)
	}
	timeout := target.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	c, err := dial(ctx, &target, log)
	if err != nil {
		return nil, err
	}
	defer c.close()
	res := &Result{HostKey: c.hostKey}

	plat, err := c.platform(ctx)
	if err != nil {
		return nil, err
	}
	log.Debug("remote platform", "arch", plat.arch, "uid", plat.uid)

	raw, err := deps.Probe(ctx, "linux", plat.arch)
	if err != nil {
		return nil, fmt.Errorf("ssh: get probe for linux/%s: %w", plat.arch, err)
	}
	// Verify and send a private copy, so the caller cannot change the bytes
	// between verification and transfer.
	probe := bytes.Clone(raw)
	if err := verifyProbe(probe, plat.arch); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(probe)
	digest := hex.EncodeToString(sum[:])

	mode := sudoMode{}
	if plat.uid == 0 {
		res.Privileged = true
	} else if target.Sudo {
		mode = sudoMode{enabled: true, password: target.sudoPassword()}
		if err := c.checkSudo(ctx, mode); err != nil {
			if !errors.Is(err, errSudoRefused) {
				return nil, err
			}
			log.Info("sudo unavailable, collecting without privileges", "reason", err)
			res.SudoFallback = err.Error()
			mode = sudoMode{}
		}
	}

	var out []byte
	var stderr string
	for {
		out, stderr, err = c.transferAndRun(ctx, dirs, probe, digest, mode, payload, maxReport)
		if mode.enabled && errors.Is(err, errSudoRefused) {
			log.Info("sudo refused at run time, collecting without privileges", "reason", err)
			res.SudoFallback = err.Error()
			mode = sudoMode{}
			continue
		}
		break
	}
	if err != nil {
		return nil, err
	}
	if mode.enabled {
		res.Privileged = true
	}
	rep, err := report.Decode(bytes.NewReader(out))
	if err != nil {
		return nil, fmt.Errorf("ssh: probe output: %w", err)
	}
	rep.Subject = nil
	res.Report = rep
	res.Stderr = stderr
	res.Duration = time.Since(begin)
	return res, nil
}

// transferAndRun uploads the probe, runs it and removes every file it
// created, whatever the outcome.
func (c *conn) transferAndRun(ctx context.Context, dirs []string, probe []byte, digest string, mode sudoMode, payload []byte, maxReport int64) ([]byte, string, error) {
	path, created, err := c.transfer(ctx, dirs, probe, digest)
	defer c.remove(ctx, created)
	if err != nil {
		return nil, "", err
	}
	return c.runProbe(ctx, path, mode, payload, maxReport)
}

func (t *Target) sudoPassword() string {
	if t.SudoPassword != "" {
		return t.SudoPassword
	}
	return t.Auth.Password
}

func validateTarget(t *Target) error {
	if t.Address == "" {
		return errors.New("ssh: target address is required")
	}
	if t.User == "" {
		return errors.New("ssh: target user is required")
	}
	if t.Port < 0 || t.Port > 65535 {
		return fmt.Errorf("ssh: target port %d out of range", t.Port)
	}
	if len(t.Auth.PrivateKey) == 0 && t.Auth.Password == "" {
		return errors.New("ssh: target needs a private key or a password")
	}
	if t.Sudo && strings.ContainsAny(t.sudoPassword(), "\r\n\x00") {
		return errors.New("ssh: sudo password must not contain line breaks or NUL")
	}
	return nil
}

// verifyProbe checks the code signature and that the executable matches the
// remote architecture.
func verifyProbe(data []byte, arch string) error {
	if err := sign.VerifyELF(data); err != nil {
		return fmt.Errorf("%w: %w", ErrProbeRejected, err)
	}
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrProbeRejected, err)
	}
	defer f.Close()
	want := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}[arch]
	if f.Machine != want {
		return fmt.Errorf("%w: executable is for %v, target is %s", ErrProbeRejected, f.Machine, arch)
	}
	return nil
}
