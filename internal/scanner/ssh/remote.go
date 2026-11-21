// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package ssh

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// defaultDirs are tried in order for the uploaded probe. Entries are either
// an absolute path or a variable reference expanded by the remote shell;
// they are constants and the only text spliced into a script.
var defaultDirs = []string{"$XDG_RUNTIME_DIR", "/tmp", "/var/tmp", "/dev/shm", "$HOME"}

var dirExprRe = regexp.MustCompile(`^(\$[A-Z_][A-Z0-9_]*|/[A-Za-z0-9._/+-]*)$`)

func validDirExpr(s string) bool { return dirExprRe.MatchString(s) }

// probeFilePrefix names uploaded files. Leftovers older than an hour with
// this prefix and owned by the login user are removed by later transfers.
const probeFilePrefix = ".bomcensus-probe-"

var remotePathRe = regexp.MustCompile(`^/[A-Za-z0-9._/+-]*/\.bomcensus-probe-[0-9a-f]{32}$`)

const (
	controlOutputLimit = 64 << 10
	stderrTailLimit    = 16 << 10
	errorTailLimit     = 1 << 10
	sudoStartTimeout   = 30 * time.Second
	cleanupTimeout     = 15 * time.Second
)

// Exit codes of transferScript.
const (
	exitDirUnusable = 64
	exitCreate      = 65
	exitNoExec      = 66
	exitWrite       = 67
	exitSize        = 68
	exitDigest      = 69
	exitVersion     = 70
)

// platformScript prints a marker line, then "uname -s -m" and "id -u".
// $1 marker.
const platformScript = `echo "$1"; uname -s -m; id -u`

// transferScript creates the probe file in directory d (spliced in as
// "d=<expr>; " in front), checks that files there can be executed, writes
// standard input to it and verifies it. Every status line starts with the
// marker so that output from login scripts is ignored.
//
// $1 file name, $2 marker, $3 expected size, $4 expected SHA-256 (hex).
//
// The execute test runs a two-line shell script before the probe is sent, so
// a noexec mount costs one round trip instead of a full upload. set -C makes
// the redirection fail on an existing file (O_EXCL). The EXIT trap removes
// the file unless the transfer completed.
const transferScript = `umask 077; ` +
	`case $d in /*) ;; *) exit 64;; esac; ` +
	`case $d in *[!A-Za-z0-9._/+-]*) exit 64;; esac; ` +
	`[ -d "$d" ] && [ -w "$d" ] && [ -x "$d" ] || exit 64; ` +
	`find "$d" -maxdepth 1 -name "` + probeFilePrefix + `*" -user "$(id -u)" -mmin +60 -exec rm -f {} + >/dev/null 2>&1; ` +
	`f="$d/$1"; ` +
	`set -C; echo "#!/bin/sh" > "$f" || exit 65; set +C; ` +
	`trap '[ -n "$ok" ] || rm -f "$f"' EXIT; trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM; ` +
	`echo "$2 path $f"; ` +
	`chmod 700 "$f" && "$f" </dev/null >/dev/null 2>&1 || exit 66; ` +
	`echo "$2 ready"; ` +
	`cat > "$f" || exit 67; ` +
	`n=$(wc -c < "$f" | tr -d " "); echo "$2 size $n"; [ "$n" = "$3" ] || exit 68; ` +
	`if command -v sha256sum >/dev/null 2>&1; then s=$(sha256sum < "$f"); s=${s%% *}; echo "$2 sha256 $s"; [ "$s" = "$4" ] || exit 69; fi; ` +
	`chmod 700 "$f" && "$f" version </dev/null >/dev/null 2>&1 || exit 70; ` +
	`ok=1; echo "$2 ok"`

// runPlaceholder is replaced by "", sudoNoPassword or sudoWithPassword.
const runPlaceholder = "@RUN@"

const (
	sudoNoPassword = `sudo -n -- `
	// The prompt is a random marker ($2) so the client can tell that sudo
	// waits for the password, instead of guessing from an empty prompt.
	sudoWithPassword = `sudo -S -p "$2" -- `
)

// collectScript runs the probe in the background and waits for it, so that
// a TERM, HUP or INT (for example a signal request on cancellation) kills the
// probe and the EXIT trap removes the file. The inner shell, which runs
// after sudo has accepted, prints the start marker on both streams before it
// executes the probe: the client sends the request only after seeing it on
// standard error and discards standard output up to it. Standard input is
// passed to the background job through fd 3 because a non-interactive shell
// connects background jobs to /dev/null otherwise.
//
// $1 start marker, $2 sudo prompt marker, $3 probe path.
const collectScript = `f=$3; ` +
	`trap 'rm -f "$f"' EXIT; ` +
	`trap 'kill "$p" 2>/dev/null; exit 129' HUP; ` +
	`trap 'kill "$p" 2>/dev/null; exit 130' INT; ` +
	`trap 'kill "$p" 2>/dev/null; exit 143' TERM; ` +
	`exec 3<&0; ` +
	runPlaceholder + `/bin/sh -c 'echo "$1"; echo "$1" >&2; exec "$2" collect' sh "$1" "$f" <&3 3<&- & ` +
	`p=$!; wait "$p"; r=$?; exit "$r"`

// sudoCheckScript tests whether sudo accepts. $1 start marker, $2 prompt
// marker.
const sudoCheckScript = runPlaceholder + `/bin/sh -c 'echo "$1" >&2' sh "$1"`

// removeScript removes the given files.
const removeScript = `rm -f -- "$@"`

// shellQuote quotes s for a POSIX shell.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// shellCommand returns the command line that runs script with /bin/sh and
// the given positional parameters. The login shell execs /bin/sh, so a
// signal request reaches the script (not every shell does that by itself
// for a single command).
func shellCommand(script string, args ...string) string {
	var b strings.Builder
	b.WriteString("exec /bin/sh -c ")
	b.WriteString(shellQuote(script))
	b.WriteString(" sh")
	for _, a := range args {
		b.WriteByte(' ')
		b.WriteString(shellQuote(a))
	}
	return b.String()
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type platform struct {
	arch string
	uid  int
}

func (c *conn) platform(ctx context.Context) (platform, error) {
	marker := randomHex(16)
	out, errOut, status, err := c.output(ctx, shellCommand(platformScript, marker))
	if err != nil {
		return platform{}, fmt.Errorf("ssh: detect platform: %w", err)
	}
	if status != 0 {
		return platform{}, fmt.Errorf("ssh: detect platform: exit status %d: %s", status, tail(errOut, errorTailLimit))
	}
	lines := linesAfter(out, marker)
	if len(lines) < 2 {
		return platform{}, fmt.Errorf("ssh: detect platform: unexpected output %q", tail(out, errorTailLimit))
	}
	fields := strings.Fields(lines[0])
	if len(fields) != 2 {
		return platform{}, fmt.Errorf("ssh: detect platform: unexpected uname output %q", lines[0])
	}
	uid, err := strconv.Atoi(strings.TrimSpace(lines[1]))
	if err != nil {
		return platform{}, fmt.Errorf("ssh: detect platform: unexpected id output %q", lines[1])
	}
	arch := ""
	if fields[0] == "Linux" {
		switch fields[1] {
		case "x86_64", "amd64":
			arch = "amd64"
		case "aarch64", "arm64":
			arch = "arm64"
		}
	}
	if arch == "" {
		return platform{}, &UnsupportedPlatformError{Kernel: fields[0], Machine: fields[1]}
	}
	return platform{arch: arch, uid: uid}, nil
}

// output runs a short command with empty standard input.
func (c *conn) output(ctx context.Context, cmd string) ([]byte, []byte, int, error) {
	out := newStreamBuffer(controlOutputLimit, 0)
	errOut := newStreamBuffer(controlOutputLimit, errorTailLimit)
	p, err := c.start(ctx, cmd, out, errOut, nil)
	if err != nil {
		return nil, nil, -1, err
	}
	defer p.release()
	_ = p.stdin.Close()
	status, err := p.wait(ctx)
	return out.head(), errOut.tailBytes(), status, err
}

// linesAfter returns the lines that follow the first line equal to marker.
func linesAfter(out []byte, marker string) []string {
	var lines []string
	found := false
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if !found {
			found = sc.Text() == marker
			continue
		}
		lines = append(lines, sc.Text())
	}
	return lines
}

// markedLines returns "key value" pairs from lines starting with marker.
func markedLines(out []byte, marker string) map[string]string {
	m := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		rest, ok := strings.CutPrefix(sc.Text(), marker+" ")
		if !ok {
			continue
		}
		k, v, _ := strings.Cut(rest, " ")
		if _, dup := m[k]; !dup {
			m[k] = v
		}
	}
	return m
}

// transfer uploads probe into the first usable candidate directory. It
// returns the remote path and every path that may have been created, which
// the caller removes in any case.
func (c *conn) transfer(ctx context.Context, dirs []string, probe []byte, digest string) (string, []string, error) {
	var created []string
	var reasons []string
	for _, dir := range dirs {
		path, made, err := c.transferTo(ctx, dir, probe, digest)
		if made != "" {
			created = append(created, made)
		}
		if err == nil {
			c.log.Debug("probe uploaded", "path", path, "bytes", len(probe))
			return path, created, nil
		}
		if ctx.Err() != nil {
			return "", created, ctx.Err()
		}
		var ce *candidateError
		if !errors.As(err, &ce) {
			return "", created, err
		}
		c.log.Debug("candidate directory rejected", "dir", dir, "reason", ce.reason)
		reasons = append(reasons, dir+": "+ce.reason)
	}
	return "", created, fmt.Errorf("%w (%s)", ErrNoExecDir, strings.Join(reasons, "; "))
}

// candidateError means this directory cannot be used and the next one
// should be tried.
type candidateError struct{ reason string }

func (e *candidateError) Error() string { return e.reason }

func (c *conn) transferTo(ctx context.Context, dir string, probe []byte, digest string) (path, created string, err error) {
	marker := randomHex(16)
	name := probeFilePrefix + randomHex(16)
	cmd := shellCommand("d="+dir+"; "+transferScript, name, marker, strconv.Itoa(len(probe)), digest)
	out := newStreamBuffer(controlOutputLimit, 0)
	errOut := newStreamBuffer(controlOutputLimit, errorTailLimit)
	p, err := c.start(ctx, cmd, out, errOut, nil)
	if err != nil {
		return "", "", err
	}
	defer p.release()

	ready := []byte(marker + " ready\n")
	exited := false
	for !exited && !bytes.Contains(out.head(), ready) {
		select {
		case <-out.changed:
		case <-p.done:
			exited = true
		case <-ctx.Done():
			p.abort()
			return "", pathFrom(out.head(), marker), ctx.Err()
		}
	}
	if bytes.Contains(out.head(), ready) {
		// Write exactly the verified bytes, then signal end of file.
		if _, werr := p.stdin.Write(probe); werr != nil {
			c.log.Debug("probe upload interrupted", "error", werr)
		}
	}
	_ = p.stdin.Close()
	status, err := p.wait(ctx)
	head := out.head()
	created = pathFrom(head, marker)
	if err != nil {
		return "", created, err
	}
	stderr := strings.TrimSpace(string(errOut.tailBytes()))
	fail := func(reason string) (string, string, error) {
		if stderr != "" {
			reason += ": " + stderr
		}
		return "", created, &candidateError{reason: reason}
	}
	switch status {
	case 0:
	case exitDirUnusable:
		return fail("not a usable directory")
	case exitCreate:
		return fail("cannot create a file")
	case exitNoExec:
		return fail("files cannot be executed (noexec mount or policy)")
	case exitWrite:
		return fail("write failed")
	case exitSize:
		return fail("size mismatch after transfer")
	case exitDigest:
		return fail("SHA-256 mismatch after transfer")
	case exitVersion:
		return fail("uploaded probe does not run")
	default:
		return fail(fmt.Sprintf("exit status %d", status))
	}
	kv := markedLines(head, marker)
	if _, ok := kv["ok"]; !ok || created == "" {
		return fail("incomplete transfer output")
	}
	if kv["size"] != strconv.Itoa(len(probe)) {
		return fail(fmt.Sprintf("size mismatch after transfer (%s bytes)", kv["size"]))
	}
	if s, ok := kv["sha256"]; ok && s != digest {
		return fail("SHA-256 mismatch after transfer")
	}
	return created, created, nil
}

// pathFrom returns the remote path reported by transferScript, if it is
// well-formed.
func pathFrom(out []byte, marker string) string {
	p := markedLines(out, marker)["path"]
	if !remotePathRe.MatchString(p) || strings.Contains(p, "/../") {
		return ""
	}
	return p
}

// remove deletes paths with a fresh session. It runs even when ctx has
// ended, with its own short deadline.
func (c *conn) remove(ctx context.Context, paths []string) {
	if len(paths) == 0 {
		return
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	_, errOut, status, err := c.output(rctx, shellCommand(removeScript, paths...))
	switch {
	case err != nil:
		c.log.Warn("could not remove probe from target", "paths", paths, "error", err)
	case status != 0:
		c.log.Warn("could not remove probe from target", "paths", paths, "status", status, "stderr", string(errOut))
	default:
		c.log.Debug("probe removed", "paths", paths)
	}
}

// sudoMode says how the probe is started.
type sudoMode struct {
	enabled  bool
	password string
}

func (m sudoMode) prefix() string {
	switch {
	case !m.enabled:
		return ""
	case m.password == "":
		return sudoNoPassword
	default:
		return sudoWithPassword
	}
}

// errSudoRefused means sudo did not run the command; the caller falls back
// to running without it.
var errSudoRefused = errors.New("sudo refused")

type sudoError struct{ reason string }

func (e *sudoError) Error() string        { return "sudo unavailable: " + e.reason }
func (e *sudoError) Is(target error) bool { return target == errSudoRefused }

// awaitStart answers the sudo password prompt (once) and returns when the
// inner shell has printed the start marker on standard error.
func awaitStart(ctx context.Context, p *remoteProc, errOut *streamBuffer, start, prompt string, mode sudoMode) error {
	startLine := []byte(start + "\n")
	promptB := []byte(prompt)
	timer := time.NewTimer(sudoStartTimeout)
	defer timer.Stop()
	sent := false
	exited := false
	for {
		head := errOut.head()
		if bytes.Contains(head, startLine) {
			return nil
		}
		if mode.enabled && mode.password != "" {
			switch n := bytes.Count(head, promptB); {
			case n > 1:
				p.abort()
				return &sudoError{reason: "password rejected"}
			case n == 1 && !sent:
				if _, err := p.stdin.Write([]byte(mode.password + "\n")); err != nil {
					return fmt.Errorf("ssh: send sudo password: %w", err)
				}
				sent = true
			}
		}
		if exited {
			reason := strings.TrimSpace(cleanTail(errOut.tailBytes(), start, prompt))
			status, err := exitStatus(p.err)
			if err == nil {
				reason = fmt.Sprintf("exit status %d: %s", status, reason)
			}
			if mode.enabled {
				return &sudoError{reason: reason}
			}
			return fmt.Errorf("ssh: probe did not start: %s", reason)
		}
		select {
		case <-errOut.changed:
		case <-p.done:
			exited = true
		case <-timer.C:
			p.abort()
			if mode.enabled {
				return &sudoError{reason: "no prompt or start within " + sudoStartTimeout.String()}
			}
			return errors.New("ssh: probe did not start in time")
		case <-ctx.Done():
			p.abort()
			return ctx.Err()
		}
	}
}

func (c *conn) checkSudo(ctx context.Context, mode sudoMode) error {
	start, prompt := randomHex(16), randomHex(16)
	script := strings.Replace(sudoCheckScript, runPlaceholder, mode.prefix(), 1)
	out := newStreamBuffer(controlOutputLimit, 0)
	errOut := newStreamBuffer(controlOutputLimit, stderrTailLimit)
	p, err := c.start(ctx, shellCommand(script, start, prompt), out, errOut, nil)
	if err != nil {
		return err
	}
	defer p.release()
	if err := awaitStart(ctx, p, errOut, start, prompt, mode); err != nil {
		return err
	}
	_ = p.stdin.Close()
	status, err := p.wait(ctx)
	if err != nil {
		return err
	}
	if status != 0 {
		return &sudoError{reason: fmt.Sprintf("exit status %d", status)}
	}
	return nil
}

// runProbe runs the uploaded probe and returns its standard output and the
// tail of its standard error.
func (c *conn) runProbe(ctx context.Context, path string, mode sudoMode, payload []byte, maxReport int64) ([]byte, string, error) {
	start, prompt := randomHex(16), randomHex(16)
	script := strings.Replace(collectScript, runPlaceholder, mode.prefix(), 1)
	sink := newReportSink(start, maxReport)
	errOut := newStreamBuffer(controlOutputLimit, stderrTailLimit)
	p, err := c.start(ctx, shellCommand(script, start, prompt, path), nil, errOut, sink)
	if err != nil {
		return nil, "", err
	}
	defer p.release()
	stderr := func() string { return cleanTail(errOut.tailBytes(), start, prompt) }
	if err := awaitStart(ctx, p, errOut, start, prompt, mode); err != nil {
		return nil, stderr(), err
	}
	c.log.Debug("probe started", "privileged", mode.enabled)
	if _, err := p.stdin.Write(payload); err != nil {
		return nil, stderr(), fmt.Errorf("ssh: send request: %w", err)
	}
	_ = p.stdin.Close()
	select {
	case <-p.done:
	case <-sink.overflow:
		p.abort()
		return nil, stderr(), fmt.Errorf("%w (%d bytes)", ErrReportTooLarge, maxReport)
	case <-ctx.Done():
		p.abort()
		return nil, stderr(), ctx.Err()
	}
	if sink.overflowed() {
		return nil, stderr(), fmt.Errorf("%w (%d bytes)", ErrReportTooLarge, maxReport)
	}
	status, err := exitStatus(p.err)
	if err != nil {
		return nil, stderr(), err
	}
	if status != 0 {
		return nil, stderr(), fmt.Errorf("ssh: probe exited with status %d: %s", status, tail([]byte(stderr()), errorTailLimit))
	}
	out, ok := sink.result()
	if !ok {
		return nil, stderr(), errors.New("ssh: probe output did not start with the expected marker")
	}
	return out, stderr(), nil
}

// cleanTail removes the markers from captured standard error.
func cleanTail(b []byte, markers ...string) string {
	s := string(b)
	for _, m := range markers {
		s = strings.ReplaceAll(s, m+"\n", "")
		s = strings.ReplaceAll(s, m, "")
	}
	return strings.ToValidUTF8(s, "�")
}

func tail(b []byte, n int) string {
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return strings.TrimSpace(strings.ToValidUTF8(string(b), "�"))
}
