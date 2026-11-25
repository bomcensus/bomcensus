// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package cli is the bomcensus-scanner command, the remote scanner: it
// enrolls like an agent (kind scanner), polls the server for scan
// directives and collects SSH hosts and Kubernetes clusters with
// internal/scanner/runner. Secrets in directives are sealed to the HPKE key
// generated at enrollment, whose private half stays in the state directory.
package cli

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bomcensus/bomcensus/agentproto"
	"github.com/bomcensus/bomcensus/agentproto/dto"
	"github.com/bomcensus/bomcensus/internal/agent"
	"github.com/bomcensus/bomcensus/internal/agent/core"
	"github.com/bomcensus/bomcensus/internal/agent/state"
	"github.com/bomcensus/bomcensus/internal/link"
	"github.com/bomcensus/bomcensus/internal/pki"
	"github.com/bomcensus/bomcensus/internal/platform/paths"
	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/scanner/hpkebox"
	"github.com/bomcensus/bomcensus/internal/scanner/runner"
	"github.com/bomcensus/bomcensus/internal/sign"
	"github.com/bomcensus/bomcensus/internal/version"
)

// Environment variables used as flag defaults (the same as the agent's).
const (
	envStateDir = "BOMCENSUS_STATE_DIR"
	envLogLevel = "BOMCENSUS_LOG_LEVEL"
	envToken    = "BOMCENSUS_TOKEN"
)

// defaultStateDir is the scanner's state directory.
var defaultStateDir = paths.ScannerStateDir()

// hpkeKeyFile holds the HPKE private key (PKCS#8 PEM, mode 0600).
const hpkeKeyFile = "hpke-key.pem"

const usageText = `usage: bomcensus-scanner <command> [flags]

commands:
  enroll   enroll with the server and wait for approval
  run      run the scanner
  version  print the version

Run 'bomcensus-scanner <command> -h' for the flags of a command.
`

var errUsage = errors.New("usage error")

// Extensions are the parts a build of the scanner adds (package scanner).
type Extensions struct {
	// Channels are further channels by name, chosen with
	// "enroll --channel NAME".
	Channels map[string]agentproto.ChannelFactory
}

// check refuses a build with extensions that is not signed with its own
// release keys.
func (e Extensions) check() error {
	if len(e.Channels) == 0 {
		return nil
	}
	return sign.RequireOwnTrust()
}

func run(args []string, stdout, stderr io.Writer) int {
	return Main(args, stdout, stderr, Extensions{})
}

// Main is the bomcensus-scanner command. It returns the exit status: 0 on
// success, 1 on failure, 2 on usage errors.
func Main(args []string, stdout, stderr io.Writer, ext Extensions) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	if args[0] == "enroll" || args[0] == "run" {
		if err := ext.check(); err != nil {
			fmt.Fprintln(stderr, "bomcensus-scanner:", err)
			return 1
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch args[0] {
	case "enroll":
		err = cmdEnroll(ctx, args[1:], stderr, ext)
	case "run":
		err = cmdRun(ctx, args[1:], stderr, ext)
	case "version":
		fmt.Fprintln(stdout, version.Version)
		return 0
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usageText)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usageText)
		return 2
	}
	switch {
	case err == nil:
		return 0
	case errors.Is(err, flag.ErrHelp), errors.Is(err, errUsage):
		return 2
	default:
		fmt.Fprintln(stderr, "bomcensus-scanner:", err)
		return 1
	}
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func newLogger(w io.Writer, level string) (*slog.Logger, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("%w: invalid log level %q", errUsage, level)
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: l})), nil
}

func cmdEnroll(ctx context.Context, args []string, stderr io.Writer, ext Extensions) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)
	server := fs.String("server", "", "server address, https://HOST:PORT")
	tok := fs.String("token", "", "enrollment string (default $"+envToken+")")
	mode := fs.String("connect-mode", core.ModeConnect, "connection mode; scanners support connect only")
	serverName := fs.String("server-name", "", "name in the server certificate (default: host of --server)")
	tlsVerify := fs.String("tls-verify", "pinned", "server certificate verification: pinned, system or none")
	tlsCA := fs.String("tls-ca", "", "PEM file with CA certificates trusted in addition to the OS store (tls-verify system)")
	stateDir := fs.String("state-dir", envOr(envStateDir, defaultStateDir), "state directory")
	level := fs.String("log-level", envOr(envLogLevel, "info"), "log level: debug, info, warn, error")
	ifNotEnrolled := fs.Bool("if-not-enrolled", false, "succeed without doing anything when the state directory holds an approved enrollment")
	channel := fs.String("channel", "", "channel registered in this build (default: the HTTP channel)")
	settings := settingsFlag{}
	fs.Var(settings, "channel-setting", "key=value setting of --channel (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("%w: unexpected arguments", errUsage)
	}
	log, err := newLogger(stderr, *level)
	if err != nil {
		return err
	}
	t := *tok
	if t == "" {
		t = os.Getenv(envToken)
	}
	tlsMode, err := link.ParseTLSMode(*tlsVerify)
	if err != nil {
		return err
	}
	roots, err := loadRoots(*tlsCA)
	if err != nil {
		return err
	}
	st, err := state.OpenAs(*stateDir, paths.ScannerService)
	if err != nil {
		return err
	}
	defer st.Close()
	pub, err := ensureHPKEKey(st)
	if err != nil {
		return err
	}
	_, err = core.Enroll(ctx, core.EnrollOptions{
		State:           st,
		Kind:            core.KindScanner,
		Version:         version.Version,
		Token:           t,
		ServerURL:       *server,
		ServerName:      *serverName,
		ConnectMode:     *mode,
		TLSMode:         tlsMode,
		ExtraRoots:      roots,
		Host:            agent.HostFacts(ctx),
		HPKEPublicKey:   pub,
		Channel:         *channel,
		ChannelSettings: settings,
		Logger:          log,
		Runtime:         core.Options{Channels: ext.Channels},
	})
	if *ifNotEnrolled && errors.Is(err, core.ErrAlreadyEnrolled) {
		log.Info("already enrolled; nothing to do", "state_dir", *stateDir)
		return nil
	}
	return err
}

func loadRoots(path string) ([]*x509.Certificate, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	return pki.ParseCertificatesPEM(b)
}

// ensureHPKEKey returns the public key of the stored HPKE key, generating
// and storing a key first when there is none. The key is written before
// enrollment, so a resumed enrollment keeps the key the server knows.
func ensureHPKEKey(st *state.Dir) ([]byte, error) {
	b, err := st.ReadFile(hpkeKeyFile)
	if err == nil {
		priv, err := hpkebox.ParsePrivateKeyPEM(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", hpkeKeyFile, err)
		}
		return hpkebox.PublicKey(priv)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	priv, pub, err := hpkebox.GenerateKey()
	if err != nil {
		return nil, err
	}
	enc, err := hpkebox.EncodePrivateKeyPEM(priv)
	if err != nil {
		return nil, err
	}
	if err := st.WriteFile(hpkeKeyFile, enc, 0o600); err != nil {
		return nil, fmt.Errorf("store HPKE key: %w", err)
	}
	return pub, nil
}

func loadHPKEKey(st *state.Dir) ([]byte, error) {
	b, err := st.ReadFile(hpkeKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read HPKE key (enroll the scanner first): %w", err)
	}
	return hpkebox.ParsePrivateKeyPEM(b)
}

func cmdRun(ctx context.Context, args []string, stderr io.Writer, ext Extensions) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", envOr(envStateDir, defaultStateDir), "state directory")
	level := fs.String("log-level", envOr(envLogLevel, "info"), "log level: debug, info, warn, error")
	workers := fs.Int("workers", 4, "scan jobs run at the same time")
	backlog := fs.Int("backlog", 64, "scan jobs waiting for a worker")
	external := fs.Bool("kube-allow-external-credentials", false,
		"allow kubeconfigs from the server to run credential plugins or read local files")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("%w: unexpected arguments", errUsage)
	}
	log, err := newLogger(stderr, *level)
	if err != nil {
		return err
	}
	st, err := state.OpenAs(*stateDir, paths.ScannerService)
	if err != nil {
		return err
	}
	defer st.Close()
	key, err := loadHPKEKey(st)
	if err != nil {
		return err
	}
	rt, err := core.New(core.Options{Kind: core.KindScanner, State: st, Version: version.Version, Logger: log,
		Channels: ext.Channels})
	if err != nil {
		if errors.Is(err, state.ErrNotEnrolled) {
			return errors.New("not enrolled; run 'bomcensus-scanner enroll' first")
		}
		return err
	}
	pool := runner.NewPool(*workers, *backlog, log)
	probes := newProbeCache(rt.API)
	sc := &scanner{
		agentID: rt.AgentID,
		key:     key,
		deps: runner.Deps{
			Sink:                         &clientSink{reports: rt, client: rt.API, log: log, retryWait: 5 * time.Second},
			Probe:                        probes.Get,
			Logger:                       log,
			AllowExternalKubeCredentials: *external,
		},
		pool: pool,
		run:  packageRunner{},
		log:  log,
	}
	sc.register(rt)
	rt.OnStatus(func(_ context.Context, req *dto.PollRequest) {
		features := []string{report.FeatureGoSymbols, report.FeatureIntegrity}
		req.Features = &features
	})
	ctx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-ctx.Done()
		cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := pool.Close(cctx); err != nil {
			log.Warn("scan jobs did not stop in time", "error", err)
		}
	}()
	err = rt.Run(ctx)
	cancelRun()
	<-stopped
	return err
}

// settingsFlag collects repeated key=value flags.
type settingsFlag map[string]string

func (s settingsFlag) String() string { return "" }

func (s settingsFlag) Set(v string) error {
	k, val, ok := strings.Cut(v, "=")
	if !ok || k == "" {
		return fmt.Errorf("want key=value, got %q", v)
	}
	s[k] = val
	return nil
}
