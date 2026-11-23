// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package agent

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/bomcensus/bomcensus/internal/agent/core"
	"github.com/bomcensus/bomcensus/internal/agent/probeexec"
	"github.com/bomcensus/bomcensus/internal/agent/state"
	"github.com/bomcensus/bomcensus/internal/agent/update"
	"github.com/bomcensus/bomcensus/internal/version"
)

// Environment variables used as flag defaults.
const (
	EnvStateDir   = "BOMCENSUS_STATE_DIR"
	EnvInstallDir = "BOMCENSUS_INSTALL_DIR"
	EnvLogLevel   = "BOMCENSUS_LOG_LEVEL"
	EnvToken      = "BOMCENSUS_TOKEN"
)

const usageText = `usage: bomcensus-agent <command> [flags]

commands:
  enroll      enroll with the server and wait for approval
  run         run the agent
  init-state  give a state directory to the agent's user (container init step, as root)
  version     print the version

Run 'bomcensus-agent <command> -h' for the flags of a command.
`

// Main is the bomcensus-agent command. It returns the exit status: 0 on
// success, 1 on failure, 2 on usage errors. When an update switched the
// current version, it replaces the process with the new executable.
func Main(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch args[0] {
	case "enroll":
		err = cmdEnroll(ctx, args[1:], stderr)
	case "run":
		err = cmdRun(ctx, args[1:], stderr)
	case "init-state":
		err = cmdInitState(args[1:], stderr)
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
	var re *update.ReexecError
	switch {
	case err == nil:
		return 0
	case errors.Is(err, flag.ErrHelp), errors.Is(err, errUsage):
		return 2
	case errors.As(err, &re):
		stop()
		fmt.Fprintln(stderr, "bomcensus-agent:", re.Error())
		if runtime.GOOS == "windows" {
			// No exec on Windows. The service manager restarts the
			// service (see RunService); a console run must be started again.
			fmt.Fprintf(stderr, "bomcensus-agent: version %s is installed; start %s again\n", re.Version, re.Path)
			return 1
		}
		// The state lock is held through a close-on-exec descriptor and
		// was released by Run.
		xerr := syscall.Exec(re.Path, append([]string{re.Path}, os.Args[1:]...), os.Environ())
		fmt.Fprintln(stderr, "bomcensus-agent: re-execute:", xerr)
		return 1
	default:
		fmt.Fprintln(stderr, "bomcensus-agent:", err)
		return 1
	}
}

var errUsage = errors.New("usage error")

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

func cmdEnroll(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)
	server := fs.String("server", "", "server address, https://HOST:PORT (connect mode)")
	tok := fs.String("token", "", "enrollment string (default $"+EnvToken+")")
	mode := fs.String("connect-mode", core.ModeConnect, "connect or listen")
	listen := fs.String("listen", ":7443", "listen address (listen mode)")
	serverName := fs.String("server-name", "", "name in the server certificate (required in listen mode; default: host of --server)")
	tlsVerify := fs.String("tls-verify", "pinned", "server certificate verification in connect mode: pinned, system or none")
	tlsCA := fs.String("tls-ca", "", "PEM file with CA certificates trusted in addition to the OS store (tls-verify system)")
	stateDir := fs.String("state-dir", envOr(EnvStateDir, state.DefaultDir), "state directory")
	level := fs.String("log-level", envOr(EnvLogLevel, "info"), "log level: debug, info, warn, error")
	ifNotEnrolled := fs.Bool("if-not-enrolled", false, "succeed without doing anything when the state directory holds an approved enrollment")
	probeSock := fs.String("probe-socket", "", "take the host facts from the probe behind this socket instead of reading this system (container use)")
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
		t = os.Getenv(EnvToken)
	}
	listenAddr := ""
	if *mode == core.ModeListen {
		listenAddr = *listen
	}
	err = Enroll(ctx, EnrollOptions{
		StateDir:       *stateDir,
		ServerURL:      *server,
		Token:          t,
		ConnectMode:    *mode,
		ListenAddress:  listenAddr,
		ServerName:     *serverName,
		TLSMode:        *tlsVerify,
		ExtraRootsFile: *tlsCA,
		ProbeSocket:    *probeSock,
		Logger:         log,
	})
	if *ifNotEnrolled && errors.Is(err, core.ErrAlreadyEnrolled) {
		log.Info("already enrolled; nothing to do", "state_dir", *stateDir)
		return nil
	}
	return err
}

func cmdRun(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", envOr(EnvStateDir, state.DefaultDir), "state directory")
	install := fs.String("install-dir", os.Getenv(EnvInstallDir), "install directory (default: derived from the executable path)")
	spool := fs.String("update-spool", update.DefaultSpool, "update spool directory")
	probeSock := fs.String("probe-socket", probeexec.DefaultSocket, "probe socket; when absent the probe runs as a child")
	requireSock := fs.Bool("require-probe-socket", false, "never run the probe as a child; collections fail while the socket is missing")
	noUpdates := fs.Bool("disable-updates", false, "turn automatic updates off (the binaries are updated with the image)")
	level := fs.String("log-level", envOr(EnvLogLevel, "info"), "log level: debug, info, warn, error")
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
	return Run(ctx, Options{
		StateDir:           *stateDir,
		InstallDir:         *install,
		UpdateSpool:        *spool,
		Systemd:            strings.EqualFold(os.Getenv(update.SystemdEnv), update.SystemdValue),
		ProbeSocket:        *probeSock,
		ProbeRequireSocket: *requireSock,
		DisableUpdates:     *noUpdates,
		Logger:             log,
	})
}

func cmdInitState(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("init-state", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "existing directory to hand over (required)")
	owner := fs.String("owner", "", "UID:GID of the agent (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *dir == "" || *owner == "" {
		return fmt.Errorf("%w: init-state --dir DIR --owner UID:GID", errUsage)
	}
	u, g, ok := strings.Cut(*owner, ":")
	uid, err1 := strconv.Atoi(u)
	gid, err2 := strconv.Atoi(g)
	if !ok || err1 != nil || err2 != nil || uid < 0 || gid < 0 {
		return fmt.Errorf("%w: --owner %q is not UID:GID", errUsage, *owner)
	}
	if err := InitStateDir(*dir, uid, gid); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "bomcensus-agent: %s is owned by %d:%d with mode 0700\n", *dir, uid, gid)
	return nil
}
