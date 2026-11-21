// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Command bomcensus-updater installs verified releases from the update spool
// and rolls back versions that do not come up. It has no network access.
//
// Exit status: 0 when the work was done (rejected spool entries included),
// 1 for operational failures, 2 for usage errors.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bomcensus/bomcensus/internal/updater"
	"github.com/bomcensus/bomcensus/internal/version"
)

const (
	defaultInstall = "/opt/bomcensus"
	defaultSpool   = "/var/lib/bomcensus/update-spool"
)

// errUsage marks errors that exit with status 2.
var errUsage = errors.New("usage error")

type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string, stdout, stderr io.Writer) error
}

var commands = []command{
	{"apply", "verify and install the releases in the spool, then exit", runApply},
	{"boot-check", "count a start of the pending version and roll back when it fails", runBootCheck},
	{"status", "print the install state as JSON", runStatus},
	{"version", "print the version", runVersion},
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: bomcensus-updater <command> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "commands:")
	for _, c := range commands {
		fmt.Fprintf(w, "  %-12s %s\n", c.name, c.summary)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Run 'bomcensus-updater <command> -h' for the flags of a command.")
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	switch {
	case err == nil:
	case errors.Is(err, flag.ErrHelp), errors.Is(err, errUsage):
		os.Exit(2)
	default:
		fmt.Fprintln(os.Stderr, "bomcensus-updater:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		usage(stderr)
		return errUsage
	}
	for _, c := range commands {
		if c.name == args[0] {
			return c.run(ctx, args[1:], stdout, stderr)
		}
	}
	if args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		usage(stdout)
		return nil
	}
	usage(stderr)
	fmt.Fprintf(stderr, "unknown command %q\n", args[0])
	return errUsage
}

func newFlagSet(name, args string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: bomcensus-updater %s %s\n", name, args)
		fs.PrintDefaults()
	}
	return fs
}

func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return fmt.Errorf("%w: unexpected arguments %v", errUsage, fs.Args())
	}
	return nil
}

func newLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, nil)).With("component", "updater")
}

func runApply(ctx context.Context, args []string, _, stderr io.Writer) error {
	fs := newFlagSet("apply", "[--spool DIR] [--install DIR]", stderr)
	spool := fs.String("spool", defaultSpool, "update spool `directory`")
	install := fs.String("install", defaultInstall, "install `directory`")
	lockWait := fs.Duration("lock-wait", 30*time.Second, "how long to wait for another updater to finish")
	if err := parse(fs, args); err != nil {
		return err
	}
	log := newLogger(stderr)
	res, err := updater.Apply(ctx, updater.Options{InstallDir: *install, Logger: log, LockWait: *lockWait}, *spool)
	if err != nil {
		return err
	}
	log.Info("spool processed", "installed", res.Installed, "confirmed", res.Confirmed, "rolled_back", res.RolledBack, "rejected", len(res.Rejected))
	return nil
}

func runBootCheck(ctx context.Context, args []string, _, stderr io.Writer) error {
	fs := newFlagSet("boot-check", "[--install DIR] [--max-attempts N] [--pending-timeout D]", stderr)
	install := fs.String("install", defaultInstall, "install `directory`")
	maxAttempts := fs.Int("max-attempts", updater.DefaultMaxAttempts, "starts a pending version gets before it is rolled back")
	timeout := fs.Duration("pending-timeout", updater.DefaultPendingTimeout, "how long a version may stay unconfirmed")
	lockWait := fs.Duration("lock-wait", 30*time.Second, "how long to wait for another updater to finish")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *maxAttempts < 1 || *timeout <= 0 {
		fs.Usage()
		return fmt.Errorf("%w: --max-attempts and --pending-timeout must be positive", errUsage)
	}
	log := newLogger(stderr)
	res, err := updater.BootCheck(ctx, updater.Options{InstallDir: *install, Logger: log, LockWait: *lockWait},
		updater.BootLimits{MaxAttempts: *maxAttempts, PendingTimeout: *timeout})
	if err != nil {
		return err
	}
	if res.RolledBack != "" {
		log.Info("boot check rolled back", "version", res.RolledBack)
	}
	return nil
}

func runStatus(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("status", "[--install DIR]", stderr)
	install := fs.String("install", defaultInstall, "install `directory`")
	if err := parse(fs, args); err != nil {
		return err
	}
	st, err := updater.Status(ctx, *install)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(st)
}

func runVersion(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("version", "", stderr)
	if err := parse(fs, args); err != nil {
		return err
	}
	_, err := fmt.Fprintln(stdout, version.Version)
	return err
}
