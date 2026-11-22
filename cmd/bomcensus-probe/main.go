// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Command bomcensus-probe collects one report of the system it runs on.
//
//	bomcensus-probe collect [--no-sandbox] [--log-level LEVEL]
//
// reads a JSON request from standard input until end of file (empty input
// means the default request) and writes the zstd-compressed report to
// standard output, nothing else. Logs go to standard error. It works the
// same when standard input and output are a socket passed by systemd, pipes
// of a parent process or an SSH or exec session. A caller on a socket shuts
// down its write side after the request, so that the probe sees the end of
// the input.
//
// Exit status: 0 when a report was written (also a partial one), 1 when no
// report could be produced, 2 for usage errors.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/bomcensus/bomcensus/internal/probe"
	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/version"
)

var errUsage = errors.New("usage error")

type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error
}

var commands = []command{
	{"collect", "read a request from stdin and write the report to stdout", runCollect},
	{"self-test", "apply the self-restrictions and print what took effect", runSelfTest},
	{"version", "print the version", runVersion},
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: bomcensus-probe <command> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "commands:")
	for _, c := range commands {
		fmt.Fprintf(w, "  %-10s %s\n", c.name, c.summary)
	}
}

func main() {
	// Must come first: the binary doubles as the exec helper of version
	// commands and then never returns.
	maybeRunExecHelper()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	switch {
	case err == nil:
	case errors.Is(err, flag.ErrHelp), errors.Is(err, errUsage):
		os.Exit(2)
	default:
		fmt.Fprintln(os.Stderr, "bomcensus-probe:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		usage(stderr)
		return errUsage
	}
	for _, c := range commands {
		if c.name == args[0] {
			return c.run(ctx, args[1:], stdin, stdout, stderr)
		}
	}
	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		usage(stderr)
		return flag.ErrHelp
	}
	fmt.Fprintf(stderr, "bomcensus-probe: unknown command %q\n", args[0])
	usage(stderr)
	return errUsage
}

func newLogger(w io.Writer, level string) (*slog.Logger, error) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("%w: --log-level %q", errUsage, level)
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: lvl})), nil
}

func runCollect(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	noSandbox := fs.Bool("no-sandbox", false, "do not restrict the process (debugging only)")
	level := fs.String("log-level", "info", "log level: debug, info, warn or error")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("%w: unexpected arguments %v", errUsage, fs.Args())
	}
	log, err := newLogger(stderr, *level)
	if err != nil {
		return err
	}

	// Restrictions come before the request is read and before any file of
	// the target is parsed.
	if *noSandbox {
		log.Warn("sandbox disabled; the probe runs with all the privileges it was started with")
	} else {
		probe.EnsureExecutableAfterDrop(log)
		probe.ApplySandbox(log)
	}

	req, err := probe.DecodeRequest(stdin)
	if err != nil {
		return err
	}
	rep, err := probe.Run(ctx, req, probe.Options{Log: log, ProcessLimits: true})
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(stdout, 256<<10)
	if err := report.Encode(w, rep); err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

func runSelfTest(_ context.Context, args []string, _ io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("self-test", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "print the result as JSON")
	level := fs.String("log-level", "warn", "log level: debug, info, warn or error")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log, err := newLogger(stderr, *level)
	if err != nil {
		return err
	}
	probe.EnsureExecutableAfterDrop(log)
	res := probe.ApplySandbox(log)
	checks := probe.CheckSandbox("version")
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			*probe.SandboxResult
			Checks []probe.SandboxCheck `json:"checks"`
		}{res, checks})
	}
	fmt.Fprint(stdout, res.String())
	fmt.Fprintln(stdout, "checks:")
	for _, c := range checks {
		fmt.Fprintf(stdout, "  %-22s %-6s %s\n", c.Name, map[bool]string{true: "ok", false: "FAIL"}[c.OK], strings.TrimSpace(c.Detail))
	}
	return nil
}

func runVersion(_ context.Context, _ []string, _ io.Reader, stdout, _ io.Writer) error {
	_, err := fmt.Fprintln(stdout, version.Version)
	return err
}
