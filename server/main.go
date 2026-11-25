// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/bomcensus/bomcensus/internal/server/session"
	"github.com/bomcensus/bomcensus/internal/version"
	"github.com/bomcensus/bomcensus/server/config"
)

const usage = `Usage: bomcensus-server [command]

Commands:
  serve          run the server (default)
  migrate        apply database migrations and exit
  hash-password  read a password from stdin (or prompt) and print its argon2id hash
  healthcheck    exit 0 when the local console listener reports ready (/readyz)
  version        print the version

The server is configured through BOMCENSUS_* environment variables.
`

// Main runs the bomcensus-server command line with opts and exits. It is
// configured through BOMCENSUS_* environment variables (package config).
//
//	[serve]            run the server (default)
//	migrate            apply database migrations and exit
//	hash-password      print an argon2id hash for BOMCENSUS_ADMIN_PASSWORD_HASH
//	bootstrap-scanner  store scanner enrollment strings in Kubernetes Secrets
//	healthcheck        check /readyz of the local console listener
//	version            print the version
func Main(opts Options) {
	os.Exit(Command(os.Args[1:], opts))
}

// Command runs one command line (without the program name) and returns the
// exit code.
func Command(args []string, opts Options) int {
	cmd := "serve"
	if len(args) > 0 {
		cmd = args[0]
		args = args[1:]
	}
	if len(args) > 0 && cmd != "bootstrap-scanner" {
		fmt.Fprintf(os.Stderr, "bomcensus-server %s: unexpected arguments: %s\n", cmd, strings.Join(args, " "))
		return 2
	}
	var err error
	switch cmd {
	case "serve":
		err = start(config.Serve, opts)
	case "migrate":
		err = start(config.Migrate, opts)
	case "hash-password":
		err = hashPassword(os.Stdin, os.Stdout, os.Stderr)
	case "bootstrap-scanner":
		err = bootstrapScanner(args, os.Stderr)
	case "healthcheck":
		err = healthcheck(context.Background(), os.Getenv)
	case "version":
		fmt.Println(version.Version)
	case "help", "-h", "-help", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "bomcensus-server: unknown command %q\n\n%s", cmd, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "bomcensus-server: %v\n", err)
		return 1
	}
	return 0
}

// start runs the server until SIGINT or SIGTERM, or only the migrations.
// A second signal ends the process at once.
func start(p config.Purpose, opts Options) error {
	cfg, err := config.Load(p)
	if err != nil {
		return err
	}
	log := cfg.NewLogger(os.Stderr)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		stop()
	}()
	if p == config.Migrate {
		return Migrate(ctx, cfg, log)
	}
	return Run(ctx, cfg, log, opts)
}

// hashPassword prints the PHC string of a password. On a terminal it
// prompts twice without echo; otherwise it reads the first line of stdin.
func hashPassword(stdin *os.File, stdout, stderr io.Writer) error {
	var pw string
	if fd := int(stdin.Fd()); term.IsTerminal(fd) {
		fmt.Fprint(stderr, "Password: ")
		a, err := term.ReadPassword(fd)
		fmt.Fprintln(stderr)
		if err != nil {
			return err
		}
		fmt.Fprint(stderr, "Repeat password: ")
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(stderr)
		if err != nil {
			return err
		}
		if string(a) != string(b) {
			return errors.New("passwords do not match")
		}
		pw = string(a)
	} else {
		line, err := bufio.NewReader(io.LimitReader(stdin, 4096)).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		pw = strings.TrimRight(line, "\r\n")
	}
	if pw == "" {
		return errors.New("empty password")
	}
	h, err := session.HashPassword(pw)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, h)
	return nil
}
