// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Command bomcensus-release creates release keys, signs executables and
// builds signed release bundles. It is part of the build pipeline and is not
// shipped to hosts.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
)

type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string, stdout io.Writer) error
}

var commands = []command{
	{"keygen", "generate a manifest key pair and a code-signing CA and certificate", runKeygen},
	{"sign-elf", "add an AuthentiELF signature to ELF files in place", runSignELF},
	{"bundle", "build a signed release bundle from a binary directory", runBundle},
	{"manifest-pub", "print the public key of a manifest key (PEM file or Cloud KMS)", runManifestPub},
	{"print-ldflags", "print the -X linker flags that compile the trust into binaries", runPrintLDFlags},
	{"verify", "verify release bundles against the trust compiled into this binary", runVerify},
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: bomcensus-release <command> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "commands:")
	for _, c := range commands {
		fmt.Fprintf(w, "  %-14s %s\n", c.name, c.summary)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Run 'bomcensus-release <command> -h' for the flags of a command.")
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "bomcensus-release:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		usage(stderr)
		return flag.ErrHelp
	}
	for _, c := range commands {
		if c.name == args[0] {
			return c.run(ctx, args[1:], stdout)
		}
	}
	if args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		usage(stdout)
		return nil
	}
	usage(stderr)
	return fmt.Errorf("unknown command %q", args[0])
}

func newFlagSet(name, args string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: bomcensus-release %s %s\n", name, args)
		fs.PrintDefaults()
	}
	return fs
}
