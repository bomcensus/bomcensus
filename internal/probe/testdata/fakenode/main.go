// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Command fakenode is detected as node by the tests of package probe. Run
// without arguments it sleeps; with --version it prints a version and, on
// stderr, its own credentials, so that tests see whom a version command
// ran as.
//
//go:debug containermaxprocs=0
//go:debug updatemaxprocs=0
package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println("v1.2.3")
		b, _ := os.ReadFile("/proc/self/status")
		for line := range strings.SplitSeq(string(b), "\n") {
			for _, k := range []string{"Uid:", "CapEff:", "CapPrm:", "NoNewPrivs:", "Seccomp:"} {
				if strings.HasPrefix(line, k) {
					fmt.Fprintln(os.Stderr, line)
				}
			}
		}
		return
	}
	time.Sleep(120 * time.Second)
}
