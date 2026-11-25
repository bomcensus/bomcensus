// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Command bomcensus-scanner is the remote scanner. See package scanner for
// building a scanner of your own.
package main

import "github.com/bomcensus/bomcensus/scanner"

func main() {
	scanner.Main(scanner.Options{})
}
