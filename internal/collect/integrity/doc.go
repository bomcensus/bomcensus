// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package integrity compares the files of installed OS packages with the
// digests their package database records, like dpkg --verify and rpm -Va,
// and reports the expected and actual digests of files that differ.
//
// A pass over all packages may span several runs ("chunks"): each run
// checks packages in key order from a cursor until its deadline and returns
// the cursor to continue from. Reads are rate limited, pause while the host
// is under CPU or I/O pressure, and are dropped from the page cache.
package integrity
