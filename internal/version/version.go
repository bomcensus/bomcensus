// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package version holds the build version of the bomcensus binaries.
package version

// Version is set at build time with -ldflags "-X .../internal/version.Version=...".
var Version = "0.0.0-dev"
