// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build !windows

package paths

func installDir() string { return "/opt/bomcensus" }

func dataDir() string { return "/var/lib/bomcensus" }
