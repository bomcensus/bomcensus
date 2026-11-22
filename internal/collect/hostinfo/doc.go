// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package hostinfo collects the identity of the inspected system: OS release,
// hostname, machine-id, kernel release and architecture.
//
// On Linux the release comes from os-release and the rest from uname. On
// Windows it comes from the registry and RtlGetVersion (hostinfo_windows.go).
package hostinfo
