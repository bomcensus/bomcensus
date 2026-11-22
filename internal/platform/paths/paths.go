// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package paths holds the default install and state locations of the
// bomcensus host components for the operating system they run on.
//
// Linux:
//
//	install       /opt/bomcensus
//	agent state   /var/lib/bomcensus/agent
//	scanner state /var/lib/bomcensus/scanner
//	update spool  /var/lib/bomcensus/update-spool
//
// Windows:
//
//	install       %ProgramFiles%\bomcensus
//	agent state   %ProgramData%\bomcensus\agent
//	scanner state %ProgramData%\bomcensus\scanner
//	update spool  %ProgramData%\bomcensus\update-spool
//
// Every value is a default only; each command lets the operator override it.
package paths

import "path/filepath"

// InstallDir returns the directory the released binaries are installed in.
func InstallDir() string { return installDir() }

// DataDir returns the parent of all bomcensus state directories.
func DataDir() string { return dataDir() }

// AgentStateDir returns the default agent state directory.
func AgentStateDir() string { return filepath.Join(dataDir(), "agent") }

// ScannerStateDir returns the default scanner state directory.
func ScannerStateDir() string { return filepath.Join(dataDir(), "scanner") }

// UpdateSpoolDir returns the default directory the agent stages updates in
// for the updater.
func UpdateSpoolDir() string { return filepath.Join(dataDir(), "update-spool") }

// Windows service names. Each service runs as the virtual account
// NT SERVICE\<name>, which is also the account the state directory of that
// component is shared with.
const (
	AgentService   = "bomcensus-agent"
	ScannerService = "bomcensus-scanner"
)
