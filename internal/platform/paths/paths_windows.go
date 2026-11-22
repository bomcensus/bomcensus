// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build windows

package paths

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// The known folder is asked for first: a service gets it regardless of its
// environment block. The environment variable and the stock location are
// fallbacks for the unlikely case the shell API is unavailable.

func installDir() string {
	return filepath.Join(knownFolder(windows.FOLDERID_ProgramFiles, "ProgramFiles", `C:\Program Files`), "bomcensus")
}

func dataDir() string {
	return filepath.Join(knownFolder(windows.FOLDERID_ProgramData, "ProgramData", `C:\ProgramData`), "bomcensus")
}

func knownFolder(id *windows.KNOWNFOLDERID, env, fallback string) string {
	if p, err := windows.KnownFolderPath(id, windows.KF_FLAG_DEFAULT); err == nil && p != "" {
		return p
	}
	if p := os.Getenv(env); p != "" {
		return p
	}
	return fallback
}
