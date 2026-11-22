// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package probe

import (
	"os"

	"golang.org/x/sys/windows"

	"github.com/bomcensus/bomcensus/internal/report"
)

// DetectPrivilege reports privileged when the process token is elevated or
// belongs to LocalSystem, which is what reading every user's files and
// processes will need once there is collection on Windows. UID is -1.
func DetectPrivilege() report.Privilege {
	p := report.Privilege{Level: report.PrivilegeNonRoot, UID: os.Geteuid()}
	tok := windows.GetCurrentProcessToken()
	if tok.IsElevated() {
		p.Level = report.PrivilegePrivileged
		return p
	}
	if u, err := tok.GetTokenUser(); err == nil && u.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		p.Level = report.PrivilegePrivileged
	}
	return p
}
