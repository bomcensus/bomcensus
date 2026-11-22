// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package winacl restricts Windows files and directories that hold secrets
// to the account the process runs as, LocalSystem and the Administrators
// group. It is the Windows counterpart of creating a directory with mode
// 0700 and files with mode 0600. The package is empty on other systems.
//
// The DACL set is protected: nothing is inherited from the parent. A
// directory's entries are inherited by everything created inside it, so
// files written there later (including by rename of a temporary file from
// the same directory) are covered without further calls.
package winacl
