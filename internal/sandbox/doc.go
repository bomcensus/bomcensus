// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package sandbox holds the Linux restriction primitives shared by the
// probe (internal/probe) and the exec helper of version commands
// (internal/collect/artifact): the seccomp filters and the Landlock
// ruleset of a version command. On Windows it runs version commands
// itself (Run) and checks that sandbox (CheckCommand). See
// docs/SECURITY.md 6.2 and 6.6.
package sandbox
