// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

import type { ProcessInfo } from '~/types'

/** The executable or a mapped library was replaced on disk; the old version is still in memory. Same rule as `view=restart`. */
export const needsRestart = (p: ProcessInfo) => p.exeState === 'replaced' || p.deletedLibs.some((l) => l.state === 'replaced')

/** The executable or a mapped library was deleted, or the process runs from a memfd. Same rule as `view=suspicious`. */
export const isSuspicious = (p: ProcessInfo) =>
  p.exeState === 'deleted' || p.exeState === 'memfd' || p.deletedLibs.some((l) => l.state === 'deleted')
