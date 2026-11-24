// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

import type { Severity, VulnLocation } from '~/types'

/** Text color of a severity mark. */
export const severityText: Record<Severity, string> = {
  critical: 'text-critical',
  high: 'text-high',
  medium: 'text-medium',
  low: 'text-low',
  none: 'text-ink-3',
}

/** Kind of asset and, for a container, its name and layer. */
export function locationWhere(l: VulnLocation): string {
  const kind = l.assetKind === 'workload' ? '워크로드' : '호스트'
  if (!l.container) return kind
  return `${kind} · ${l.container} · ${findingLayerLabel[l.layer]}`
}

/** The first loading process of a location: executable, pid and listening ports. */
export function locationProcess(l: VulnLocation): string {
  const p = l.processes[0]
  if (!p) return ''
  const exe = p.exe.split('/').pop() ?? p.exe
  const more = l.processes.length > 1 ? ` 외 ${l.processes.length - 1}` : ''
  return `${exe} · pid ${p.pid}${p.ports.length ? ` · ${p.ports.join(', ')}` : ''}${more}`
}

export const percent = (n?: number) => (n === undefined ? '—' : `${(n * 100).toFixed(1)}%`)
