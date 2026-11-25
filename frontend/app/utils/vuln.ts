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
  negligible: 'text-ink-3',
  none: 'text-ink-3',
}

/** Kind of asset and, for a container, its name and layer. */
export function locationWhere(l: VulnLocation): string {
  const kind = l.assetKind === 'workload' ? '워크로드' : '호스트'
  if (!l.container) return kind
  return `${kind} · ${l.container} · ${findingLayerLabel[l.layer]}`
}

/** One loading process: executable, pid and listening ports. */
function processLine(p: VulnLocation['processes'][number], full = false): string {
  const exe = full ? p.exe : (p.exe.split('/').pop() ?? p.exe)
  return `${exe} · pid ${p.pid}${p.ports.length ? ` · ${p.ports.join(', ')}` : ''}`
}

/** Loading processes of a location, those running exe first. */
function processesOf(l: VulnLocation, exe?: string) {
  if (!exe) return l.processes
  return [...l.processes.filter((p) => p.exe === exe), ...l.processes.filter((p) => p.exe !== exe)]
}

/** The first loading process of a location (one running exe if given), and how many more. */
export function locationProcess(l: VulnLocation, exe?: string): string {
  const [p, ...rest] = processesOf(l, exe)
  if (!p) return ''
  return `${processLine(p)}${rest.length ? ` 외 ${rest.length}` : ''}`
}

/** Every loading process of a location, one per line. */
export function locationProcessTitle(l: VulnLocation, exe?: string): string {
  return processesOf(l, exe)
    .map((p) => processLine(p, true))
    .join('\n')
}

export const percent = (n?: number) => (n === undefined ? '—' : `${(n * 100).toFixed(1)}%`)
