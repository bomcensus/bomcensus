// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

import type { Severity, VersionRange, VulnLocation } from '~/types'

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

/**
 * The version to update to: the fixed version, or "> X" when a range ends
 * "up to and including" X and no release is named as the fix. Empty when
 * neither is known. The API sets lastAffected only when it bounds the update.
 */
export function fixTarget(m: { fixedVersion?: string; lastAffected?: string }): string {
  if (m.lastAffected) return `> ${m.lastAffected}`
  return m.fixedVersion ?? ''
}

/** Tooltip of a "> X" update target. */
export function lastAffectedHint(m: { lastAffected?: string }): string | undefined {
  if (!m.lastAffected) return undefined
  return `${m.lastAffected} 이하가 취약 범위로 알려져 있습니다. 수정이 들어간 버전은 데이터에 없어 ${m.lastAffected}보다 높은 버전을 제안합니다.`
}

/** An affected range as "1.9.5 ≤ v ≤ 1.25.2", "= 1.13.3" or "모든 버전". */
export function rangeText(r: VersionRange): string {
  if (r.version) return `= ${r.version}`
  const lo = r.startIncluding ? `${r.startIncluding} ≤ ` : r.startExcluding ? `${r.startExcluding} < ` : ''
  const hi = r.endIncluding ? ` ≤ ${r.endIncluding}` : r.endExcluding ? ` < ${r.endExcluding}` : ''
  if (!lo && !hi) return '모든 버전'
  return `${lo}v${hi}`
}
