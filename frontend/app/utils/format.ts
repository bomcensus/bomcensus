// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

const pad = (n: number) => String(n).padStart(2, '0')

/** 2026-11-20 09:00 */
export function formatDateTime(iso?: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

/** 2026-11-20 */
export function formatDate(iso?: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
}

/** "3분 전", "2시간 전", "5일 후" (3 minutes ago, 2 hours ago, in 5 days), relative to the current time. */
export function formatRelative(iso?: string): string {
  if (!iso) return '—'
  const diff = Date.now() - new Date(iso).getTime()
  const abs = Math.abs(diff)
  const suffix = diff >= 0 ? '전' : '후'
  const min = Math.round(abs / 60_000)
  if (min < 1) return '방금'
  if (min < 60) return `${min}분 ${suffix}`
  const hour = Math.round(min / 60)
  if (hour < 24) return `${hour}시간 ${suffix}`
  const day = Math.round(hour / 24)
  if (day < 60) return `${day}일 ${suffix}`
  return `${Math.round(day / 30)}개월 ${suffix}`
}

/** Days remaining from now. Negative if already past. */
export function daysUntil(iso: string): number {
  return Math.floor((new Date(iso).getTime() - Date.now()) / 86_400_000)
}

export function formatBytes(bytes?: number): string {
  if (bytes === undefined) return '—'
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let value = bytes / 1024
  let i = 0
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024
    i++
  }
  return `${value >= 100 ? value.toFixed(0) : value.toFixed(1)} ${units[i]}`
}

export function formatNumber(n: number): string {
  return n.toLocaleString('ko-KR')
}

/** Shorten to the form sha256:ab12…ef90 */
export function shortHash(hash?: string, head = 12): string {
  if (!hash) return '—'
  const [prefix, rest] = hash.includes(':') ? hash.split(':') : ['', hash]
  const body = rest ?? ''
  const short = body.length > head + 4 ? `${body.slice(0, head)}…` : body
  return prefix ? `${prefix}:${short}` : short
}
