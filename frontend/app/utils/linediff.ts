// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

export interface DiffLine {
  /** ' ' unchanged, '-' only in the old text, '+' only in the new text. */
  op: ' ' | '-' | '+'
  text: string
  /** 1-based line numbers in the old and the new text. */
  oldNo?: number
  newNo?: number
}

/** Above this many line pairs the diff falls back to showing both texts as removed and added. */
const maxCells = 4_000_000

/** Line diff of two texts (longest common subsequence of lines). */
export function lineDiff(oldText: string, newText: string): DiffLine[] {
  const a = oldText.split('\n')
  const b = newText.split('\n')
  // Common head and tail are cheap and keep the table small.
  let head = 0
  while (head < a.length && head < b.length && a[head] === b[head]) head++
  let tail = 0
  while (tail < a.length - head && tail < b.length - head && a[a.length - 1 - tail] === b[b.length - 1 - tail]) tail++
  const am = a.slice(head, a.length - tail)
  const bm = b.slice(head, b.length - tail)

  const out: DiffLine[] = []
  for (let i = 0; i < head; i++) out.push({ op: ' ', text: a[i]!, oldNo: i + 1, newNo: i + 1 })

  const n = am.length
  const m = bm.length
  if (n * m > maxCells) {
    am.forEach((text, i) => out.push({ op: '-', text, oldNo: head + i + 1 }))
    bm.forEach((text, j) => out.push({ op: '+', text, newNo: head + j + 1 }))
  } else {
    // lcs[i][j] is the LCS length of am[i:] and bm[j:].
    const lcs: Uint32Array[] = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1))
    for (let i = n - 1; i >= 0; i--) {
      for (let j = m - 1; j >= 0; j--) {
        lcs[i]![j] = am[i] === bm[j] ? lcs[i + 1]![j + 1]! + 1 : Math.max(lcs[i + 1]![j]!, lcs[i]![j + 1]!)
      }
    }
    let i = 0
    let j = 0
    while (i < n || j < m) {
      if (i < n && j < m && am[i] === bm[j]) {
        out.push({ op: ' ', text: am[i]!, oldNo: head + i + 1, newNo: head + j + 1 })
        i++
        j++
      } else if (j < m && (i >= n || lcs[i]![j + 1]! >= lcs[i + 1]![j]!)) {
        out.push({ op: '+', text: bm[j]!, newNo: head + j + 1 })
        j++
      } else {
        out.push({ op: '-', text: am[i]!, oldNo: head + i + 1 })
        i++
      }
    }
  }

  for (let k = tail; k > 0; k--) {
    out.push({ op: ' ', text: a[a.length - k]!, oldNo: a.length - k + 1, newNo: b.length - k + 1 })
  }
  return out
}

/** Keeps the changed lines with `context` unchanged lines around them; gaps become a single '…' line. */
export function diffHunks(lines: DiffLine[], context = 3): (DiffLine | { op: 'gap'; count: number })[] {
  const keep = new Array<boolean>(lines.length).fill(false)
  lines.forEach((l, i) => {
    if (l.op === ' ') return
    for (let k = Math.max(0, i - context); k <= Math.min(lines.length - 1, i + context); k++) keep[k] = true
  })
  const out: (DiffLine | { op: 'gap'; count: number })[] = []
  let skipped = 0
  lines.forEach((l, i) => {
    if (keep[i]) {
      if (skipped > 0) out.push({ op: 'gap', count: skipped })
      skipped = 0
      out.push(l)
    } else {
      skipped++
    }
  })
  if (skipped > 0 && out.length > 0) out.push({ op: 'gap', count: skipped })
  return out
}
