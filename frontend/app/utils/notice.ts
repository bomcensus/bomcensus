// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

import type { Notice, NoticeMatch } from '~/types'

/** Display names of notice sources; other sources are shown as sent. */
export const noticeSourceLabel: Record<string, string> = {
  kisa: 'KISA',
  tmaxsoft: 'TmaxSoft',
}

export const noticeSource = (source: string) => noticeSourceLabel[source] ?? source

/** The notice link, only when it is a web address (the server checks this too). */
export function noticeLink(n: Pick<Notice, 'url'>): string | undefined {
  return n.url && /^https?:\/\//i.test(n.url) ? n.url : undefined
}

/** Why a notice that was read is unread again, empty when it is not. */
export function reopenedReason(n: Notice): string {
  if (!n.unread || !n.readAt) return ''
  const who = n.readBy ? `${n.readBy}님이 ` : ''
  return `${who}${formatDateTime(n.readAt)}에 읽음으로 표시한 뒤 자산 ${n.newAssets}곳에서 새로 발견되었습니다.`
}

/** Where the component is on the asset: the container, then the first location. */
export function matchPlace(m: NoticeMatch): string {
  const where = m.locations[0] ?? ''
  return m.container ? `${m.container}${where ? ` · ${where}` : ''}` : where
}
