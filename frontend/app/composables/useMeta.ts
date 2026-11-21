// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

import { getMeta } from '~/api'
import type { Meta } from '~/types'

let loading: Promise<void> | undefined

/** Server version and features. Requested once per page load; undefined until it arrives. */
export function useMeta() {
  const meta = useState<Meta | undefined>('meta', () => undefined)
  if (!meta.value && !loading) {
    loading = getMeta()
      .then((m) => {
        meta.value = m
      })
      .catch(() => {
        // Retried by the next caller.
        loading = undefined
      })
  }
  return meta
}
