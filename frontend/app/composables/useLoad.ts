// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

import type { MaybeRefOrGetter, Ref } from 'vue'
import { type ApiError, toApiError } from '~/api'

export interface Load<T> {
  data: Ref<T>
  pending: Ref<boolean>
  error: Ref<ApiError | undefined>
  refresh: () => Promise<void>
}

/**
 * Loads data for a page without blocking navigation.
 * `key` must be unique per resource (for example `asset:${id}`); a getter key reloads when it changes.
 * `data` holds `initial()` (or undefined) until the loader resolves and after it fails.
 */
export function useLoad<T>(key: MaybeRefOrGetter<string>, loader: () => Promise<T>): Load<T | undefined>
export function useLoad<T>(key: MaybeRefOrGetter<string>, loader: () => Promise<T>, initial: () => T): Load<T>
export function useLoad<T>(key: MaybeRefOrGetter<string>, loader: () => Promise<T>, initial?: () => T): Load<T | undefined> {
  const error = shallowRef<ApiError>()
  const res = useAsyncData(
    key,
    async () => {
      error.value = undefined
      try {
        return await loader()
      } catch (e) {
        error.value = toApiError(e)
        throw e
      }
    },
    { lazy: true, default: initial },
  )
  return {
    data: res.data as Ref<T | undefined>,
    pending: res.pending,
    error,
    refresh: () => res.refresh(),
  }
}
