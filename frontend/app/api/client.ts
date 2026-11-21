// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

import { navigateTo, useRouter } from '#imports'
import { client } from './gen/client.gen'
import { useCurrentUser } from '~/composables/useCurrentUser'

// The base URL (/api/v1) comes from admin.yaml. The session cookie must go with every request.
// The server rejects state-changing requests without this header (cross-site request protection).
client.setConfig({ credentials: 'include', headers: { 'X-Requested-With': 'bomcensus' } })

/** Error thrown by every call in ~/api. `status` is 0 when the server could not be reached. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

export function toApiError(e: unknown): ApiError {
  if (e instanceof ApiError) return e
  return new ApiError(0, 'client_error', e instanceof Error ? e.message : String(e))
}

interface SdkResult {
  data?: unknown
  error?: unknown
  response?: Response
}

// The data type of the success branch of a generated SDK result.
type DataOf<R> = R extends { data: infer D; error: undefined } ? D : never

function errorFrom(error: unknown, response: Response | undefined): ApiError {
  if (!response) {
    return new ApiError(0, 'network_error', error instanceof Error ? error.message : 'network error')
  }
  if (error && typeof error === 'object' && 'code' in error && 'message' in error) {
    return new ApiError(response.status, String(error.code), String(error.message))
  }
  const text = typeof error === 'string' ? error.trim() : ''
  return new ApiError(response.status, `http_${response.status}`, text.slice(0, 200) || response.statusText || `HTTP ${response.status}`)
}

function unauthorized() {
  useCurrentUser().value = null
  const route = useRouter().currentRoute.value
  if (route.path !== '/login') navigateTo({ path: '/login', query: { next: route.fullPath } })
}

/**
 * Awaits a generated SDK call and returns its data, or throws ApiError.
 * A 401 clears the session and goes to /login unless `redirect` is false.
 */
export async function call<R extends SdkResult>(request: Promise<R>, { redirect = true } = {}): Promise<DataOf<R>> {
  const { data, error, response } = await request
  if (response?.ok) return data as DataOf<R>
  const err = errorFrom(error, response)
  if (err.status === 401 && redirect) unauthorized()
  throw err
}

export interface Page {
  limit: number
  offset: number
}

/**
 * Loads every item of a list endpoint by paging through it 1000 items at a time.
 * Usage: fetchAll((page) => listAssets(page)), or fetchAll((page) => listAssetComponents(id, { ...page, includeRemoved: true })).
 */
export async function fetchAll<T>(list: (page: Page) => Promise<{ items: T[]; total: number }>): Promise<T[]> {
  const items: T[] = []
  for (;;) {
    const res = await list({ limit: 1000, offset: items.length })
    items.push(...res.items)
    if (res.items.length === 0 || items.length >= res.total) return items
  }
}

/** Resolves to undefined when the resource does not exist (404). Other errors are rethrown. */
export async function optional<T>(request: Promise<T>): Promise<T | undefined> {
  try {
    return await request
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) return undefined
    throw e
  }
}
