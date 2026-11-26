// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

import type { Ref } from 'vue'
import type { LocationQuery, LocationQueryRaw } from 'vue-router'
import { type ApiError, toApiError } from '~/api'

/** A filter value. '' and false do not filter. */
export type FilterValue = string | boolean

/** What the loader of a server list receives: a page, the sort, the search and the filters that are set. */
export type ListParams<F extends Record<string, FilterValue>> = {
  limit: number
  offset: number
  sort?: string
  q?: string
} & { [K in keyof F]?: F[K] extends boolean ? true : string }

export interface ServerListOptions<F extends Record<string, FilterValue>> {
  /** Filters with their initial ("All") values */
  filters?: F
  /** The sort the server uses when none is given (for example 'name' or '-createdAt') */
  sort?: string
  /** Rows per page. Default 25 */
  pageSize?: number
  /**
   * Keeps search, filters, sort and page in the URL query so that going back restores them.
   * true uses plain keys (q, sort, page, …); a string prefixes them (`ports.q`) for a second list on the page.
   */
  url?: boolean | string
  /** Other reactive inputs of the loader. A change reloads from the first page */
  deps?: () => unknown
}

export interface ServerList<T, F extends Record<string, FilterValue>> {
  items: Ref<T[]>
  /** Matches on the server */
  total: Ref<number>
  pending: Ref<boolean>
  error: Ref<ApiError | undefined>
  refresh: () => Promise<void>
  /** Search text as typed; it goes to the server once typing pauses */
  q: Ref<string>
  filters: F
  sort: Ref<string>
  /** Zero-based */
  page: Ref<number>
  size: Ref<number>
  /** True while any filter or the search is set */
  filtered: Ref<boolean>
  reset: () => void
}

const debounceMs = 300

/**
 * A list that the server searches, filters, sorts and pages. Only the current page is loaded.
 * `key` must be unique per list (for example `asset:${id}:components`).
 *
 *   const { items, total, pending, error, refresh, q, filters, sort, page, size } = useServerList(
 *     'assets',
 *     (p) => listAssets(p as AssetQuery),
 *     { filters: { kind: '', inUse: false }, sort: 'name', url: true },
 *   )
 */
export function useServerList<T, F extends Record<string, FilterValue> = Record<never, FilterValue>>(
  key: string,
  loader: (params: ListParams<F>) => Promise<{ items: T[]; total: number }>,
  options: ServerListOptions<F> = {},
): ServerList<T, F> {
  const route = useRoute()
  const router = useRouter()
  const initialFilters = { ...(options.filters ?? ({} as F)) }
  const defaultSort = options.sort ?? ''
  const defaultSize = options.pageSize ?? 25
  const prefix = typeof options.url === 'string' ? `${options.url}.` : ''

  const q = ref('')
  const qSent = ref('')
  const filters = reactive({ ...initialFilters }) as F
  const sort = ref(defaultSort)
  const page = ref(0)
  const size = ref(defaultSize)

  if (options.url) readQuery(route.query)

  function readQuery(query: LocationQuery) {
    const get = (name: string) => {
      const v = query[prefix + name]
      return typeof v === 'string' ? v : undefined
    }
    q.value = qSent.value = get('q') ?? ''
    for (const name of Object.keys(initialFilters) as (keyof F & string)[]) {
      const v = get(name)
      if (v === undefined) continue
      ;(filters as Record<string, FilterValue>)[name] = typeof initialFilters[name] === 'boolean' ? v === '1' || v === 'true' : v
    }
    sort.value = get('sort') ?? defaultSort
    const n = Number(get('size'))
    if (Number.isInteger(n) && n > 0) size.value = n
    const p = Number(get('page'))
    if (Number.isInteger(p) && p > 1) page.value = p - 1
  }

  let timer: ReturnType<typeof setTimeout> | undefined
  watch(q, (v) => {
    clearTimeout(timer)
    timer = setTimeout(() => (qSent.value = v.trim()), debounceMs)
  })
  onScopeDispose(() => clearTimeout(timer))

  const activeFilters = computed(() => {
    const out: Record<string, string | true> = {}
    for (const [name, v] of Object.entries(filters as Record<string, FilterValue>)) {
      if (v === true) out[name] = true
      else if (typeof v === 'string' && v !== '') out[name] = v
    }
    return out
  })

  // Anything but the page starts over from the first page.
  watch([qSent, activeFilters, sort, size, () => options.deps?.()], () => (page.value = 0), { deep: true })

  const params = computed(
    () =>
      ({
        limit: size.value,
        offset: page.value * size.value,
        sort: sort.value || undefined,
        q: qSent.value || undefined,
        ...activeFilters.value,
      }) as ListParams<F>,
  )

  const error = shallowRef<ApiError>()
  const res = useAsyncData(
    `list:${key}`,
    async () => {
      error.value = undefined
      try {
        return await loader(params.value)
      } catch (e) {
        error.value = toApiError(e)
        throw e
      }
    },
    {
      lazy: true,
      default: () => ({ items: [] as T[], total: 0 }),
      watch: [params, () => options.deps?.()],
    },
  )

  const items = computed(() => res.data.value?.items ?? [])
  const total = computed(() => res.data.value?.total ?? 0)

  // A page past the end (rows removed meanwhile) moves to the last page.
  watch(total, (t) => {
    if (page.value > 0 && page.value * size.value >= t) page.value = Math.max(0, Math.ceil(t / size.value) - 1)
  })

  if (options.url) {
    watch([qSent, activeFilters, sort, page, size], () => {
      const query: LocationQueryRaw = { ...router.currentRoute.value.query }
      const set = (name: string, v: string | undefined) => {
        if (v === undefined || v === '') delete query[prefix + name]
        else query[prefix + name] = v
      }
      set('q', qSent.value)
      for (const name of Object.keys(initialFilters)) {
        const v = activeFilters.value[name]
        set(name, v === true ? '1' : v)
      }
      set('sort', sort.value === defaultSort ? undefined : sort.value)
      set('page', page.value > 0 ? String(page.value + 1) : undefined)
      set('size', size.value === defaultSize ? undefined : String(size.value))
      router.replace({ query })
    }, { deep: true })
  }

  const filtered = computed(() => !!qSent.value || Object.keys(activeFilters.value).length > 0)

  function reset() {
    q.value = qSent.value = ''
    Object.assign(filters, initialFilters)
  }

  return {
    items: items as Ref<T[]>,
    total: total as Ref<number>,
    pending: res.pending,
    error,
    refresh: () => res.refresh(),
    q,
    filters,
    sort,
    page,
    size,
    filtered: filtered as Ref<boolean>,
    reset,
  }
}
