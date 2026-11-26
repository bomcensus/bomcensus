<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts" generic="T">
import { ChevronDown, ChevronUp } from '@lucide/vue'
import type { TableColumn } from '~/types/table'

// A table with sorting and pagination.
// Cell content is replaced through the #cell-<key>="{ row }" slot. Without a slot, row[key] is shown as is.
//
// Without `total`, rows are every row: the table sorts (column sortValue) and pages them itself.
// With `total`, rows are one page the server sorted (useServerList): headers with a column `sort`
// change v-model:sort, and the pager changes v-model:page and v-model:size.
const props = withDefaults(
  defineProps<{
    columns: TableColumn<T>[]
    rows: T[]
    rowKey: (row: T) => string
    /** When given, clicking a row navigates. The name cell gets its own NuxtLink. */
    rowTo?: (row: T) => string | undefined
    empty?: string
    emptyDescription?: string
    /** Rows per page. Default 25. 0 disables pagination */
    pageSize?: number
    initialSort?: { key: string; dir: 'asc' | 'desc' }
    /** While true and there are no rows, a loading line is shown; rows already shown are dimmed */
    loading?: boolean
    /** Matches on the server. Set for a server-paged list */
    total?: number
  }>(),
  { pageSize: 25, empty: '결과 없음' },
)

defineSlots<{ [name: string]: (props: { row: T }) => unknown }>()

/** Server sort: a column `sort` value, prefixed with '-' for descending */
const serverSort = defineModel<string>('sort')
const serverPage = defineModel<number>('page')
const serverSize = defineModel<number>('size')

const server = computed(() => props.total !== undefined)

const localSort = ref(props.initialSort ? { ...props.initialSort } : undefined)
const localPage = ref(0)
const localSize = ref(props.pageSize)

const page = computed({
  get: () => (server.value ? (serverPage.value ?? 0) : localPage.value),
  set: (v: number) => (server.value ? (serverPage.value = v) : (localPage.value = v)),
})
const size = computed({
  get: () => (server.value ? (serverSize.value ?? props.pageSize) : localSize.value),
  set: (v: number) => (server.value ? (serverSize.value = v) : (localSize.value = v)),
})

/** The sorted column and direction */
const active = computed<{ key: string; dir: 'asc' | 'desc' } | undefined>(() => {
  if (!server.value) return localSort.value
  const s = serverSort.value ?? ''
  const field = s.replace(/^-/, '')
  const column = props.columns.find((c) => c.sort === field)
  return column ? { key: column.key, dir: s.startsWith('-') ? 'desc' : 'asc' } : undefined
})

const sortable = (c: TableColumn<T>) => (server.value ? !!c.sort : !!c.sortValue)

const sorted = computed(() => {
  if (server.value) return props.rows
  const column = props.columns.find((c) => c.key === active.value?.key)
  if (!column?.sortValue) return props.rows
  const value = column.sortValue
  const dir = active.value?.dir === 'desc' ? -1 : 1
  return [...props.rows].sort((a, b) => {
    const x = value(a)
    const y = value(b)
    if (x === y) return 0
    if (x === undefined) return 1
    if (y === undefined) return -1
    return (x < y ? -1 : 1) * dir
  })
})

const count = computed(() => (server.value ? (props.total ?? 0) : sorted.value.length))
const visible = computed(() => {
  if (server.value || size.value <= 0) return sorted.value
  return sorted.value.slice(page.value * size.value, (page.value + 1) * size.value)
})
const sizeOptions = [25, 50, 100]
// The pager shows once there are more rows than the smallest page size
const showPager = computed(
  () => size.value > 0 && (page.value > 0 || count.value > Math.min(props.pageSize, sizeOptions[0]!)) && !(props.loading && props.rows.length === 0),
)

watch(localSize, () => (localPage.value = 0))
watch(
  () => props.rows,
  () => {
    if (!server.value) localPage.value = 0
  },
)

function toggleSort(column: TableColumn<T>) {
  if (!sortable(column)) return
  const first: 'asc' | 'desc' = column.sortDesc ? 'desc' : 'asc'
  const dir = active.value?.key === column.key ? (active.value.dir === 'asc' ? 'desc' : 'asc') : first
  if (server.value) {
    serverSort.value = dir === 'desc' ? `-${column.sort}` : column.sort
  } else {
    localSort.value = { key: column.key, dir }
    localPage.value = 0
  }
}

function open(row: T, event: MouseEvent) {
  const to = props.rowTo?.(row)
  if (!to) return
  // Clicks on a link or button inside a cell are left to that element
  if ((event.target as HTMLElement).closest('a, button, input, select, label')) return
  if (window.getSelection()?.toString()) return
  navigateTo(to)
}

const alignClass = { left: 'text-left', right: 'text-right', center: 'text-center' }
const hideClass = { sm: 'hidden sm:table-cell', md: 'hidden md:table-cell', lg: 'hidden lg:table-cell' }
const cellClass = (c: TableColumn<T>) => [alignClass[c.align ?? 'left'], c.hideBelow ? hideClass[c.hideBelow] : '']
const cellValue = (row: T, key: string) => (row as Record<string, unknown>)[key]
</script>

<template>
  <div class="min-w-0">
    <div class="overflow-x-auto">
      <table class="w-full border-collapse text-sm">
        <thead>
          <tr class="border-b border-line bg-surface-2 text-xs text-ink-2">
            <th
              v-for="c in columns"
              :key="c.key"
              scope="col"
              class="whitespace-nowrap px-3 py-2 font-medium"
              :class="cellClass(c)"
              :style="c.width ? { width: c.width } : undefined"
              :aria-sort="active?.key === c.key ? (active.dir === 'asc' ? 'ascending' : 'descending') : undefined"
            >
              <button
                v-if="sortable(c)"
                type="button"
                class="inline-flex items-center gap-0.5 hover:text-ink"
                :class="active?.key === c.key ? 'text-ink' : ''"
                @click="toggleSort(c)"
              >
                {{ c.label }}
                <component
                  :is="active?.key === c.key && active.dir === 'desc' ? ChevronDown : ChevronUp"
                  :size="12"
                  :class="active?.key === c.key ? '' : 'opacity-0'"
                  aria-hidden="true"
                />
              </button>
              <template v-else>{{ c.label }}</template>
            </th>
          </tr>
        </thead>
        <tbody v-if="rows.length" :class="loading ? 'opacity-60 transition-opacity' : ''" :aria-busy="loading || undefined">
          <tr
            v-for="row in visible"
            :key="rowKey(row)"
            class="border-b border-line last:border-b-0"
            :class="rowTo?.(row) ? 'cursor-pointer hover:bg-surface-2' : ''"
            @click="open(row, $event)"
          >
            <td v-for="c in columns" :key="c.key" class="px-3 py-2 align-top" :class="[cellClass(c), c.mono ? 'mono' : '']">
              <slot :name="`cell-${c.key}`" :row="row">{{ cellValue(row, c.key) ?? '—' }}</slot>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <LoadingText v-if="loading && rows.length === 0" />
    <EmptyState v-else-if="rows.length === 0" :title="empty" :description="emptyDescription" />

    <TablePager v-if="showPager" v-model:page="page" v-model:size="size" :total="count" :sizes="sizeOptions" />
  </div>
</template>
