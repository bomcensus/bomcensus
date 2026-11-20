<script setup lang="ts" generic="T">
import { ChevronDown, ChevronUp } from '@lucide/vue'
import type { TableColumn } from '~/types/table'

// 정렬과 페이지 나눔이 있는 표.
// 셀 내용은 #cell-<key>="{ row }" 슬롯으로 바꾼다. 슬롯이 없으면 row[key] 를 그대로 보여 준다.
const props = withDefaults(
  defineProps<{
    columns: TableColumn<T>[]
    rows: T[]
    rowKey: (row: T) => string
    /** 주면 행을 눌러 이동한다. 이름 셀에는 따로 NuxtLink 를 둔다. */
    rowTo?: (row: T) => string | undefined
    empty?: string
    emptyDescription?: string
    /** 한 쪽에 보일 행 수. 기본 25. 0 이면 나누지 않는다 */
    pageSize?: number
    initialSort?: { key: string; dir: 'asc' | 'desc' }
  }>(),
  { pageSize: 25, empty: '결과 없음' },
)

defineSlots<{ [name: string]: (props: { row: T }) => unknown }>()

const sortKey = ref(props.initialSort?.key ?? '')
const sortDir = ref<'asc' | 'desc'>(props.initialSort?.dir ?? 'asc')
const page = ref(0)
const sizeOptions = [25, 50, 100]
const size = ref(props.pageSize)

const sorted = computed(() => {
  const column = props.columns.find((c) => c.key === sortKey.value)
  if (!column?.sortValue) return props.rows
  const value = column.sortValue
  const dir = sortDir.value === 'asc' ? 1 : -1
  return [...props.rows].sort((a, b) => {
    const x = value(a)
    const y = value(b)
    if (x === y) return 0
    if (x === undefined) return 1
    if (y === undefined) return -1
    return (x < y ? -1 : 1) * dir
  })
})

const pageCount = computed(() => (size.value > 0 ? Math.max(1, Math.ceil(sorted.value.length / size.value)) : 1))
const visible = computed(() =>
  size.value > 0 ? sorted.value.slice(page.value * size.value, (page.value + 1) * size.value) : sorted.value,
)
// 가장 작은 쪽 크기보다 행이 많을 때만 쪽 나눔 줄을 보인다
const showPager = computed(() => size.value > 0 && sorted.value.length > Math.min(props.pageSize, sizeOptions[0]!))

watch(size, () => (page.value = 0))

watch(
  () => props.rows,
  () => (page.value = 0),
)

function toggleSort(column: TableColumn<T>) {
  if (!column.sortValue) return
  if (sortKey.value === column.key) {
    sortDir.value = sortDir.value === 'asc' ? 'desc' : 'asc'
  } else {
    sortKey.value = column.key
    sortDir.value = 'asc'
  }
  page.value = 0
}

function open(row: T, event: MouseEvent) {
  const to = props.rowTo?.(row)
  if (!to) return
  // 셀 안의 링크나 버튼을 누른 경우는 그쪽 동작에 맡긴다
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
              :aria-sort="sortKey === c.key ? (sortDir === 'asc' ? 'ascending' : 'descending') : undefined"
            >
              <button
                v-if="c.sortValue"
                type="button"
                class="inline-flex items-center gap-0.5 hover:text-ink"
                :class="sortKey === c.key ? 'text-ink' : ''"
                @click="toggleSort(c)"
              >
                {{ c.label }}
                <component
                  :is="sortKey === c.key && sortDir === 'desc' ? ChevronDown : ChevronUp"
                  :size="12"
                  :class="sortKey === c.key ? '' : 'opacity-0'"
                  aria-hidden="true"
                />
              </button>
              <template v-else>{{ c.label }}</template>
            </th>
          </tr>
        </thead>
        <tbody>
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

    <EmptyState v-if="rows.length === 0" :title="empty" :description="emptyDescription" />

    <div v-if="showPager" class="flex flex-wrap items-center justify-between gap-2 border-t border-line px-3 py-2 text-xs text-ink-2">
      <span class="mono whitespace-nowrap">
        {{ page * size + 1 }}–{{ Math.min((page + 1) * size, sorted.length) }} / {{ formatNumber(sorted.length) }}
      </span>
      <span class="flex items-center gap-2">
        <label class="inline-flex items-center">
          <span class="sr-only">한 쪽에 보일 행 수</span>
          <select v-model.number="size" class="select h-7 px-1.5 text-xs">
            <option v-for="n in sizeOptions" :key="n" :value="n">{{ n }}행</option>
          </select>
        </label>
        <AppButton size="sm" :disabled="page === 0" @click="page--">이전</AppButton>
        <span class="mono whitespace-nowrap">{{ page + 1 }} / {{ pageCount }}</span>
        <AppButton size="sm" :disabled="page >= pageCount - 1" @click="page++">다음</AppButton>
      </span>
    </div>
  </div>
</template>
