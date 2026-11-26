<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import { ChevronsLeft, ChevronsRight } from '@lucide/vue'

// Pagination row under a list. `page` is zero-based. `compact` leaves out the page size choice.
const props = defineProps<{ total: number; compact?: boolean; sizes?: number[] }>()
const page = defineModel<number>('page', { required: true })
const size = defineModel<number>('size', { required: true })

const sizeOptions = computed(() => {
  const list = props.sizes ?? [25, 50, 100]
  return list.includes(size.value) ? list : [...list, size.value].sort((a, b) => a - b)
})
const pageCount = computed(() => Math.max(1, Math.ceil(props.total / size.value)))
const from = computed(() => (props.total === 0 ? 0 : page.value * size.value + 1))
const to = computed(() => Math.min((page.value + 1) * size.value, props.total))

function setSize(n: number) {
  size.value = n
  page.value = 0
}
</script>

<template>
  <div class="flex flex-wrap items-center justify-between gap-2 border-t border-line px-3 py-2 text-xs text-ink-2">
    <span class="mono whitespace-nowrap">{{ formatNumber(from) }}–{{ formatNumber(to) }} / {{ formatNumber(total) }}</span>
    <span class="flex items-center gap-1.5">
      <label v-if="!compact" class="inline-flex items-center">
        <span class="sr-only">한 쪽에 보일 행 수</span>
        <select :value="size" class="select h-7 px-1.5 text-xs" @change="setSize(Number(($event.target as HTMLSelectElement).value))">
          <option v-for="n in sizeOptions" :key="n" :value="n">{{ n }}행</option>
        </select>
      </label>
      <AppButton v-if="!compact" size="sm" variant="ghost" :icon="ChevronsLeft" :disabled="page === 0" aria-label="처음" @click="page = 0" />
      <AppButton size="sm" :disabled="page === 0" @click="page--">이전</AppButton>
      <span class="mono whitespace-nowrap">{{ page + 1 }} / {{ pageCount }}</span>
      <AppButton size="sm" :disabled="page >= pageCount - 1" @click="page++">다음</AppButton>
      <AppButton
        v-if="!compact"
        size="sm"
        variant="ghost"
        :icon="ChevronsRight"
        :disabled="page >= pageCount - 1"
        aria-label="마지막"
        @click="page = pageCount - 1"
      />
    </span>
  </div>
</template>
