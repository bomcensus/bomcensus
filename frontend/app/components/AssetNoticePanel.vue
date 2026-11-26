<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { AssetNotice } from '~/types'
import type { TableColumn } from '~/types/table'
import type { ApiError } from '~/api'
import { markNoticesRead, toApiError } from '~/api'

// Security notices that name software installed on an asset, read ones included. Unread first, then the newest.
const props = defineProps<{ items: AssetNotice[]; pending: boolean; error?: ApiError }>()
const emit = defineEmits<{ retry: [] }>()

const busy = ref(false)
const markError = ref('')
async function markRead(id: string) {
  busy.value = true
  markError.value = ''
  try {
    await markNoticesRead([id])
    await refreshNuxtData('notices:summary')
    emit('retry')
  } catch (e) {
    markError.value = toApiError(e).message
  } finally {
    busy.value = false
  }
}

const unread = computed(() => props.items.filter((n) => n.notice.unread).length)

const columns: TableColumn<AssetNotice>[] = [
  { key: 'title', label: '공지', sortValue: (r) => r.notice.title },
  { key: 'component', label: '컴포넌트', sortValue: (r) => r.matches[0]?.componentName ?? '' },
  { key: 'published', label: '공개', sortValue: (r) => r.notice.published ?? '', hideBelow: 'sm' },
  { key: 'state', label: '상태', sortValue: (r) => (r.notice.unread ? 0 : 1) },
]
</script>

<template>
  <Panel
    title="보안 공지"
    description="이 자산에 설치된 소프트웨어를 다루는 공지입니다. 버전은 비교하지 않았습니다."
    flush
  >
    <template #actions>
      <span v-if="unread" class="text-xs text-ink-2">읽지 않음 <span class="mono">{{ unread }}</span></span>
    </template>
    <p v-if="markError" class="note note-danger mx-3.5 my-2" role="alert">{{ markError }}</p>
    <LoadError v-if="error" :error="error" @retry="emit('retry')" />
    <DataTable
      v-else
      :columns="columns"
      :rows="items"
      :row-key="(r) => r.notice.noticeId"
      :loading="pending && !items.length"
      :page-size="50"
      empty="이 자산과 일치하는 공지가 없습니다"
    >
      <template #cell-title="{ row }">
        <span class="text-xs text-ink-3">{{ noticeSource(row.notice.source) }}</span>
        <NuxtLink
          :to="`/notices?id=${encodeURIComponent(row.notice.noticeId)}`"
          class="block max-w-[60ch] hover:underline"
          :class="row.notice.unread ? 'font-medium' : 'text-ink-2'"
        >{{ row.notice.title }}</NuxtLink>
        <div v-if="row.notice.cveIds.length" class="mono text-xs text-ink-3">{{ row.notice.cveIds.slice(0, 3).join(', ') }}<template v-if="row.notice.cveIds.length > 3"> 외 {{ row.notice.cveIds.length - 3 }}</template></div>
      </template>
      <template #cell-component="{ row }">
        <div v-for="m in row.matches" :key="`${m.container ?? ''}/${m.componentId}`">
          <NuxtLink :to="`/components/${m.componentId}`" class="hover:underline">{{ m.componentName }}</NuxtLink>
          <span class="mono ml-1 text-xs text-ink-2">{{ m.componentVersion }}</span>
          <span v-if="m.container" class="ml-1 text-xs text-ink-3">{{ m.container }}</span>
        </div>
      </template>
      <template #cell-published="{ row }"><span class="whitespace-nowrap text-xs">{{ formatDate(row.notice.published) }}</span></template>
      <template #cell-state="{ row }">
        <template v-if="row.notice.unread">
          <StatusBadge tone="warn" :label="row.notice.readAt ? '새로 발견' : '읽지 않음'" dot />
          <button type="button" class="link block text-xs" title="이 공지를 모든 자산에서 읽음으로 표시합니다" :disabled="busy" @click="markRead(row.notice.noticeId)">
            읽음으로 표시
          </button>
        </template>
        <StatusBadge v-else label="읽음" />
      </template>
    </DataTable>
  </Panel>
</template>
