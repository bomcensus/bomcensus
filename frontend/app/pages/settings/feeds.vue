<script setup lang="ts">
import { RefreshCw, Upload } from '@lucide/vue'
import type { Feed } from '~/types'
import type { TableColumn } from '~/types/table'
import { feeds as feedSource, MOCK_NOW } from '~/mock'

useHead({ title: '취약점 피드 · bomcensus' })

const feeds = ref<Feed[]>(feedSource.map((f) => ({ ...f })))
const modeLabel: Record<Feed['mode'], string> = { online: '온라인', offline: '오프라인' }
const statusLabel: Record<Feed['status'], string> = { ok: '정상', stale: '오래됨', error: '오류' }
const statusTone: Record<Feed['status'], Tone> = { ok: 'ok', stale: 'warn', error: 'danger' }

const columns: TableColumn<Feed>[] = [
  { key: 'name', label: '이름', sortValue: (f) => f.name },
  { key: 'covers', label: '대상', hideBelow: 'md' },
  { key: 'mode', label: '방식', sortValue: (f) => f.mode, hideBelow: 'sm' },
  { key: 'status', label: '상태', sortValue: (f) => f.status },
  { key: 'lastSync', label: '최근 동기화', sortValue: (f) => f.lastSync ?? '' },
  { key: 'advisories', label: '권고 수', align: 'right', sortValue: (f) => f.advisories, hideBelow: 'sm' },
  { key: 'message', label: '메시지', hideBelow: 'lg' },
  { key: 'actions', label: '', align: 'right' },
]

// 온라인 피드만 동기화할 수 있다
function sync(ids: string[]) {
  for (const f of feeds.value) {
    if (!ids.includes(f.id)) continue
    f.status = 'ok'
    f.lastSync = MOCK_NOW
    f.message = undefined
  }
}
const onlineIds = computed(() => feeds.value.filter((f) => f.mode === 'online').map((f) => f.id))

const importOpen = ref(false)
</script>

<template>
  <div>
    <div class="mb-3 flex flex-wrap justify-end gap-2">
      <AppButton :icon="Upload" @click="importOpen = true">오프라인 DB import</AppButton>
      <AppButton variant="primary" :icon="RefreshCw" :disabled="!onlineIds.length" @click="sync(onlineIds)">동기화</AppButton>
    </div>

    <Panel flush>
      <DataTable :columns="columns" :rows="feeds" :row-key="(f) => f.id">
        <template #cell-name="{ row }"><span class="font-medium">{{ row.name }}</span></template>
        <template #cell-covers="{ row }">{{ row.covers }}</template>
        <template #cell-mode="{ row }">{{ modeLabel[row.mode] }}</template>
        <template #cell-status="{ row }"><StatusBadge :tone="statusTone[row.status]" :label="statusLabel[row.status]" dot /></template>
        <template #cell-lastSync="{ row }"><TimeAgo v-if="row.lastSync" :at="row.lastSync" class="whitespace-nowrap text-ink-2" /><span v-else class="text-ink-3">동기화 이력 없음</span></template>
        <template #cell-advisories="{ row }"><span class="mono whitespace-nowrap">{{ formatNumber(row.advisories) }}</span></template>
        <template #cell-message="{ row }"><span class="text-ink-2">{{ row.message ?? '—' }}</span></template>
        <template #cell-actions="{ row }">
          <AppButton v-if="row.mode === 'online'" size="sm" @click="sync([row.id])">동기화</AppButton>
        </template>
      </DataTable>
    </Panel>

    <AppModal v-model:open="importOpen" title="오프라인 DB import">
      <FormField label="번들 파일"><input type="file" class="input w-full" /></FormField>
      <template #footer>
        <AppButton @click="importOpen = false">취소</AppButton>
        <AppButton variant="primary" @click="importOpen = false">import</AppButton>
      </template>
    </AppModal>
  </div>
</template>
