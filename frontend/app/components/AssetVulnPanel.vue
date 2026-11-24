<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { AssetVuln } from '~/types'
import type { TableColumn } from '~/types/table'
import type { ApiError } from '~/api'

// Open findings of an asset, most exposed first.
defineProps<{ items: AssetVuln[]; pending: boolean; error?: ApiError }>()
const emit = defineEmits<{ retry: [] }>()

const columns: TableColumn<AssetVuln>[] = [
  { key: 'vulnId', label: '취약점', sortValue: (r) => r.vulnId },
  { key: 'severity', label: '심각도', sortValue: (r) => -(r.score ?? -1) },
  { key: 'component', label: '컴포넌트', sortValue: (r) => `${r.componentName} ${r.componentVersion}` },
  { key: 'where', label: '위치', sortValue: (r) => r.container ?? '', hideBelow: 'md' },
  { key: 'exposure', label: '영향도', sortValue: (r) => -exposureLevel[r.exposure] },
  { key: 'fix', label: '수정', hideBelow: 'sm' },
  { key: 'firstSeen', label: '발견', align: 'right', sortValue: (r) => r.firstSeen, hideBelow: 'md' },
]
</script>

<template>
  <Panel title="취약점" description="feed 서버가 찾은 취약점입니다. 영향도가 높은 것부터 보입니다." flush>
    <LoadError v-if="error" :error="error" @retry="emit('retry')" />
    <DataTable
      v-else
      :columns="columns"
      :rows="items"
      :row-key="(r) => `${r.container ?? ''}/${r.componentId}/${r.vulnId}`"
      :loading="pending && !items.length"
      :page-size="50"
      empty="열린 취약점이 없습니다"
    >
      <template #cell-vulnId="{ row }">
        <NuxtLink :to="`/vulnerabilities?view=cve&id=${encodeURIComponent(row.vulnId)}`" class="mono whitespace-nowrap font-medium hover:underline">{{ row.vulnId }}</NuxtLink>
        <StatusBadge v-if="row.kev" class="ml-1" tone="danger" label="KEV" />
        <div v-if="row.summary" class="max-w-[44ch] text-xs text-ink-2">{{ row.summary }}</div>
      </template>
      <template #cell-severity="{ row }"><SeverityBadge :severity="row.severity" :score="row.score" /></template>
      <template #cell-component="{ row }">
        <NuxtLink :to="`/components/${row.componentId}`" class="hover:underline">{{ row.componentName }}</NuxtLink>
        <span class="mono ml-1 text-xs text-ink-2">{{ row.componentVersion }}</span>
      </template>
      <template #cell-where="{ row }">
        <span class="text-xs">{{ findingLayerLabel[row.layer] }}</span>
        <span v-if="row.container" class="mono ml-1 text-xs text-ink-2">{{ row.container }}</span>
      </template>
      <template #cell-exposure="{ row }">
        <ExposureMeter :exposure="row.exposure" />
        <div v-if="row.processes.length" class="mono text-xs text-ink-3">
          {{ row.processes[0]!.exe.split('/').pop() }}<template v-if="row.processes[0]!.ports.length"> · {{ row.processes[0]!.ports.join(', ') }}</template>
        </div>
      </template>
      <template #cell-fix="{ row }">
        <span v-if="row.fixedVersion" class="mono whitespace-nowrap text-xs">→ {{ row.fixedVersion }}</span>
        <span v-else class="whitespace-nowrap text-xs text-ink-3">{{ fixStateLabel[row.fixState] }}</span>
      </template>
      <template #cell-firstSeen="{ row }"><span class="whitespace-nowrap text-xs">{{ formatDate(row.firstSeen) }}</span></template>
    </DataTable>
  </Panel>
</template>
