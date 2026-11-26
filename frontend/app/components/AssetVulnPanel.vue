<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { AssetVuln } from '~/types'
import type { TableColumn } from '~/types/table'
import type { ApiError } from '~/api'

// Open findings of an asset, most exposed first. Deferred ones are hidden unless asked for;
// a finding can be judged not affected for its component version, this asset or its group.
const props = defineProps<{
  asset: { id: string; name: string; group?: string }
  items: AssetVuln[]
  pending: boolean
  error?: ApiError
}>()
const emit = defineEmits<{ retry: [] }>()

const hideDeferred = ref(true)
const deferredCount = computed(() => props.items.filter((v) => v.triage?.active).length)
const rows = computed(() => (hideDeferred.value ? props.items.filter((v) => !v.triage?.active) : props.items))

const picker = reactive({ open: false, vulnId: '', purl: '' })
function judge(v: AssetVuln) {
  Object.assign(picker, { open: true, vulnId: v.vulnId, purl: v.componentPurl ?? '' })
}

// Within one exposure a linked vulnerable function comes first, none last.
function reachRank(r: AssetVuln) {
  return r.reachability === 'symbol_present' ? 2 : r.reachability === 'symbol_absent' ? 0 : 1
}

const columns: TableColumn<AssetVuln>[] = [
  { key: 'vulnId', label: '취약점', sortValue: (r) => r.vulnId },
  { key: 'severity', label: '심각도', sortValue: (r) => -(r.score ?? -1) },
  { key: 'component', label: '컴포넌트', sortValue: (r) => `${r.componentName} ${r.componentVersion}` },
  { key: 'where', label: '위치', sortValue: (r) => r.container ?? '', hideBelow: 'md' },
  { key: 'exposure', label: '영향도', sortValue: (r) => -(exposureLevel[r.exposure] * 3 + reachRank(r)) },
  { key: 'fix', label: '수정', hideBelow: 'sm' },
  { key: 'triage', label: '판정' },
  { key: 'firstSeen', label: '발견', align: 'right', sortValue: (r) => r.firstSeen, hideBelow: 'md' },
]
</script>

<template>
  <Panel title="취약점" description="feed 서버가 찾은 취약점입니다. 영향도가 높은 것부터 보입니다." flush>
    <template #actions>
      <label class="inline-flex items-center gap-1.5 text-sm">
        <input v-model="hideDeferred" type="checkbox" class="size-[15px] accent-(--accent)" /> 유예 숨김
        <span v-if="deferredCount" class="mono text-xs text-ink-3">{{ deferredCount }}</span>
      </label>
    </template>
    <LoadError v-if="error" :error="error" @retry="emit('retry')" />
    <DataTable
      v-else
      :columns="columns"
      :rows="rows"
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
        <span class="mono ml-1 text-xs text-ink-2">{{ versionText(row.componentVersion, row.componentBuild) }}</span>
      </template>
      <template #cell-where="{ row }">
        <span class="text-xs">{{ findingLayerLabel[row.layer] }}</span>
        <span v-if="row.container" class="mono ml-1 text-xs text-ink-2">{{ row.container }}</span>
      </template>
      <template #cell-exposure="{ row }">
        <ExposureMeter :exposure="row.exposure" />
        <ReachabilityBadge :reachability="row.reachability" :symbols="row.symbols" />
        <div v-if="row.processes.length" class="mono text-xs text-ink-3">
          {{ row.processes[0]!.exe.split('/').pop() }}<template v-if="row.processes[0]!.ports.length"> · {{ row.processes[0]!.ports.join(', ') }}</template>
        </div>
      </template>
      <template #cell-fix="{ row }">
        <span v-if="row.fixedVersion" class="mono whitespace-nowrap text-xs">→ {{ row.fixedVersion }}</span>
        <span v-else class="whitespace-nowrap text-xs text-ink-3">{{ fixStateLabel[row.fixState] }}</span>
      </template>
      <template #cell-firstSeen="{ row }"><span class="whitespace-nowrap text-xs">{{ formatDate(row.firstSeen) }}</span></template>
      <template #cell-triage="{ row }">
        <TriageRuleBadge v-if="row.triage" :rule="row.triage" @changed="emit('retry')" />
        <button v-if="!row.triage?.active" type="button" class="link block text-xs" @click="judge(row)">판정…</button>
      </template>
    </DataTable>
    <TriagePicker v-model:open="picker.open" :vuln-id="picker.vulnId" :purl="picker.purl" :asset="asset" @saved="emit('retry')" />
  </Panel>
</template>
