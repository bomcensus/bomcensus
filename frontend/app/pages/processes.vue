<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { ExeState, ListenPortRow, ProcessInfo } from '~/types'
import type { TableColumn } from '~/types/table'
import { fetchAll, listListenPorts, listProcesses } from '~/api'

useHead({ title: '프로세스 · bomcensus' })

const tab = ref('restart')

const {
  data: processes,
  pending: processesPending,
  error: processesError,
  refresh: refreshProcesses,
} = useLoad('processes', () => fetchAll((page) => listProcesses(page)), () => [])
const {
  data: portRows,
  pending: portsPending,
  error: portsError,
  refresh: refreshPorts,
} = useLoad('listen-ports', () => fetchAll((page) => listListenPorts(page)), () => [])

const restartRows = computed(() => processes.value.filter(needsRestart))
const suspiciousRows = computed(() => processes.value.filter(isSuspicious))

const tabs = computed(() => [
  { key: 'restart', label: '재시작 필요', count: restartRows.value.length },
  { key: 'suspicious', label: '의심 프로세스', count: suspiciousRows.value.length },
  { key: 'ports', label: 'listen 포트', count: portRows.value.length },
  { key: 'all', label: '전체', count: processes.value.length },
])

const exeName = (path: string) => path.split(/[\\/]/).filter(Boolean).pop() ?? path

/** The replaced executable, or the replaced library if there is none */
const replacedFiles = (p: ProcessInfo): string[] => [
  ...(p.exeState === 'replaced' ? [p.exePath] : []),
  ...p.deletedLibs.filter((l) => l.state === 'replaced').map((l) => l.path),
]

/** Reason a process is suspicious */
function suspiciousState(p: ProcessInfo): string {
  if (p.exeState === 'deleted') return exeStateLabel.deleted
  if (p.exeState === 'memfd') return exeStateLabel.memfd
  return '삭제된 라이브러리'
}
const suspiciousTone = (p: ProcessInfo) => (p.exeState === 'deleted' || p.exeState === 'memfd' ? 'danger' : 'warn')

const baseColumns: TableColumn<ProcessInfo>[] = [
  { key: 'asset', label: '자산', sortValue: (p) => p.assetName },
  { key: 'process', label: '프로세스', sortValue: (p) => exeName(p.exePath) },
  { key: 'user', label: '사용자', sortValue: (p) => p.user, hideBelow: 'sm' },
]
const restartColumns: TableColumn<ProcessInfo>[] = [
  ...baseColumns,
  { key: 'files', label: '교체된 파일', hideBelow: 'md' },
  { key: 'startedAt', label: '시작', align: 'right', sortValue: (p) => p.startedAt, hideBelow: 'sm' },
]
const suspiciousColumns: TableColumn<ProcessInfo>[] = [
  ...baseColumns,
  { key: 'state', label: '상태', sortValue: (p) => suspiciousState(p) },
  { key: 'path', label: '경로', hideBelow: 'md' },
  { key: 'sha', label: 'sha256', hideBelow: 'lg' },
  { key: 'startedAt', label: '시작', align: 'right', sortValue: (p) => p.startedAt, hideBelow: 'sm' },
]
const portColumns: TableColumn<ListenPortRow>[] = [
  { key: 'port', label: '포트', sortValue: (r) => r.port },
  { key: 'bind', label: 'bind 주소', sortValue: (r) => r.address, hideBelow: 'sm' },
  { key: 'process', label: '프로세스', sortValue: (r) => (r.exePath ? exeName(r.exePath) : '') },
  { key: 'user', label: '사용자', sortValue: (r) => r.user ?? '', hideBelow: 'md' },
  { key: 'asset', label: '자산', sortValue: (r) => r.assetName },
  { key: 'component', label: '컴포넌트', hideBelow: 'lg' },
]
const allColumns: TableColumn<ProcessInfo>[] = [
  ...baseColumns,
  { key: 'state', label: '상태', sortValue: (p) => p.exeState },
  { key: 'path', label: '경로', hideBelow: 'md' },
  { key: 'startedAt', label: '시작', align: 'right', sortValue: (p) => p.startedAt, hideBelow: 'sm' },
]

// Filter for the All tab
const q = ref('')
const assetId = ref('')
const state = ref('')
const assetOptions = computed(() => {
  const byId = new Map(processes.value.map((p) => [p.assetId, p.assetName]))
  return [...byId].map(([value, label]) => ({ value, label })).sort((a, b) => a.label.localeCompare(b.label))
})
const stateOptions = (Object.keys(exeStateLabel) as ExeState[]).map((value) => ({ value, label: exeStateLabel[value] }))

const allRows = computed(() => {
  const needle = q.value.trim().toLowerCase()
  return processes.value.filter((p) => {
    if (assetId.value && p.assetId !== assetId.value) return false
    if (state.value && p.exeState !== state.value) return false
    if (!needle) return true
    return [exeName(p.exePath), p.exePath, p.user, p.cmdline].some((v) => v.toLowerCase().includes(needle))
  })
})
</script>

<template>
  <div>
    <PageHeader title="프로세스" />

    <AppTabs v-model="tab" :tabs="tabs" query-key="view" />

    <div class="mt-3">
      <template v-if="tab === 'restart'">
        <Panel flush>
          <LoadError v-if="processesError" :error="processesError" @retry="refreshProcesses" />
          <DataTable v-else :columns="restartColumns" :loading="processesPending" :rows="restartRows" :row-key="(p) => p.id" :page-size="25">
            <template #cell-asset="{ row }">
              <NuxtLink :to="`/assets/${row.assetId}?tab=processes`" class="link">{{ row.assetName }}</NuxtLink>
            </template>
            <template #cell-process="{ row }">
              <span class="mono">{{ exeName(row.exePath) }}</span> <span class="mono whitespace-nowrap text-xs text-ink-3">pid {{ row.pid }}</span>
            </template>
            <template #cell-files="{ row }">
              <div v-for="f in replacedFiles(row)" :key="f" class="mono text-xs break-all">{{ f }}</div>
            </template>
            <template #cell-startedAt="{ row }"><TimeAgo :at="row.startedAt" class="text-ink-2" /></template>
          </DataTable>
        </Panel>
      </template>

      <template v-else-if="tab === 'suspicious'">
        <Panel flush>
          <LoadError v-if="processesError" :error="processesError" @retry="refreshProcesses" />
          <DataTable v-else :columns="suspiciousColumns" :loading="processesPending" :rows="suspiciousRows" :row-key="(p) => p.id" :page-size="25">
            <template #cell-asset="{ row }">
              <NuxtLink :to="`/assets/${row.assetId}?tab=processes`" class="link">{{ row.assetName }}</NuxtLink>
            </template>
            <template #cell-process="{ row }">
              <span class="mono">{{ exeName(row.exePath) }}</span> <span class="mono whitespace-nowrap text-xs text-ink-3">pid {{ row.pid }}</span>
            </template>
            <template #cell-state="{ row }"><StatusBadge :tone="suspiciousTone(row)" :label="suspiciousState(row)" /></template>
            <template #cell-path="{ row }"><span class="mono text-xs break-all">{{ row.exePath }}</span></template>
            <template #cell-sha="{ row }"><span class="mono text-xs" :title="row.sha256">{{ shortHash(row.sha256) }}</span></template>
            <template #cell-startedAt="{ row }"><TimeAgo :at="row.startedAt" class="text-ink-2" /></template>
          </DataTable>
        </Panel>
      </template>

      <template v-else-if="tab === 'ports'">
        <Panel flush>
          <LoadError v-if="portsError" :error="portsError" @retry="refreshPorts" />
          <DataTable v-else :columns="portColumns" :loading="portsPending" :rows="portRows" :row-key="(r) => `${r.assetId}/${r.container ?? ''}/${r.proto}/${r.address}/${r.port}`" :page-size="25">
            <template #cell-port="{ row }"><span class="mono whitespace-nowrap">{{ row.proto }}/{{ row.port }}</span></template>
            <template #cell-bind="{ row }">
              <span class="mono whitespace-nowrap">{{ row.address }}</span>
            </template>
            <template #cell-process="{ row }">
              <template v-if="row.exePath">
                <span class="mono">{{ exeName(row.exePath) }}</span>
                <span v-if="row.pid !== undefined" class="mono whitespace-nowrap text-xs text-ink-3"> pid {{ row.pid }}</span>
              </template>
              <span v-else class="text-ink-3">—</span>
            </template>
            <template #cell-user="{ row }">{{ row.user ?? '—' }}</template>
            <template #cell-asset="{ row }">
              <NuxtLink :to="`/assets/${row.assetId}?tab=processes`" class="link">{{ row.assetName }}</NuxtLink>
            </template>
            <template #cell-component="{ row }">
              <NuxtLink v-if="row.componentId" :to="`/components/${encodeURIComponent(row.componentId)}`" class="link">
                {{ row.componentName ?? row.componentId }}
              </NuxtLink>
              <span v-else class="text-ink-3">—</span>
            </template>
          </DataTable>
        </Panel>
      </template>

      <template v-else>
        <FilterBar :count="allRows.length" :total="processes.length" unit="개">
          <SearchInput v-model="q" placeholder="실행 파일, 사용자, cmdline" />
          <SelectFilter v-model="assetId" label="자산" :options="assetOptions" />
          <SelectFilter v-model="state" label="상태" :options="stateOptions" />
        </FilterBar>
        <Panel flush>
          <LoadError v-if="processesError" :error="processesError" @retry="refreshProcesses" />
          <DataTable v-else :columns="allColumns" :loading="processesPending" :rows="allRows" :row-key="(p) => p.id" :page-size="25">
            <template #cell-asset="{ row }">
              <NuxtLink :to="`/assets/${row.assetId}?tab=processes`" class="link">{{ row.assetName }}</NuxtLink>
            </template>
            <template #cell-process="{ row }">
              <span class="mono">{{ exeName(row.exePath) }}</span> <span class="mono whitespace-nowrap text-xs text-ink-3">pid {{ row.pid }}</span>
            </template>
            <template #cell-state="{ row }"><StatusBadge :tone="exeStateTone[row.exeState]" :label="exeStateLabel[row.exeState]" /></template>
            <template #cell-path="{ row }">
              <span class="mono text-xs break-all">{{ row.exePath }}</span>
              <span v-if="row.exeSource === 'cmdline'" class="ml-1 text-xs text-ink-3">추정</span>
            </template>
            <template #cell-startedAt="{ row }"><TimeAgo :at="row.startedAt" class="text-ink-2" /></template>
          </DataTable>
        </Panel>
      </template>
    </div>
  </div>
</template>
