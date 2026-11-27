<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { ExeState, ListenPortRow, ProcessInfo } from '~/types'
import type { TableColumn } from '~/types/table'
import { listListenPorts, listProcesses, type QueryOf } from '~/api'

useHead({ title: '프로세스 · bomcensus' })

type ProcessView = 'restart' | 'suspicious' | 'all'
const tabKeys = ['restart', 'suspicious', 'ports', 'all']
const route = useRoute()
// Read before the lists are created, so that a tab from the URL does not reset their page
const tab = ref(typeof route.query.view === 'string' && tabKeys.includes(route.query.view) ? route.query.view : 'restart')

const empty = { items: [], total: 0 }

// One process list; its view follows the tab. The state filter applies to the All tab only.
const {
  items: processes,
  total: processTotal,
  pending: processesPending,
  error: processesError,
  refresh: refreshProcesses,
  q,
  filters,
  sort,
  page,
  size,
} = useServerList(
  'processes',
  (p) => {
    if (tab.value === 'ports') return Promise.resolve(empty)
    const { state, ...rest } = p
    return listProcesses({ ...rest, view: tab.value as ProcessView, state: tab.value === 'all' ? state : undefined } as QueryOf<typeof listProcesses>)
  },
  { filters: { state: '' }, sort: 'asset', url: true, deps: () => tab.value },
)

const {
  items: portRows,
  total: portTotal,
  pending: portsPending,
  error: portsError,
  refresh: refreshPorts,
  q: portQ,
  filters: portFilters,
  sort: portSort,
  page: portPage,
  size: portSize,
} = useServerList(
  'listen-ports',
  (p) => (tab.value === 'ports' ? listListenPorts(p as QueryOf<typeof listListenPorts>) : Promise.resolve(empty)),
  { filters: { proto: '' }, sort: 'port', url: 'ports', deps: () => tab.value },
)

// Unfiltered counts of the tabs
const { data: counts } = useLoad('processes:counts', async () => {
  const [restart, suspicious, all, ports] = await Promise.all([
    listProcesses({ view: 'restart', limit: 1 }),
    listProcesses({ view: 'suspicious', limit: 1 }),
    listProcesses({ view: 'all', limit: 1 }),
    listListenPorts({ limit: 1 }),
  ])
  return { restart: restart.total, suspicious: suspicious.total, all: all.total, ports: ports.total }
})

const tabs = computed(() => [
  { key: 'restart', label: '재시작 필요', count: counts.value?.restart },
  { key: 'suspicious', label: '의심 프로세스', count: counts.value?.suspicious },
  { key: 'ports', label: 'listen 포트', count: counts.value?.ports },
  { key: 'all', label: '전체', count: counts.value?.all },
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
  { key: 'asset', label: '자산', sort: 'asset' },
  { key: 'process', label: '프로세스', sort: 'exe' },
  { key: 'user', label: '사용자', sort: 'user', hideBelow: 'sm' },
]
const restartColumns: TableColumn<ProcessInfo>[] = [
  ...baseColumns,
  { key: 'files', label: '교체된 파일', hideBelow: 'md' },
  { key: 'startedAt', label: '시작', align: 'right', sort: 'startedAt', sortDesc: true, hideBelow: 'sm' },
]
const suspiciousColumns: TableColumn<ProcessInfo>[] = [
  ...baseColumns,
  { key: 'state', label: '상태', sort: 'state' },
  { key: 'path', label: '경로', hideBelow: 'md' },
  { key: 'sha', label: 'sha256', hideBelow: 'lg' },
  { key: 'startedAt', label: '시작', align: 'right', sort: 'startedAt', sortDesc: true, hideBelow: 'sm' },
]
const portColumns: TableColumn<ListenPortRow>[] = [
  { key: 'port', label: '포트', sort: 'port' },
  { key: 'bind', label: 'bind 주소', sort: 'address', hideBelow: 'sm' },
  { key: 'process', label: '프로세스', sort: 'process' },
  { key: 'user', label: '사용자', sort: 'user', hideBelow: 'md' },
  { key: 'asset', label: '자산', sort: 'asset' },
  { key: 'component', label: '컴포넌트', hideBelow: 'lg' },
]
const allColumns: TableColumn<ProcessInfo>[] = [
  ...baseColumns,
  { key: 'state', label: '상태', sort: 'state' },
  { key: 'path', label: '경로', hideBelow: 'md' },
  { key: 'startedAt', label: '시작', align: 'right', sort: 'startedAt', sortDesc: true, hideBelow: 'sm' },
]

const stateOptions = (Object.keys(exeStateLabel) as ExeState[]).map((value) => ({ value, label: exeStateLabel[value] }))
const protoOptions = [
  { value: 'tcp', label: 'TCP' },
  { value: 'udp', label: 'UDP' },
]
</script>

<template>
  <div>
    <PageHeader title="프로세스" />

    <AppTabs v-model="tab" :tabs="tabs" query-key="view" />

    <div class="mt-3">
      <FilterBar v-if="tab === 'ports'" :count="portTotal" unit="개">
        <SearchInput v-model="portQ" placeholder="주소, 포트, 프로세스, 자산" />
        <SelectFilter v-model="portFilters.proto" label="프로토콜" :options="protoOptions" />
      </FilterBar>
      <FilterBar v-else :count="processTotal" unit="개">
        <SearchInput v-model="q" placeholder="실행 파일, 사용자, cmdline, 자산" />
        <SelectFilter v-if="tab === 'all'" v-model="filters.state" label="상태" :options="stateOptions" />
      </FilterBar>

      <template v-if="tab === 'restart'">
        <Panel flush>
          <LoadError v-if="processesError" :error="processesError" @retry="refreshProcesses" />
          <DataTable v-else :columns="restartColumns" v-model:sort="sort" v-model:page="page" v-model:size="size" :total="processTotal" :loading="processesPending" :rows="processes" :row-key="(p) => p.id">
            <template #cell-asset="{ row }">
              <NuxtLink :to="`/assets/${row.assetId}?tab=processes`" class="link">{{ row.assetName }}</NuxtLink>
              <span v-if="row.node" class="mono whitespace-nowrap text-xs text-ink-3"> @ {{ row.node }}</span>
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
          <DataTable v-else :columns="suspiciousColumns" v-model:sort="sort" v-model:page="page" v-model:size="size" :total="processTotal" :loading="processesPending" :rows="processes" :row-key="(p) => p.id">
            <template #cell-asset="{ row }">
              <NuxtLink :to="`/assets/${row.assetId}?tab=processes`" class="link">{{ row.assetName }}</NuxtLink>
              <span v-if="row.node" class="mono whitespace-nowrap text-xs text-ink-3"> @ {{ row.node }}</span>
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
          <DataTable v-else :columns="portColumns" v-model:sort="portSort" v-model:page="portPage" v-model:size="portSize" :total="portTotal" :loading="portsPending" :rows="portRows" :row-key="(r) => `${r.assetId}/${r.container ?? ''}/${r.processId ?? ''}/${r.proto}/${r.address}/${r.port}`">
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
              <span v-if="row.node" class="mono whitespace-nowrap text-xs text-ink-3"> @ {{ row.node }}</span>
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
        <Panel flush>
          <LoadError v-if="processesError" :error="processesError" @retry="refreshProcesses" />
          <DataTable v-else :columns="allColumns" v-model:sort="sort" v-model:page="page" v-model:size="size" :total="processTotal" :loading="processesPending" :rows="processes" :row-key="(p) => p.id">
            <template #cell-asset="{ row }">
              <NuxtLink :to="`/assets/${row.assetId}?tab=processes`" class="link">{{ row.assetName }}</NuxtLink>
              <span v-if="row.node" class="mono whitespace-nowrap text-xs text-ink-3"> @ {{ row.node }}</span>
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
