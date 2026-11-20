<script setup lang="ts">
import type { ExeState, ProcessInfo } from '~/types'
import type { TableColumn } from '~/types/table'
import { assets, getAsset, getComponent, isSuspicious, needsRestart, processes } from '~/mock'

useHead({ title: '프로세스 · bomcensus' })

const tab = ref('restart')

const restartRows = computed(() => processes.filter(needsRestart))
const suspiciousRows = computed(() => processes.filter(isSuspicious))

interface PortRow {
  key: string
  process: ProcessInfo
  proto: string
  address: string
  port: number
}
const portRows = computed<PortRow[]>(() =>
  processes.flatMap((p) =>
    p.listen.map((l, i) => ({ key: `${p.id}:${i}`, process: p, proto: l.proto, address: l.address, port: l.port })),
  ),
)

const tabs = computed(() => [
  { key: 'restart', label: '재시작 필요', count: restartRows.value.length },
  { key: 'suspicious', label: '의심 프로세스', count: suspiciousRows.value.length },
  { key: 'ports', label: 'listen 포트', count: portRows.value.length },
  { key: 'all', label: '전체', count: processes.length },
])

const assetName = (p: ProcessInfo) => getAsset(p.assetId)?.name ?? p.assetId
const exeName = (p: ProcessInfo) => p.exePath.split(/[\\/]/).filter(Boolean).pop() ?? p.exePath

/** 교체된 실행 파일, 없으면 교체된 라이브러리 */
const replacedFiles = (p: ProcessInfo): string[] => [
  ...(p.exeState === 'replaced' ? [p.exePath] : []),
  ...p.deletedLibs.filter((l) => l.state === 'replaced').map((l) => l.path),
]

/** 의심 프로세스 사유 */
function suspiciousState(p: ProcessInfo): string {
  if (p.exeState === 'deleted') return exeStateLabel.deleted
  if (p.exeState === 'memfd') return exeStateLabel.memfd
  return '삭제된 라이브러리'
}
const suspiciousTone = (p: ProcessInfo) => (p.exeState === 'deleted' || p.exeState === 'memfd' ? 'danger' : 'warn')

const baseColumns: TableColumn<ProcessInfo>[] = [
  { key: 'asset', label: '자산', sortValue: (p) => assetName(p) },
  { key: 'process', label: '프로세스', sortValue: (p) => exeName(p) },
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
const portColumns: TableColumn<PortRow>[] = [
  { key: 'port', label: '포트', sortValue: (r) => r.port },
  { key: 'bind', label: 'bind 주소', sortValue: (r) => r.address, hideBelow: 'sm' },
  { key: 'process', label: '프로세스', sortValue: (r) => exeName(r.process) },
  { key: 'user', label: '사용자', sortValue: (r) => r.process.user, hideBelow: 'md' },
  { key: 'asset', label: '자산', sortValue: (r) => assetName(r.process) },
  { key: 'component', label: '컴포넌트', hideBelow: 'lg' },
]
const allColumns: TableColumn<ProcessInfo>[] = [
  ...baseColumns,
  { key: 'state', label: '상태', sortValue: (p) => p.exeState },
  { key: 'path', label: '경로', hideBelow: 'md' },
  { key: 'startedAt', label: '시작', align: 'right', sortValue: (p) => p.startedAt, hideBelow: 'sm' },
]

// 전체 탭 필터
const q = ref('')
const assetId = ref('')
const state = ref('')
const assetOptions = computed(() => assets.map((a) => ({ value: a.id, label: a.name })))
const stateOptions = (Object.keys(exeStateLabel) as ExeState[]).map((value) => ({ value, label: exeStateLabel[value] }))

const allRows = computed(() => {
  const needle = q.value.trim().toLowerCase()
  return processes.filter((p) => {
    if (assetId.value && p.assetId !== assetId.value) return false
    if (state.value && p.exeState !== state.value) return false
    if (!needle) return true
    return [exeName(p), p.exePath, p.user, p.cmdline].some((v) => v.toLowerCase().includes(needle))
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
          <DataTable :columns="restartColumns" :rows="restartRows" :row-key="(p) => p.id" :page-size="25">
            <template #cell-asset="{ row }">
              <NuxtLink :to="`/assets/${row.assetId}?tab=processes`" class="link">{{ assetName(row) }}</NuxtLink>
            </template>
            <template #cell-process="{ row }">
              <span class="mono">{{ exeName(row) }}</span> <span class="mono whitespace-nowrap text-xs text-ink-3">pid {{ row.pid }}</span>
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
          <DataTable :columns="suspiciousColumns" :rows="suspiciousRows" :row-key="(p) => p.id" :page-size="25">
            <template #cell-asset="{ row }">
              <NuxtLink :to="`/assets/${row.assetId}?tab=processes`" class="link">{{ assetName(row) }}</NuxtLink>
            </template>
            <template #cell-process="{ row }">
              <span class="mono">{{ exeName(row) }}</span> <span class="mono whitespace-nowrap text-xs text-ink-3">pid {{ row.pid }}</span>
            </template>
            <template #cell-state="{ row }"><StatusBadge :tone="suspiciousTone(row)" :label="suspiciousState(row)" /></template>
            <template #cell-path="{ row }"><span class="mono text-xs break-all">{{ row.exePath }}</span></template>
            <template #cell-sha="{ row }"><span class="mono text-xs">{{ shortHash(row.sha256) }}</span></template>
            <template #cell-startedAt="{ row }"><TimeAgo :at="row.startedAt" class="text-ink-2" /></template>
          </DataTable>
        </Panel>
      </template>

      <template v-else-if="tab === 'ports'">
        <Panel flush>
          <DataTable :columns="portColumns" :rows="portRows" :row-key="(r) => r.key" :page-size="25">
            <template #cell-port="{ row }"><span class="mono whitespace-nowrap">{{ row.proto }}/{{ row.port }}</span></template>
            <template #cell-bind="{ row }">
              <span class="mono whitespace-nowrap">{{ row.address }}</span>
            </template>
            <template #cell-process="{ row }">
              <span class="mono">{{ exeName(row.process) }}</span> <span class="mono whitespace-nowrap text-xs text-ink-3">pid {{ row.process.pid }}</span>
            </template>
            <template #cell-user="{ row }">{{ row.process.user }}</template>
            <template #cell-asset="{ row }">
              <NuxtLink :to="`/assets/${row.process.assetId}?tab=processes`" class="link">{{ assetName(row.process) }}</NuxtLink>
            </template>
            <template #cell-component="{ row }">
              <NuxtLink v-if="row.process.componentId && getComponent(row.process.componentId)" :to="`/components/${row.process.componentId}`" class="link">
                {{ getComponent(row.process.componentId)?.name }}
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
          <DataTable :columns="allColumns" :rows="allRows" :row-key="(p) => p.id" :page-size="25">
            <template #cell-asset="{ row }">
              <NuxtLink :to="`/assets/${row.assetId}?tab=processes`" class="link">{{ assetName(row) }}</NuxtLink>
            </template>
            <template #cell-process="{ row }">
              <span class="mono">{{ exeName(row) }}</span> <span class="mono whitespace-nowrap text-xs text-ink-3">pid {{ row.pid }}</span>
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
