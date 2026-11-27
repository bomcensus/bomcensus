<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import { RefreshCw } from '@lucide/vue'
import type { AssetComponentRow, AssetContainer, ComponentOrigin, ComponentType, K8sPod, ProcessInfo, SectionCoverage } from '~/types'
import type { TableColumn } from '~/types/table'
import type { TriState } from '~/composables/useServerList'
import type { Tone } from '~/utils/labels'
import {
  collectAsset,
  getAgent,
  getAsset,
  getAssetProcess,
  getComponent,
  listAssetComponents,
  listAssetInstances,
  listAssetProcesses,
  listAssetVulnerabilities,
  listAssetNotices,
  optional,
  toApiError,
  type QueryOf,
} from '~/api'

const route = useRoute()
const router = useRouter()

// When only the id changes on the same page, NuxtPage recreates it, so the value at setup time is enough
const id = String(route.params.id)

// ── Loading ───────────────────────────────────────────

const {
  data: detail,
  error,
  refresh,
} = useLoad(`asset:${id}`, async () => {
  const asset = await getAsset(id)
  // The agent may be gone (deleted); the asset still shows its id.
  const agent = asset.agentId ? await optional(getAgent(asset.agentId)) : undefined
  return { asset, agent }
})
// Totals for the tab labels and the overview, independent of the filters of the tabs
const {
  data: counts,
  pending: countsPending,
  error: countsError,
  refresh: refreshCounts,
} = useLoad(`asset:${id}:counts`, async () => {
  const procTotal = (view?: 'restart' | 'suspicious' | 'listen') => listAssetProcesses(id, { view, limit: 1 }).then((r) => r.total)
  const [components, processes, restart, suspicious, listen] = await Promise.all([
    listAssetComponents(id, { limit: 1 }).then((r) => r.total),
    procTotal(),
    procTotal('restart'),
    procTotal('suspicious'),
    procTotal('listen'),
  ])
  return { components, processes, restart, suspicious, listen }
})

const asset = computed(() => detail.value?.asset)
const agent = computed(() => detail.value?.agent)

useHead({ title: computed(() => `${asset.value?.name ?? '자산'} · bomcensus`) })

const limited = computed(() => !!asset.value && asset.value.coverage !== 'full')
const assetContainers = computed(() => asset.value?.containers ?? [])

// Container filter for the components tab. HOST_SELF means only items outside containers (the host).
const HOST_SELF = '__host'
const containerOptions = computed(() => [
  ...(asset.value?.kind === 'host' ? [{ value: HOST_SELF, label: '호스트' }] : []),
  ...assetContainers.value.map((c) => ({ value: c.name, label: c.name })),
])

// ── Header ─────────────────────────────────────────────

const subtitle = computed(() => {
  const a = asset.value
  if (!a) return undefined
  return [assetKindLabel[a.kind], osLabel(a.os), assetLocation(a)].filter(Boolean).join(' · ')
})

const collectBusy = ref(false)
const collectError = ref('')
// Requested state comes from the server, so it survives a reload.
const collectRequestedAt = computed(() => asset.value?.collectRequestedAt)

async function collect() {
  if (collectBusy.value) return
  collectBusy.value = true
  collectError.value = ''
  try {
    await collectAsset(id)
    await refresh()
  } catch (e) {
    const err = toApiError(e)
    collectError.value = err.status === 409 ? `수집할 수 없는 상태입니다: ${err.message}` : err.message
  } finally {
    collectBusy.value = false
  }
}

// ── Tabs ───────────────────────────────────────────────

const tab = ref('overview')

function goTab(key: string) {
  tab.value = key
  router.replace({ query: { ...route.query, tab: key } })
}

// ── Components ─────────────────────────────────────────

// The same component can exist on the host and in several containers, so entries are keyed by (container, component)
const placeKey = (r: { container?: string; componentId: string }) => `${r.container ?? ''}|${r.componentId}`

const {
  items: componentRows,
  total: componentTotal,
  pending: componentsPending,
  error: componentsError,
  refresh: refreshComponents,
  q: compQuery,
  filters: compFilters,
  sort: compSort,
  page: compPage,
  size: compSize,
} = useServerList(
  `asset:${id}:components`,
  ({ container, ...p }) =>
    listAssetComponents(id, {
      ...(p as QueryOf<typeof listAssetComponents>),
      ...(container === HOST_SELF ? { hostOnly: true } : { container }),
    }),
  { filters: { type: '', origin: '', container: '', inUse: '' as TriState }, sort: 'name' },
)

const compTypeOptions = (Object.keys(componentTypeLabel) as ComponentType[]).map((value) => ({ value, label: componentTypeLabel[value] }))
const compOriginOptions = (Object.keys(originLabel) as ComponentOrigin[]).map((value) => ({ value, label: originLabel[value] }))

const componentColumns: TableColumn<AssetComponentRow>[] = [
  { key: 'name', label: '이름', sort: 'name' },
  { key: 'version', label: '버전', sort: 'version' },
  { key: 'type', label: '종류', sort: 'type', hideBelow: 'md' },
  { key: 'origin', label: '출처', sort: 'origin', hideBelow: 'lg' },
  { key: 'method', label: '탐지 방법', sort: 'method', hideBelow: 'lg' },
  { key: 'locations', label: '위치', hideBelow: 'md' },
  { key: 'inUse', label: '실행 중', sort: 'inUse', sortDesc: true, hideBelow: 'sm' },
]

const rawOpen = ref(false)
const rawTarget = ref<AssetComponentRow>()

function openRaw(r: AssetComponentRow) {
  rawTarget.value = r
  rawOpen.value = true
}

// ── Processes ─────────────────────────────────────────

const restartCount = computed(() => counts.value?.restart ?? 0)
const suspiciousCount = computed(() => counts.value?.suspicious ?? 0)
const listenCount = computed(() => counts.value?.listen ?? 0)

const {
  items: procRows,
  total: procTotal,
  pending: procsPending,
  error: procsError,
  refresh: refreshProcs,
  q: procQuery,
  filters: procFilters,
  sort: procSort,
  page: procPage,
  size: procSize,
} = useServerList(`asset:${id}:processes`, (p) => listAssetProcesses(id, p as QueryOf<typeof listAssetProcesses>), {
  filters: { view: '' },
  // Suspicious first, then those needing a restart
  sort: '-risk',
})
const procViewOptions = [
  { value: 'restart', label: '재시작 필요' },
  { value: 'suspicious', label: '의심 프로세스' },
  { value: 'listen', label: 'listen 포트 있음' },
]

function goProcesses(view: string) {
  procFilters.view = view
  goTab('processes')
}

const exeName = (p: ProcessInfo) => p.exePath.split(/[\\/]/).filter(Boolean).pop() ?? p.exePath
const portLabel = (l: ProcessInfo['listen'][number]) => `${l.proto}/${l.port}`

function procFlags(p: ProcessInfo): { label: string; tone: Tone }[] {
  const flags: { label: string; tone: Tone }[] = []
  if (p.exeState !== 'normal') flags.push({ label: exeStateLabel[p.exeState], tone: exeStateTone[p.exeState] })
  if (p.deletedLibs.some((l) => l.state === 'replaced')) flags.push({ label: '라이브러리 교체됨', tone: 'warn' })
  if (p.deletedLibs.some((l) => l.state === 'deleted')) flags.push({ label: '라이브러리 삭제됨', tone: 'danger' })
  return flags
}
const procColumns: TableColumn<ProcessInfo>[] = [
  { key: 'pid', label: 'pid', sort: 'pid' },
  { key: 'user', label: '사용자', sort: 'user', hideBelow: 'sm' },
  { key: 'exe', label: '실행 파일', sort: 'exe' },
  { key: 'state', label: '상태', sort: 'risk', sortDesc: true },
  { key: 'listen', label: 'listen 포트', hideBelow: 'md' },
  { key: 'sha256', label: 'sha256', hideBelow: 'lg' },
  { key: 'startedAt', label: '시작', align: 'right', sort: 'startedAt', sortDesc: true, hideBelow: 'sm' },
]

// The selected process is kept in the query (proc). It is picked by navigating from a table row and undone with the back button.
const procLink = (p: ProcessInfo) => `/assets/${encodeURIComponent(id)}?tab=processes&proc=${encodeURIComponent(p.id)}`
// The selected process is loaded by id, so a link to a process on another page opens it too.
const procKey = computed(() => (typeof route.query.proc === 'string' ? route.query.proc : ''))
const { data: loadedProc } = useLoad(
  () => `asset:${id}:process:${procKey.value}`,
  () => (procKey.value ? optional(getAssetProcess(id, procKey.value)) : Promise.resolve(undefined)),
)
const selectedProc = computed(() => {
  if (!procKey.value) return undefined
  if (loadedProc.value?.id === procKey.value) return loadedProc.value
  return procRows.value.find((p) => p.id === procKey.value)
})
const selectedContainer = computed(() => assetContainers.value.find((c) => c.name === selectedProc.value?.container))
const { data: selectedComponent } = useLoad(
  () => `component:${selectedProc.value?.componentId ?? ''}`,
  () => (selectedProc.value?.componentId ? optional(getComponent(selectedProc.value.componentId)) : Promise.resolve(undefined)),
)

function closeProc() {
  const { proc: _proc, ...query } = route.query
  router.replace({ query })
}

// ── Containers ─────────────────────────────────────────

const containerColumns: TableColumn<AssetContainer>[] = [
  { key: 'name', label: '이름', sortValue: (c) => c.name },
  { key: 'image', label: '이미지', sortValue: (c) => c.imageRef },
  { key: 'runtime', label: 'runtime', sortValue: (c) => c.runtime, hideBelow: 'md' },
  { key: 'instances', label: '인스턴스', align: 'right', sortValue: (c) => c.instances, hideBelow: 'sm' },
  { key: 'coverage', label: '수집 범위', sortValue: (c) => c.coverage, hideBelow: 'sm' },
]

const {
  items: pods,
  total: podTotal,
  pending: podsPending,
  error: podsError,
  refresh: refreshPods,
  sort: podSort,
  page: podPage,
  size: podSize,
} = useServerList(`asset:${id}:instances`, (p) => listAssetInstances(id, p as QueryOf<typeof listAssetInstances>), {
  sort: 'name',
})

const podColumns: TableColumn<K8sPod>[] = [
  { key: 'name', label: 'pod', sort: 'name' },
  { key: 'node', label: '노드', sort: 'node', hideBelow: 'md' },
  { key: 'phase', label: '상태', sort: 'phase' },
  { key: 'containers', label: '컨테이너별 수집 범위' },
]

// ── Collection ─────────────────────────────────────────────

const sectionColumns: TableColumn<SectionCoverage>[] = [
  { key: 'section', label: '섹션' },
  { key: 'coverage', label: '범위' },
  { key: 'reason', label: '사유' },
  { key: 'collectedAt', label: '수집 시각', align: 'right', hideBelow: 'sm' },
]

// Difference between privileged and non-root collection. Lists only the restricted items.
const nonRootLimits: { item: string; limit: string }[] = [
  { item: '프로세스 목록', limit: '/proc이 hidepid로 마운트되어 있으면 자기 프로세스만 보입니다' },
  { item: '실행 파일 경로·해시, 삭제된 파일 감지', limit: '자기 사용자의 프로세스만. 나머지는 cmdline에서 추정한 경로로 표시합니다' },
  { item: 'listen 포트', limit: '포트와 소유 uid까지. 프로세스 연결은 자기 사용자 것만 합니다' },
  { item: 'JAR, Go 바이너리, 알려진 소프트웨어', limit: '읽을 수 있는 경로만' },
  { item: '버전 실행', limit: '자기가 실행할 수 있는 파일만' },
  { item: '컨테이너', limit: '프로세스의 cgroup에서 얻는 컨테이너 ID까지' },
]

// ── Tab list ──────────────────────────────────────────

// Counts are left out until the list has loaded
const countOf = (pending: boolean, rows: unknown[]) => (pending ? undefined : rows.length)
const {
  data: vulns,
  pending: vulnsPending,
  error: vulnsError,
  refresh: refreshVulns,
} = useLoad(`asset:${id}:vulns`, async () => (await listAssetVulnerabilities(id)).items, () => [])
const {
  data: notices,
  pending: noticesPending,
  error: noticesError,
  refresh: refreshNotices,
} = useLoad(`asset:${id}:notices`, async () => (await listAssetNotices(id)).items, () => [])

const tabs = computed(() => [
  { key: 'overview', label: '개요' },
  { key: 'vulnerabilities', label: '취약점', count: countOf(vulnsPending.value, vulns.value) },
  { key: 'notices', label: '보안 공지', count: countOf(noticesPending.value, notices.value) },
  { key: 'components', label: '컴포넌트', count: counts.value?.components },
  { key: 'processes', label: '프로세스', count: counts.value?.processes },
  ...(assetContainers.value.length > 0 ? [{ key: 'containers', label: '컨테이너', count: assetContainers.value.length }] : []),
  ...(asset.value?.kind === 'host' ? [{ key: 'integrity', label: '파일 무결성' }] : []),
  { key: 'collection', label: '수집' },
])
</script>

<template>
  <div>
    <template v-if="!asset">
      <PageHeader title="자산" :back="{ to: '/assets', label: '자산' }" />
      <Panel>
        <LoadError v-if="error" :error="error" :back="{ to: '/assets', label: '자산 목록' }" @retry="refresh" />
        <LoadingText v-else />
      </Panel>
    </template>

    <template v-else>
      <PageHeader :title="asset.name" :subtitle="subtitle" :back="{ to: '/assets', label: '자산' }">
        <template #actions>
          <span v-if="collectRequestedAt" class="whitespace-nowrap text-xs text-ink-2">{{ formatDateTime(collectRequestedAt) }}</span>
          <AppButton variant="primary" :icon="RefreshCw" :disabled="collectBusy || !!collectRequestedAt" @click="collect">
            {{ collectRequestedAt ? '수집 요청됨' : '수집 실행' }}
          </AppButton>
        </template>

        <div class="space-y-2">
          <p v-if="collectError" class="note note-danger" role="alert">{{ collectError }}</p>
          <p v-if="limited" class="note note-warn">
            수집 범위: {{ coverageLabel[asset.coverage] }}. 확인하지 못한 범위가 있습니다.
            <Diagnostic v-if="asset.coverageReason" :text="asset.coverageReason" class="mt-1" />
          </p>
          <AppTabs v-model="tab" :tabs="tabs" query-key="tab" />
        </div>
      </PageHeader>

      <!-- Overview -->
      <div v-if="tab === 'overview'" class="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Panel title="자산 정보" class="lg:col-span-2">
          <dl class="kv">
            <dt>종류</dt>
            <dd>{{ assetKindLabel[asset.kind] }}</dd>
            <dt>OS</dt>
            <dd>
              <template v-if="asset.os">{{ osLabel(asset.os) }}</template>
              <span v-else class="text-ink-3">—</span>
            </dd>
            <dt>커널</dt>
            <dd :class="asset.os?.kernel ? 'mono' : 'text-ink-3'">{{ asset.os?.kernel ?? '—' }}</dd>
            <dt>아키텍처</dt>
            <dd :class="asset.os ? 'mono' : 'text-ink-3'">{{ asset.os?.arch ?? '—' }}</dd>
            <dt>주소</dt>
            <dd :class="asset.address ? 'mono' : 'text-ink-3'">{{ asset.address ?? '—' }}</dd>
            <dt>그룹</dt>
            <dd :class="asset.group ? '' : 'text-ink-3'">{{ asset.group || '—' }}</dd>
            <dt>태그</dt>
            <dd>
              <span v-if="asset.tags.length === 0" class="text-ink-3">—</span>
              <span v-else class="flex flex-wrap gap-1">
                <span v-for="t in asset.tags" :key="t" class="rounded-sm bg-surface-2 px-1.5 text-xs leading-5 text-ink-2">{{ t }}</span>
              </span>
            </dd>
            <dt>수집 방식</dt>
            <dd>{{ methodLabel[asset.method] }}</dd>
            <dt>권한</dt>
            <dd>{{ asset.privilege ? privilegeLabel[asset.privilege] : '—' }}</dd>
            <template v-if="asset.agentId">
              <dt>Agent</dt>
              <dd>
                <template v-if="agent">
                  <NuxtLink :to="`/agents/${agent.id}`" class="link">{{ agent.hostname }}</NuxtLink>
                  <StatusBadge class="ml-2" :tone="agentStatusTone[agent.status]" :label="agentStatusLabel[agent.status]" dot />
                </template>
                <span v-else class="mono text-ink-3">{{ asset.agentId }}</span>
              </dd>
            </template>
            <template v-if="asset.kind === 'workload'">
              <dt>클러스터</dt>
              <dd>
                <NuxtLink v-if="asset.clusterId" :to="`/kubernetes/${asset.clusterId}`" class="link">{{ asset.clusterName ?? asset.clusterId }}</NuxtLink>
                <span v-else class="text-ink-3">—</span>
              </dd>
              <dt>namespace</dt>
              <dd :class="asset.namespace ? 'mono' : 'text-ink-3'">{{ asset.namespace ?? '—' }}</dd>
              <dt>워크로드 종류</dt>
              <dd>{{ asset.workloadKind ?? '—' }}</dd>
              <dt>replicas</dt>
              <dd :class="asset.replicas !== undefined ? 'mono' : 'text-ink-3'">{{ asset.replicas ?? '—' }}</dd>
              <dt>컨테이너</dt>
              <dd class="mono">{{ asset.containers.length }}</dd>
            </template>
            <dt>최초 수집</dt>
            <dd>{{ formatDateTime(asset.firstSeen) }} <TimeAgo :at="asset.firstSeen" class="text-ink-3" /></dd>
            <dt>최근 수집</dt>
            <dd>{{ formatDateTime(asset.lastSeen) }} <TimeAgo :at="asset.lastSeen" class="text-ink-3" /></dd>
          </dl>
        </Panel>

        <div class="flex min-w-0 flex-col gap-4">
          <Panel title="프로세스">
            <LoadError v-if="countsError" :error="countsError" @retry="refreshCounts" />
            <LoadingText v-else-if="countsPending && !counts" />
            <ul v-else class="space-y-0.5 text-sm">
              <li>
                <button type="button" class="flex w-full items-center justify-between rounded-sm px-1 py-1 hover:bg-surface-2" @click="goProcesses('restart')">
                  <span>재시작 필요</span>
                  <span class="mono" :class="restartCount > 0 ? 'font-semibold text-medium' : 'text-ink-3'">{{ restartCount }}</span>
                </button>
              </li>
              <li>
                <button type="button" class="flex w-full items-center justify-between rounded-sm px-1 py-1 hover:bg-surface-2" @click="goProcesses('suspicious')">
                  <span>의심 프로세스</span>
                  <span class="mono" :class="suspiciousCount > 0 ? 'font-semibold text-critical' : 'text-ink-3'">{{ suspiciousCount }}</span>
                </button>
              </li>
              <li>
                <button type="button" class="flex w-full items-center justify-between rounded-sm px-1 py-1 hover:bg-surface-2" @click="goProcesses('listen')">
                  <span>listen 중인 프로세스</span>
                  <span class="mono" :class="listenCount > 0 ? '' : 'text-ink-3'">{{ listenCount }}</span>
                </button>
              </li>
            </ul>
          </Panel>
        </div>
      </div>

      <!-- Components -->
      <div v-else-if="tab === 'components'">
        <FilterBar :count="componentTotal" :total="counts?.components" unit="개">
          <SearchInput v-model="compQuery" placeholder="이름, 버전, purl, 경로" />
          <SelectFilter v-model="compFilters.type" label="종류" :options="compTypeOptions" />
          <SelectFilter v-model="compFilters.origin" label="출처" :options="compOriginOptions" />
          <SelectFilter v-if="assetContainers.length > 0" v-model="compFilters.container" label="컨테이너" :options="containerOptions" />
          <SelectFilter v-model="compFilters.inUse" label="실행" :options="triStateOptions('실행 중', '실행 안 함')" />
        </FilterBar>

        <Panel flush>
          <LoadError v-if="componentsError" :error="componentsError" @retry="refreshComponents" />
          <DataTable
            v-else
            :columns="componentColumns"
            v-model:sort="compSort"
            v-model:page="compPage"
            v-model:size="compSize"
            :rows="componentRows"
            :total="componentTotal"
            :row-key="placeKey"
            :row-to="(r) => `/components/${r.componentId}`"
            :loading="componentsPending"
          >
            <template #cell-name="{ row }">
              <NuxtLink :to="`/components/${row.componentId}`" class="font-medium hover:underline">{{ row.component.name }}</NuxtLink>
              <div v-if="row.container" class="text-xs text-ink-3">
                {{ row.container }}<template v-if="row.layer"> · {{ layerLabel[row.layer] }}</template>
              </div>
            </template>
            <template #cell-version="{ row }">
              <span class="inline-flex flex-wrap items-center gap-1.5">
                <span class="mono whitespace-nowrap">{{ versionText(row.component.version, row.component.build) }}</span>
                <AppButton v-if="row.versionRaw" size="sm" variant="ghost" @click="openRaw(row)">출력 보기</AppButton>
              </span>
            </template>
            <template #cell-type="{ row }">{{ componentTypeLabel[row.component.type] }}</template>
            <template #cell-origin="{ row }">{{ originLabel[row.component.origin] }}</template>
            <template #cell-method="{ row }">{{ detectMethodLabel[row.method] }}</template>
            <template #cell-locations="{ row }">
              <span v-if="row.locations.length === 0" class="text-ink-3">—</span>
              <span v-else :title="row.locations.join('\n')">
                <span class="mono break-all text-xs">{{ row.locations[0] }}</span>
                <span v-if="row.locations.length > 1" class="ml-1 whitespace-nowrap text-xs text-ink-3">외 {{ row.locations.length - 1 }}</span>
              </span>
            </template>
            <template #cell-inUse="{ row }">
              <StatusBadge v-if="row.inUse" tone="info" label="실행 중" />
              <span v-else class="text-ink-3">—</span>
            </template>
          </DataTable>
        </Panel>
      </div>

      <!-- Processes -->
      <div v-else-if="tab === 'processes'">
        <p v-if="asset.privilege === 'non_root'" class="note note-warn mb-3">
          non-root로 수집한 자산입니다. 다른 사용자의 프로세스는 실행 파일 경로를 cmdline에서 추정하고("추정" 표시), 해시와 삭제 여부를 확인하지 못합니다.
        </p>

        <FilterBar :count="procTotal" :total="counts?.processes" unit="개">
          <SearchInput v-model="procQuery" placeholder="실행 파일, 사용자, cmdline, pid" />
          <SelectFilter v-model="procFilters.view" label="상태" :options="procViewOptions" />
        </FilterBar>

        <Panel flush>
          <LoadError v-if="procsError" :error="procsError" @retry="refreshProcs" />
          <DataTable
            v-else
            :columns="procColumns"
            v-model:sort="procSort"
            v-model:page="procPage"
            v-model:size="procSize"
            :rows="procRows"
            :total="procTotal"
            :row-key="(p) => p.id"
            :row-to="procLink"
            :loading="procsPending"
          >
            <template #cell-pid="{ row }">
              <NuxtLink :to="procLink(row)" class="mono whitespace-nowrap hover:underline" :class="selectedProc?.id === row.id ? 'font-semibold text-accent' : ''">
                {{ row.pid }}
              </NuxtLink>
            </template>
            <template #cell-user="{ row }">{{ row.user }}</template>
            <template #cell-exe="{ row }">
              <span class="inline-flex flex-wrap items-center gap-1.5">
                <span class="font-medium">{{ exeName(row) }}</span>
                <StatusBadge v-if="row.exeSource === 'cmdline'" label="추정" title="권한이 없어 cmdline에서 추정한 경로" />
              </span>
              <div class="mono break-all text-xs text-ink-3">{{ row.exePath }}</div>
              <div v-if="row.container" class="text-xs text-ink-3">
                컨테이너 {{ row.container }}<span v-if="row.node" class="mono"> @ {{ row.node }}</span>
              </div>
            </template>
            <template #cell-state="{ row }">
              <span v-if="procFlags(row).length === 0" class="text-ink-3">정상</span>
              <span v-else class="inline-flex flex-wrap gap-1">
                <StatusBadge v-for="f in procFlags(row)" :key="f.label" :tone="f.tone" :label="f.label" />
              </span>
            </template>
            <template #cell-listen="{ row }">
              <span v-if="row.listen.length === 0" class="text-ink-3">—</span>
              <span v-else class="mono flex flex-wrap gap-x-2 text-xs">
                <span v-for="l in row.listen" :key="`${l.proto}${l.address}${l.port}`" class="whitespace-nowrap" :title="l.address">{{ portLabel(l) }}</span>
              </span>
            </template>
            <template #cell-sha256="{ row }">
              <span class="mono text-xs" :class="row.sha256 ? 'text-ink-2' : 'text-ink-3'" :title="row.sha256">{{ shortHash(row.sha256) }}</span>
            </template>
            <template #cell-startedAt="{ row }">
              <TimeAgo :at="row.startedAt" class="text-ink-2" />
            </template>
          </DataTable>
        </Panel>

        <Panel v-if="selectedProc" :title="`${exeName(selectedProc)} · pid ${selectedProc.pid}`" class="mt-4">
          <template #actions>
            <AppButton size="sm" variant="ghost" @click="closeProc">닫기</AppButton>
          </template>

          <dl class="kv">
            <dt>실행 파일</dt>
            <dd>
              <span class="mono">{{ selectedProc.exePath }}</span>
              <StatusBadge v-if="selectedProc.exeSource === 'cmdline'" class="ml-2" label="추정" />
            </dd>
            <dt>사용자</dt>
            <dd>{{ selectedProc.user }}</dd>
            <dt>상태</dt>
            <dd>
              <span v-if="procFlags(selectedProc).length === 0" class="text-ink-2">정상</span>
              <span v-else class="inline-flex flex-wrap gap-1">
                <StatusBadge v-for="f in procFlags(selectedProc)" :key="f.label" :tone="f.tone" :label="f.label" />
              </span>
            </dd>
            <dt>sha256</dt>
            <dd>
              <CopyField v-if="selectedProc.sha256" :value="selectedProc.sha256" label="sha256" />
              <span v-else class="text-ink-3">—</span>
            </dd>
            <dt>시작</dt>
            <dd>{{ formatDateTime(selectedProc.startedAt) }} <TimeAgo :at="selectedProc.startedAt" class="text-ink-3" /></dd>
            <dt>listen 포트</dt>
            <dd>
              <span v-if="selectedProc.listen.length === 0" class="text-ink-3">—</span>
              <ul v-else class="space-y-0.5">
                <li v-for="l in selectedProc.listen" :key="`${l.proto}${l.address}${l.port}`">
                  <span class="mono">{{ portLabel(l) }}</span>
                  <span class="mono ml-2 text-ink-2">{{ l.address }}</span>
                </li>
              </ul>
            </dd>
            <template v-if="selectedProc.container">
              <dt>컨테이너</dt>
              <dd>
                {{ selectedProc.container }}
                <span v-if="selectedContainer" class="mono ml-1 text-ink-2">{{ selectedContainer.imageRef }}</span>
              </dd>
            </template>
            <template v-if="selectedProc.node">
              <dt>노드</dt>
              <dd class="mono">{{ selectedProc.node }}</dd>
            </template>
            <template v-if="selectedComponent">
              <dt>컴포넌트</dt>
              <dd>
                <NuxtLink :to="`/components/${selectedComponent.id}`" class="link">{{ selectedComponent.name }}</NuxtLink>
                <span class="mono ml-1 text-ink-2">{{ versionText(selectedComponent.version, selectedComponent.build) }}</span>
              </dd>
            </template>
          </dl>

          <p v-if="selectedProc.exeSource === 'cmdline'" class="note mt-3">
            권한이 없어 실행 파일 경로를 cmdline에서 추정했습니다. 해시와 삭제 여부는 확인하지 못했습니다.
          </p>

          <h3 class="mt-4 mb-1 text-xs font-medium text-ink-2">cmdline</h3>
          <pre class="pre">{{ selectedProc.cmdline }}</pre>

          <h3 class="mt-4 mb-1 text-xs font-medium text-ink-2">교체·삭제된 라이브러리</h3>
          <p v-if="selectedProc.deletedLibs.length === 0" class="text-sm text-ink-3">없음</p>
          <ul v-else class="divide-y divide-line rounded-md border border-line">
            <li v-for="lib in selectedProc.deletedLibs" :key="lib.path" class="flex flex-wrap items-center justify-between gap-2 px-3 py-1.5">
              <span class="mono min-w-0 break-all text-xs">{{ lib.path }}</span>
              <StatusBadge
                :tone="lib.state === 'replaced' ? 'warn' : 'danger'"
                :label="lib.state === 'replaced' ? '교체됨 · 재시작 필요' : '삭제됨 · 의심 프로세스'"
              />
            </li>
          </ul>
        </Panel>
      </div>

      <!-- Containers -->
      <div v-else-if="tab === 'containers'">
        <Panel flush>
          <DataTable
            :columns="containerColumns"
            :rows="assetContainers"
            :row-key="(c) => c.name"
            :initial-sort="{ key: 'name', dir: 'asc' }"
          >
            <template #cell-name="{ row }">
              <span class="font-medium">{{ row.name }}</span>
              <div v-if="row.workload" class="text-xs text-ink-3">
                워크로드
                <NuxtLink :to="`/assets/${row.workload.assetId}`" class="hover:underline">{{ row.workload.name }}</NuxtLink>
                · 취약점은 워크로드에 집계
              </div>
            </template>
            <template #cell-image="{ row }">
              <template v-if="row.imageDigest">
                <NuxtLink :to="`/images/${encodeURIComponent(row.imageDigest)}`" class="mono break-all hover:underline">{{ row.imageRef }}</NuxtLink>
                <div class="mono whitespace-nowrap text-xs text-ink-3" :title="row.imageDigest">{{ shortHash(row.imageDigest) }}</div>
              </template>
              <span v-else class="mono break-all">{{ row.imageRef }}</span>
            </template>
            <template #cell-runtime="{ row }">{{ runtimeLabel[row.runtime] }}</template>
            <template #cell-instances="{ row }">
              <span class="mono" :class="row.instances > 0 ? '' : 'text-ink-3'">{{ row.instances }}</span>
            </template>
            <template #cell-coverage="{ row }">
              <CoverageBadge :coverage="row.coverage" :reason="row.coverageReason" />
              <Diagnostic v-if="row.coverageReason" :text="row.coverageReason" class="mt-0.5 max-w-56" />
            </template>
          </DataTable>
        </Panel>

        <Panel v-if="asset.kind === 'workload'" title="인스턴스" class="mt-4" flush>
          <LoadError v-if="podsError" :error="podsError" @retry="refreshPods" />
          <DataTable
            v-else
            v-model:sort="podSort"
            v-model:page="podPage"
            v-model:size="podSize"
            :columns="podColumns"
            :rows="pods"
            :total="podTotal"
            :row-key="(p) => p.id"
            :loading="podsPending"
          >
            <template #cell-name="{ row }">
              <span class="mono break-all">{{ row.name }}</span>
            </template>
            <template #cell-node="{ row }">
              <span class="mono">{{ row.node }}</span>
            </template>
            <template #cell-phase="{ row }">
              <StatusBadge :tone="podPhaseTone[row.phase]" :label="podPhaseLabel[row.phase]" dot />
            </template>
            <template #cell-containers="{ row }">
              <ul class="space-y-1">
                <li v-for="c in row.containers" :key="c.name" class="flex flex-wrap items-center gap-1.5">
                  <span class="text-xs">{{ c.name }}</span>
                  <CoverageBadge :coverage="c.coverage" :reason="c.coverageReason" />
                </li>
              </ul>
            </template>
          </DataTable>
        </Panel>
      </div>

      <AssetVulnPanel
        v-else-if="tab === 'vulnerabilities'"
        :asset="{ id: asset.id, name: asset.name, group: asset.group || undefined }"
        :items="vulns"
        :pending="vulnsPending"
        :error="vulnsError"
        @retry="refreshVulns"
      />

      <AssetNoticePanel
        v-else-if="tab === 'notices'"
        :items="notices"
        :pending="noticesPending"
        :error="noticesError"
        @retry="refreshNotices"
      />

      <AssetIntegrityPanel v-else-if="tab === 'integrity'" :asset-id="asset.id" />

      <!-- Collection -->
      <div v-else-if="tab === 'collection'" class="space-y-4">
        <Panel title="섹션별 수집 범위" flush>
          <DataTable :columns="sectionColumns" :rows="asset.sections" :row-key="(s) => s.section">
            <template #cell-section="{ row }">{{ sectionLabel[row.section] }}</template>
            <template #cell-coverage="{ row }">
              <StatusBadge :tone="sectionCoverageTone[row.coverage]" :label="sectionCoverageLabel[row.coverage]" dot />
            </template>
            <template #cell-reason="{ row }">
              <Diagnostic v-if="row.reason" :text="row.reason" />
              <span v-else class="text-ink-3">—</span>
            </template>
            <template #cell-collectedAt="{ row }">
              <TimeAgo :at="row.collectedAt" class="text-ink-2" />
            </template>
          </DataTable>
        </Panel>

        <Panel title="권한">
          <dl class="kv">
            <dt>수집 방식</dt>
            <dd>{{ methodLabel[asset.method] }}</dd>
            <dt>권한 수준</dt>
            <dd>
              {{ asset.privilege ? privilegeLabel[asset.privilege] : '—' }}
            </dd>
            <template v-if="agent">
              <dt>exec helper</dt>
              <dd>
                {{ agent.execHelper ? '사용' : '미사용' }}
              </dd>
            </template>
            <dt>수집 범위</dt>
            <dd>
              <CoverageBadge :coverage="asset.coverage" :reason="asset.coverageReason" />
              <span v-if="asset.coverageReason" class="ml-2 text-ink-2">{{ asset.coverageReason }}</span>
            </dd>
          </dl>

          <div v-if="asset.privilege === 'non_root'" class="note note-warn mt-3">
            <p>non-root 수집은 아래 항목이 제한됩니다. OS와 패키지 DB는 전체 수집합니다.</p>
            <ul class="mt-1 list-disc space-y-0.5 pl-4">
              <li v-for="l in nonRootLimits" :key="l.item"><span class="text-ink">{{ l.item }}</span>: {{ l.limit }}</li>
            </ul>
          </div>
        </Panel>
      </div>

      <!-- Version output -->
      <AppModal v-model:open="rawOpen" :title="rawTarget ? `${rawTarget.component.name} 버전 출력` : '버전 출력'" wide>
        <template v-if="rawTarget">
          <dl class="kv">
            <dt>실행한 명령</dt>
            <dd :class="rawTarget.versionCommand ? 'mono' : 'text-ink-3'">{{ rawTarget.versionCommand ?? '—' }}</dd>
            <dt>파싱한 버전</dt>
            <dd class="mono">{{ versionText(rawTarget.component.version, rawTarget.component.build) }}</dd>
            <dt>탐지 방법</dt>
            <dd>{{ detectMethodLabel[rawTarget.method] }}</dd>
          </dl>
          <pre class="pre mt-3">{{ rawTarget.versionRaw }}</pre>
        </template>
        <template #footer>
          <AppButton @click="rawOpen = false">닫기</AppButton>
        </template>
      </AppModal>

    </template>
  </div>
</template>
