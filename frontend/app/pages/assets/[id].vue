<script setup lang="ts">
import { Download, RefreshCw } from '@lucide/vue'
import type {
  AssetContainer,
  ComponentOrigin,
  ComponentType,
  FindingStatus,
  K8sPod,
  ProcessInfo,
  SectionCoverage,
  Severity,
} from '~/types'
import type { TableColumn } from '~/types/table'
import type { Tone } from '~/utils/labels'
import {
  assetLocation,
  componentsOfAsset,
  countBySeverity,
  emptyCounts,
  findingsOfAsset,
  getAgent,
  getAsset,
  getCluster,
  getComponent,
  getContainer,
  imageContentKnown,
  isActive,
  isSuspicious,
  needsRestart,
  podsOfAsset,
  processesOfAsset,
  SEVERITIES,
  totalOf,
  type AssetComponentRow,
  type FindingRow,
  workloadOfAsset,
} from '~/mock'

const route = useRoute()
const router = useRouter()

// 같은 페이지에서 id만 바뀌면 NuxtPage가 다시 만들므로 setup 시점의 값으로 충분하다
const id = String(route.params.id)
const asset = getAsset(id)

useHead({ title: `${asset?.name ?? '자산'} · bomcensus` })

const agent = asset?.agentId ? getAgent(asset.agentId) : undefined
const cluster = asset?.clusterId ? getCluster(asset.clusterId) : undefined
const limited = asset ? asset.coverage !== 'full' : false
// 미지원·실패는 취약점 건수를 보여 줄 수 없다
const unknown = asset ? asset.coverage === 'unsupported' || asset.coverage === 'failed' : false
const workload = asset?.kind === 'workload' ? workloadOfAsset(id) : undefined
const assetContainers = asset?.containers ?? []

// 컴포넌트·취약점 탭의 컨테이너 필터. 값이 HOST_SELF면 컨테이너 밖(호스트)의 것만.
const HOST_SELF = '__host'
const containerOptions = [
  ...(asset?.kind === 'host' ? [{ value: HOST_SELF, label: '호스트' }] : []),
  ...assetContainers.map((c) => ({ value: c.name, label: c.name })),
]
const matchesContainer = (container: string | undefined, filter: string) =>
  !filter || (filter === HOST_SELF ? !container : container === filter)

// ── 헤더 ─────────────────────────────────────────────

const subtitle = asset
  ? [assetKindLabel[asset.kind], asset.os ? `${asset.os.name} ${asset.os.version}` : undefined, assetLocation(asset)]
      .filter(Boolean)
      .join(' · ')
  : undefined

const collectRequested = ref(false)

type SbomFormat = 'cyclonedx' | 'spdx'
const exportOpen = ref(false)
const exportFormat = ref<SbomFormat>('cyclonedx')
const sbomFormats: { value: SbomFormat; label: string; ext: string }[] = [
  { value: 'cyclonedx', label: 'CycloneDX JSON', ext: 'cdx.json' },
  { value: 'spdx', label: 'SPDX JSON', ext: 'spdx.json' },
]
const sbomFileName = (ext: string) => `${asset?.name ?? id}.${ext}`

// ── 탭 ───────────────────────────────────────────────

const tab = ref('overview')

function goTab(key: string) {
  tab.value = key
  router.replace({ query: { ...route.query, tab: key } })
}

// ── 취약점 (예외 처리를 반영하기 위해 복사본을 쓴다) ──

const findingRows = ref<FindingRow[]>(findingsOfAsset(id))

const activeFindings = computed(() => findingRows.value.filter(isActive))
const severityCounts = computed(() => countBySeverity(findingRows.value))
const findingStatuses = Object.keys(findingStatusLabel) as FindingStatus[]
const statusCounts = computed(() =>
  findingStatuses.map((status) => ({ status, count: findingRows.value.filter((f) => f.status === status).length })),
)

const vulnStatus = ref('active')
const vulnSeverity = ref('')
const vulnContainer = ref('')

const vulnRows = computed(() =>
  findingRows.value.filter((f) => {
    if (vulnStatus.value === 'active' ? !isActive(f) : vulnStatus.value && f.status !== vulnStatus.value) return false
    if (vulnSeverity.value && f.vuln.severity !== vulnSeverity.value) return false
    return matchesContainer(f.container, vulnContainer.value)
  }),
)

const vulnStatusOptions = [
  { value: 'active', label: '조치 필요' },
  ...findingStatuses.map((value) => ({ value, label: findingStatusLabel[value] })),
]
const severityOptions = SEVERITIES.map((value) => ({ value, label: severityLabel[value] }))

const vulnColumns: TableColumn<FindingRow>[] = [
  { key: 'vuln', label: 'ID', sortValue: (f) => f.vulnId },
  { key: 'severity', label: '심각도', sortValue: (f) => SEVERITIES.indexOf(f.vuln.severity) },
  { key: 'component', label: '컴포넌트', sortValue: (f) => f.component.name },
  { key: 'status', label: '상태', sortValue: (f) => findingStatuses.indexOf(f.status), hideBelow: 'sm' },
  { key: 'fix', label: '수정 버전', hideBelow: 'md' },
  { key: 'basis', label: '판정 근거', hideBelow: 'lg' },
  { key: 'flags', label: '실행 중·노출', sortValue: (f) => (f.exposed ? 0 : 1) + (f.inUse ? 0 : 2), hideBelow: 'md' },
  { key: 'firstDetected', label: '최초 탐지', align: 'right', sortValue: (f) => f.firstDetected, hideBelow: 'lg' },
  { key: 'actions', label: '', align: 'right' },
]

const triageOpen = ref(false)
const triageTarget = ref<FindingRow>()
const triageNote = ref('')

function openTriage(f: FindingRow) {
  triageTarget.value = f
  triageNote.value = ''
  triageOpen.value = true
}

function applyTriage() {
  const note = triageNote.value.trim()
  const target = findingRows.value.find((f) => f.id === triageTarget.value?.id)
  if (!target || !note) return
  target.status = 'accepted'
  target.triageNote = note
  triageOpen.value = false
}

// ── 컴포넌트 ─────────────────────────────────────────

const componentRows = componentsOfAsset(id)

// 같은 컴포넌트가 호스트와 여러 컨테이너에 있을 수 있어 (컨테이너, 컴포넌트)로 구분한다
const placeKey = (r: { container?: string; componentId: string }) => `${r.container ?? ''}|${r.componentId}`

// 위치별 조치 필요 취약점. 예외 처리하면 줄어든다.
const countsByPlace = computed(() => {
  const map = new Map<string, FindingRow[]>()
  for (const f of findingRows.value) map.set(placeKey(f), [...(map.get(placeKey(f)) ?? []), f])
  return new Map([...map].map(([key, rows]) => [key, countBySeverity(rows)]))
})
const componentCounts = (r: AssetComponentRow) => countsByPlace.value.get(placeKey(r)) ?? emptyCounts()

const compQuery = ref('')
const compType = ref('')
const compOrigin = ref('')
const compContainer = ref('')
const compInUseOnly = ref(false)

const filteredComponents = computed(() => {
  const needle = compQuery.value.trim().toLowerCase()
  return componentRows.filter((r) => {
    if (compType.value && r.component.type !== compType.value) return false
    if (compOrigin.value && r.component.origin !== compOrigin.value) return false
    if (!matchesContainer(r.container, compContainer.value)) return false
    if (compInUseOnly.value && !r.inUse) return false
    if (!needle) return true
    return [r.component.name, r.component.version, r.component.purl, r.container ?? '', ...r.locations].some((v) =>
      v.toLowerCase().includes(needle),
    )
  })
})

const compTypeOptions = [...new Set(componentRows.map((r) => r.component.type))]
  .sort()
  .map((value: ComponentType) => ({ value, label: componentTypeLabel[value] }))
const compOriginOptions = (Object.keys(originLabel) as ComponentOrigin[]).map((value) => ({ value, label: originLabel[value] }))

const componentColumns: TableColumn<AssetComponentRow>[] = [
  { key: 'name', label: '이름', sortValue: (r) => r.component.name },
  { key: 'version', label: '버전', sortValue: (r) => r.component.version },
  { key: 'type', label: '종류', sortValue: (r) => r.component.type, hideBelow: 'md' },
  { key: 'origin', label: '출처', sortValue: (r) => r.component.origin, hideBelow: 'lg' },
  { key: 'method', label: '탐지 방법', sortValue: (r) => r.method, hideBelow: 'lg' },
  { key: 'locations', label: '위치', hideBelow: 'md' },
  { key: 'inUse', label: '실행 중', sortValue: (r) => (r.inUse ? 0 : 1), hideBelow: 'sm' },
  {
    key: 'vulns',
    label: '취약점',
    sortValue: (r) => {
      const c = componentCounts(r)
      return -(c.critical * 1e6 + c.high * 1e3 + totalOf(c))
    },
  },
]

const rawOpen = ref(false)
const rawTarget = ref<AssetComponentRow>()

function openRaw(r: AssetComponentRow) {
  rawTarget.value = r
  rawOpen.value = true
}

// ── 프로세스 ─────────────────────────────────────────

const procs = processesOfAsset(id)
const restartCount = procs.filter(needsRestart).length
const suspiciousCount = procs.filter(isSuspicious).length
const listenCount = new Set(procs.flatMap((p) => p.listen.map((l) => `${l.proto}|${l.address}|${l.port}`))).size

const procQuery = ref('')
const procView = ref('')
const procViewOptions = [
  { value: 'restart', label: '재시작 필요' },
  { value: 'suspicious', label: '의심 프로세스' },
  { value: 'listen', label: 'listen 포트 있음' },
]

const procRows = computed(() => {
  const needle = procQuery.value.trim().toLowerCase()
  return procs.filter((p) => {
    if (procView.value === 'restart' && !needsRestart(p)) return false
    if (procView.value === 'suspicious' && !isSuspicious(p)) return false
    if (procView.value === 'listen' && p.listen.length === 0) return false
    if (!needle) return true
    return [p.exePath, p.user, p.cmdline, String(p.pid)].some((v) => v.toLowerCase().includes(needle))
  })
})

function goProcesses(view: string) {
  procView.value = view
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
const procRank = (p: ProcessInfo) => (isSuspicious(p) ? 0 : needsRestart(p) ? 1 : 2)

const procColumns: TableColumn<ProcessInfo>[] = [
  { key: 'pid', label: 'pid', sortValue: (p) => p.pid },
  { key: 'user', label: '사용자', sortValue: (p) => p.user, hideBelow: 'sm' },
  { key: 'exe', label: '실행 파일', sortValue: (p) => exeName(p) },
  { key: 'state', label: '상태', sortValue: procRank },
  { key: 'listen', label: 'listen 포트', sortValue: (p) => -p.listen.length, hideBelow: 'md' },
  { key: 'sha256', label: 'sha256', hideBelow: 'lg' },
  { key: 'startedAt', label: '시작', align: 'right', sortValue: (p) => p.startedAt, hideBelow: 'sm' },
]

// 선택한 프로세스는 쿼리(proc)에 둔다. 표의 행 이동으로 고르고 뒤로 가기로 되돌린다.
const procLink = (p: ProcessInfo) => `/assets/${encodeURIComponent(id)}?tab=processes&proc=${encodeURIComponent(p.id)}`
const selectedProc = computed(() => {
  const key = route.query.proc
  return typeof key === 'string' ? procs.find((p) => p.id === key) : undefined
})
const selectedContainer = computed(() => getContainer(id, selectedProc.value?.container))
const selectedComponent = computed(() => (selectedProc.value?.componentId ? getComponent(selectedProc.value.componentId) : undefined))

function closeProc() {
  const { proc: _proc, ...query } = route.query
  router.replace({ query })
}

// ── 컨테이너 ─────────────────────────────────────────

// severityCountsOfContainer와 같은 집계를 예외 처리가 반영된 복사본으로 한다
const containerCounts = (name: string) => countBySeverity(findingRows.value.filter((f) => f.container === name))

const containerColumns: TableColumn<AssetContainer>[] = [
  { key: 'name', label: '이름', sortValue: (c) => c.name },
  { key: 'image', label: '이미지', sortValue: (c) => c.imageRef },
  { key: 'runtime', label: 'runtime', sortValue: (c) => c.runtime, hideBelow: 'md' },
  { key: 'instances', label: '인스턴스', align: 'right', sortValue: (c) => c.instances, hideBelow: 'sm' },
  { key: 'coverage', label: '수집 범위', sortValue: (c) => c.coverage, hideBelow: 'sm' },
  {
    key: 'vulns',
    label: '취약점',
    sortValue: (c) => {
      const n = containerCounts(c.name)
      return -(n.critical * 1e6 + n.high * 1e3 + totalOf(n))
    },
  },
]

const pods = asset?.kind === 'workload' ? podsOfAsset(id) : []

const podPhaseLabel: Record<K8sPod['phase'], string> = { Running: '실행 중', Pending: '대기', Succeeded: '완료', Failed: '실패' }
const podPhaseTone: Record<K8sPod['phase'], Tone> = { Running: 'ok', Pending: 'warn', Succeeded: 'neutral', Failed: 'danger' }

const podColumns: TableColumn<K8sPod>[] = [
  { key: 'name', label: 'pod', sortValue: (p) => p.name },
  { key: 'node', label: '노드', sortValue: (p) => p.node, hideBelow: 'md' },
  { key: 'phase', label: '상태', sortValue: (p) => p.phase },
  { key: 'containers', label: '컨테이너별 수집 범위' },
]

// ── 수집 ─────────────────────────────────────────────

const sectionCoverageLabel: Record<SectionCoverage['coverage'], string> = { full: '전체', partial: '부분', none: '수집 안 함' }
const sectionCoverageTone: Record<SectionCoverage['coverage'], Tone> = { full: 'ok', partial: 'warn', none: 'danger' }

const sectionColumns: TableColumn<SectionCoverage>[] = [
  { key: 'section', label: '섹션' },
  { key: 'coverage', label: '범위' },
  { key: 'reason', label: '사유' },
  { key: 'collectedAt', label: '수집 시각', align: 'right', hideBelow: 'sm' },
]

// privileged 수집과 non-root의 차이. 제한되는 항목만 적는다.
const nonRootLimits: { item: string; limit: string }[] = [
  { item: '프로세스 목록', limit: '/proc이 hidepid로 마운트되어 있으면 자기 프로세스만 보입니다' },
  { item: '실행 파일 경로·해시, 삭제된 파일 감지', limit: '자기 사용자의 프로세스만. 나머지는 cmdline에서 추정한 경로로 표시합니다' },
  { item: 'listen 포트', limit: '포트와 소유 uid까지. 프로세스 연결은 자기 사용자 것만 합니다' },
  { item: 'JAR, Go 바이너리, 알려진 소프트웨어', limit: '읽을 수 있는 경로만' },
  { item: '버전 실행', limit: '자기가 실행할 수 있는 파일만' },
  { item: '컨테이너', limit: '프로세스의 cgroup에서 얻는 컨테이너 ID까지' },
]

// ── 탭 목록 ──────────────────────────────────────────

const tabs = computed(() => [
  { key: 'overview', label: '개요' },
  { key: 'components', label: '컴포넌트', count: componentRows.length },
  { key: 'vulns', label: '취약점', count: activeFindings.value.length },
  { key: 'processes', label: '프로세스', count: procs.length },
  ...(assetContainers.length > 0 ? [{ key: 'containers', label: '컨테이너', count: assetContainers.length }] : []),
  { key: 'collection', label: '수집' },
])

const severityOf = (s: Severity) => severityCounts.value[s]
</script>

<template>
  <div>
    <template v-if="!asset">
      <PageHeader title="자산" :back="{ to: '/assets', label: '자산' }" />
      <Panel>
        <EmptyState title="찾을 수 없음">
          <AppButton to="/assets">자산 목록</AppButton>
        </EmptyState>
      </Panel>
    </template>

    <template v-else>
      <PageHeader :title="asset.name" :subtitle="subtitle" :back="{ to: '/assets', label: '자산' }">
        <template #actions>
          <AppButton :icon="Download" @click="exportOpen = true">SBOM 내보내기</AppButton>
          <AppButton variant="primary" :icon="RefreshCw" :disabled="collectRequested" @click="collectRequested = true">
            {{ collectRequested ? '수집 요청됨' : '수집 실행' }}
          </AppButton>
        </template>

        <div class="space-y-2">
          <p v-if="limited" class="note note-warn">
            수집 범위: {{ coverageLabel[asset.coverage] }}<template v-if="asset.coverageReason"> ({{ asset.coverageReason }})</template>.
            확인하지 못한 범위가 있습니다. 취약점이 없다는 뜻이 아닙니다.
          </p>
          <AppTabs v-model="tab" :tabs="tabs" query-key="tab" />
        </div>
      </PageHeader>

      <!-- 개요 -->
      <div v-if="tab === 'overview'" class="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Panel title="자산 정보" class="lg:col-span-2">
          <dl class="kv">
            <dt>종류</dt>
            <dd>{{ assetKindLabel[asset.kind] }}</dd>
            <dt>OS</dt>
            <dd>
              <template v-if="asset.os">{{ asset.os.name }} <span class="mono text-ink-2">{{ asset.os.version }}</span></template>
              <span v-else class="text-ink-3">—</span>
            </dd>
            <dt>커널</dt>
            <dd :class="asset.os?.kernel ? 'mono' : 'text-ink-3'">{{ asset.os?.kernel ?? '—' }}</dd>
            <dt>아키텍처</dt>
            <dd :class="asset.os ? 'mono' : 'text-ink-3'">{{ asset.os?.arch ?? '—' }}</dd>
            <dt>주소</dt>
            <dd :class="asset.address ? 'mono' : 'text-ink-3'">{{ asset.address ?? '—' }}</dd>
            <dt>그룹</dt>
            <dd>{{ asset.group }}</dd>
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
                <NuxtLink v-if="cluster" :to="`/kubernetes/${cluster.id}`" class="link">{{ cluster.name }}</NuxtLink>
                <span v-else class="text-ink-3">—</span>
              </dd>
              <dt>namespace</dt>
              <dd :class="asset.namespace ? 'mono' : 'text-ink-3'">{{ asset.namespace ?? '—' }}</dd>
              <dt>워크로드 종류</dt>
              <dd>{{ asset.workloadKind ?? workload?.kind ?? '—' }}</dd>
              <dt>replicas</dt>
              <dd :class="workload ? 'mono' : 'text-ink-3'">{{ workload?.replicas ?? '—' }}</dd>
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
          <Panel title="취약점">
            <template #actions>
              <AppButton size="sm" variant="ghost" @click="goTab('vulns')">목록</AppButton>
            </template>
            <p v-if="unknown" class="text-sm text-ink-3">수집 범위가 {{ coverageLabel[asset.coverage] }}이라 확인할 수 없습니다.</p>
            <template v-else>
              <ul class="space-y-1.5">
                <li v-for="s in SEVERITIES" :key="s" class="flex items-center justify-between">
                  <SeverityBadge :severity="s" />
                  <span class="mono" :class="severityOf(s) > 0 ? 'font-semibold' : 'text-ink-3'">{{ severityOf(s) }}</span>
                </li>
              </ul>
              <ul class="mt-3 space-y-1.5 border-t border-line pt-3">
                <li v-for="s in statusCounts" :key="s.status" class="flex items-center justify-between">
                  <StatusBadge :tone="findingStatusTone[s.status]" :label="findingStatusLabel[s.status]" />
                  <span class="mono" :class="s.count > 0 ? '' : 'text-ink-3'">{{ s.count }}</span>
                </li>
              </ul>
            </template>
          </Panel>

          <Panel title="프로세스">
            <ul class="space-y-0.5 text-sm">
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
                  <span>listen 포트</span>
                  <span class="mono" :class="listenCount > 0 ? '' : 'text-ink-3'">{{ listenCount }}</span>
                </button>
              </li>
            </ul>
          </Panel>
        </div>
      </div>

      <!-- 컴포넌트 -->
      <div v-else-if="tab === 'components'">
        <FilterBar :count="filteredComponents.length" :total="componentRows.length" unit="개">
          <SearchInput v-model="compQuery" placeholder="이름, 버전, purl, 경로" />
          <SelectFilter v-model="compType" label="종류" :options="compTypeOptions" />
          <SelectFilter v-model="compOrigin" label="출처" :options="compOriginOptions" />
          <SelectFilter v-if="assetContainers.length > 0" v-model="compContainer" label="컨테이너" :options="containerOptions" />
          <label class="inline-flex items-center gap-1.5 text-sm">
            <input v-model="compInUseOnly" type="checkbox" class="accent-(--accent)" /> 실행 중만
          </label>
        </FilterBar>

        <Panel flush>
          <DataTable
            :columns="componentColumns"
            :rows="filteredComponents"
            :row-key="placeKey"
            :row-to="(r) => `/components/${r.componentId}`"
            :page-size="25"
            :initial-sort="{ key: 'vulns', dir: 'asc' }"
          >
            <template #cell-name="{ row }">
              <NuxtLink :to="`/components/${row.componentId}`" class="font-medium hover:underline">{{ row.component.name }}</NuxtLink>
              <div v-if="row.container" class="text-xs text-ink-3">
                {{ row.container }}<template v-if="row.layer"> · {{ layerLabel[row.layer] }}</template>
              </div>
            </template>
            <template #cell-version="{ row }">
              <span class="inline-flex flex-wrap items-center gap-1.5">
                <span class="mono whitespace-nowrap">{{ row.component.version }}</span>
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
            <template #cell-vulns="{ row }">
              <SeverityCounts :counts="componentCounts(row)" />
            </template>
          </DataTable>
        </Panel>
      </div>

      <!-- 취약점 -->
      <div v-else-if="tab === 'vulns'">

        <FilterBar :count="vulnRows.length" :total="findingRows.length">
          <SelectFilter v-model="vulnStatus" label="상태" :options="vulnStatusOptions" />
          <SelectFilter v-model="vulnSeverity" label="심각도" :options="severityOptions" />
          <SelectFilter v-if="assetContainers.length > 0" v-model="vulnContainer" label="컨테이너" :options="containerOptions" />
        </FilterBar>

        <Panel flush>
          <DataTable
            :columns="vulnColumns"
            :rows="vulnRows"
            :row-key="(f) => f.id"
            :row-to="(f) => `/vulnerabilities/${f.vulnId}`"
            :page-size="25"
            :initial-sort="{ key: 'severity', dir: 'asc' }"
          >
            <template #cell-vuln="{ row }">
              <span class="inline-flex flex-wrap items-center gap-1.5">
                <NuxtLink :to="`/vulnerabilities/${row.vulnId}`" class="mono whitespace-nowrap font-medium hover:underline">{{ row.vulnId }}</NuxtLink>
                <StatusBadge v-if="row.vuln.kev" tone="danger" label="KEV" />
              </span>
            </template>
            <template #cell-severity="{ row }">
              <SeverityBadge :severity="row.vuln.severity" />
            </template>
            <template #cell-component="{ row }">
              <NuxtLink :to="`/components/${row.componentId}`" class="hover:underline">{{ row.component.name }}</NuxtLink>
              <div class="mono whitespace-nowrap text-xs text-ink-3">{{ row.component.version }}</div>
              <div v-if="row.container" class="text-xs text-ink-3">컨테이너 {{ row.container }}</div>
            </template>
            <template #cell-status="{ row }">
              <StatusBadge :tone="findingStatusTone[row.status]" :label="findingStatusLabel[row.status]" />
              <div v-if="row.triageNote" class="mt-0.5 max-w-56 text-xs text-ink-3" :title="row.triageNote">{{ row.triageNote }}</div>
            </template>
            <template #cell-fix="{ row }">
              <span v-if="row.match?.fixedVersion" class="mono whitespace-nowrap">{{ row.match.fixedVersion }}</span>
              <span v-else-if="row.match" class="text-ink-2">{{ fixStateLabel[row.match.fixState] }}</span>
              <span v-else class="text-ink-3">—</span>
            </template>
            <template #cell-basis="{ row }">
              <template v-if="row.match">
                {{ matchBasisLabel[row.match.basis] }}
                <div v-if="row.match.advisoryId" class="mono whitespace-nowrap text-xs text-ink-3">{{ row.match.advisoryId }}</div>
              </template>
              <span v-else class="text-ink-3">—</span>
            </template>
            <template #cell-flags="{ row }">
              <span v-if="row.inUse || row.exposed" class="inline-flex flex-wrap gap-1">
                <StatusBadge v-if="row.inUse" tone="info" label="실행 중" />
                <StatusBadge v-if="row.exposed" tone="danger" label="노출" />
              </span>
              <span v-else class="text-ink-3">—</span>
            </template>
            <template #cell-firstDetected="{ row }">
              <TimeAgo :at="row.firstDetected" class="text-ink-2" />
            </template>
            <template #cell-actions="{ row }">
              <AppButton v-if="isActive(row)" size="sm" @click="openTriage(row)">예외 처리</AppButton>
            </template>
          </DataTable>
        </Panel>
      </div>

      <!-- 프로세스 -->
      <div v-else-if="tab === 'processes'">
        <p v-if="asset.privilege === 'non_root'" class="note note-warn mb-3">
          non-root로 수집한 자산입니다. 다른 사용자의 프로세스는 실행 파일 경로를 cmdline에서 추정하고("추정" 표시), 해시와 삭제 여부를 확인하지 못합니다.
        </p>

        <FilterBar :count="procRows.length" :total="procs.length" unit="개">
          <SearchInput v-model="procQuery" placeholder="실행 파일, 사용자, cmdline, pid" />
          <SelectFilter v-model="procView" label="상태" :options="procViewOptions" />
        </FilterBar>

        <Panel flush>
          <DataTable
            :columns="procColumns"
            :rows="procRows"
            :row-key="(p) => p.id"
            :row-to="procLink"
            :page-size="25"
            :initial-sort="{ key: 'state', dir: 'asc' }"
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
              <div v-if="row.container" class="text-xs text-ink-3">컨테이너 {{ row.container }}</div>
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
            <template v-if="selectedComponent">
              <dt>컴포넌트</dt>
              <dd>
                <NuxtLink :to="`/components/${selectedComponent.id}`" class="link">{{ selectedComponent.name }}</NuxtLink>
                <span class="mono ml-1 text-ink-2">{{ selectedComponent.version }}</span>
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

      <!-- 컨테이너 -->
      <div v-else-if="tab === 'containers'">
        <Panel flush>
          <DataTable
            :columns="containerColumns"
            :rows="assetContainers"
            :row-key="(c) => c.name"
            :initial-sort="{ key: 'vulns', dir: 'asc' }"
          >
            <template #cell-name="{ row }">
              <span class="font-medium">{{ row.name }}</span>
            </template>
            <template #cell-image="{ row }">
              <NuxtLink :to="`/images/${encodeURIComponent(row.imageDigest)}`" class="mono break-all hover:underline">{{ row.imageRef }}</NuxtLink>
              <div class="mono whitespace-nowrap text-xs text-ink-3" :title="row.imageDigest">{{ shortHash(row.imageDigest) }}</div>
            </template>
            <template #cell-runtime="{ row }">{{ runtimeLabel[row.runtime] }}</template>
            <template #cell-instances="{ row }">
              <span class="mono" :class="row.instances > 0 ? '' : 'text-ink-3'">{{ row.instances }}</span>
            </template>
            <template #cell-coverage="{ row }">
              <CoverageBadge :coverage="row.coverage" :reason="row.coverageReason" />
              <div v-if="row.coverageReason" class="mt-0.5 max-w-56 text-xs text-ink-3">{{ row.coverageReason }}</div>
            </template>
            <template #cell-vulns="{ row }">
              <SeverityCounts v-if="imageContentKnown(row.imageDigest)" :counts="containerCounts(row.name)" />
              <span v-else class="whitespace-nowrap text-xs text-ink-3">확인 불가</span>
            </template>
          </DataTable>
        </Panel>

        <Panel v-if="asset.kind === 'workload'" title="인스턴스" class="mt-4" flush>
          <DataTable :columns="podColumns" :rows="pods" :row-key="(p) => p.id">
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

      <!-- 수집 -->
      <div v-else-if="tab === 'collection'" class="space-y-4">
        <Panel title="섹션별 수집 범위" flush>
          <DataTable :columns="sectionColumns" :rows="asset.sections" :row-key="(s) => s.section">
            <template #cell-section="{ row }">{{ sectionLabel[row.section] }}</template>
            <template #cell-coverage="{ row }">
              <StatusBadge :tone="sectionCoverageTone[row.coverage]" :label="sectionCoverageLabel[row.coverage]" dot />
            </template>
            <template #cell-reason="{ row }">
              <span :class="row.reason ? 'text-ink-2' : 'text-ink-3'">{{ row.reason ?? '—' }}</span>
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

      <!-- SBOM 내보내기 -->
      <AppModal v-model:open="exportOpen" title="SBOM 내보내기">
        <fieldset class="space-y-2">
          <legend class="mb-1 text-xs font-medium text-ink-2">형식</legend>
          <label
            v-for="f in sbomFormats"
            :key="f.value"
            class="flex cursor-pointer items-start gap-2 rounded-md border px-3 py-2 text-sm"
            :class="exportFormat === f.value ? 'border-accent bg-accent-soft' : 'border-line hover:bg-surface-2'"
          >
            <input v-model="exportFormat" type="radio" name="sbom-format" :value="f.value" class="mt-1 accent-(--accent)" />
            <span class="min-w-0">
              <span class="block font-medium">{{ f.label }}</span>
              <span class="mono block break-all text-xs text-ink-3">{{ sbomFileName(f.ext) }}</span>
            </span>
          </label>
        </fieldset>
        <p v-if="limited" class="note note-warn mt-3">수집 범위가 제한된 자산입니다. SBOM에 빠진 컴포넌트가 있을 수 있습니다.</p>
        <template #footer>
          <AppButton @click="exportOpen = false">취소</AppButton>
          <AppButton variant="primary" :icon="Download" @click="exportOpen = false">다운로드</AppButton>
        </template>
      </AppModal>

      <!-- 버전 출력 -->
      <AppModal v-model:open="rawOpen" :title="rawTarget ? `${rawTarget.component.name} 버전 출력` : '버전 출력'" wide>
        <template v-if="rawTarget">
          <dl class="kv">
            <dt>실행한 명령</dt>
            <dd :class="rawTarget.versionCommand ? 'mono' : 'text-ink-3'">{{ rawTarget.versionCommand ?? '—' }}</dd>
            <dt>파싱한 버전</dt>
            <dd class="mono">{{ rawTarget.component.version }}</dd>
            <dt>탐지 방법</dt>
            <dd>{{ detectMethodLabel[rawTarget.method] }}</dd>
          </dl>
          <pre class="pre mt-3">{{ rawTarget.versionRaw }}</pre>
        </template>
        <template #footer>
          <AppButton @click="rawOpen = false">닫기</AppButton>
        </template>
      </AppModal>

      <!-- 예외 처리 -->
      <AppModal v-model:open="triageOpen" title="예외 처리">
        <template v-if="triageTarget">
          <dl class="kv mb-3">
            <dt>취약점</dt>
            <dd class="mono">{{ triageTarget.vulnId }}</dd>
            <dt>컴포넌트</dt>
            <dd>{{ triageTarget.component.name }} <span class="mono text-ink-2">{{ triageTarget.component.version }}</span></dd>
            <template v-if="triageTarget.container">
              <dt>컨테이너</dt>
              <dd>{{ triageTarget.container }}</dd>
            </template>
          </dl>
          <FormField label="사유">
            <textarea v-model="triageNote" class="input w-full" rows="3" placeholder="예: 외부에서 접근할 수 없는 관리망 전용 호스트" />
          </FormField>
        </template>
        <template #footer>
          <AppButton @click="triageOpen = false">취소</AppButton>
          <AppButton variant="primary" :disabled="!triageNote.trim()" @click="applyTriage">예외 처리</AppButton>
        </template>
      </AppModal>
    </template>
  </div>
</template>
