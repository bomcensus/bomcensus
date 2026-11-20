<script setup lang="ts">
import type { Coverage, K8sWorkload } from '~/types'
import type { TableColumn } from '~/types/table'
import { getAgent, getAsset, getCluster, podsOfWorkload, severityCountsOfAsset, totalOf, workloadsOfCluster } from '~/mock'

const route = useRoute()
const cluster = computed(() => getCluster(String(route.params.id)))

useHead({ title: computed(() => `${cluster.value?.name ?? 'Kubernetes'} · bomcensus`) })

const workloads = computed(() => (cluster.value ? workloadsOfCluster(cluster.value.id) : []))
const scanner = computed(() => (cluster.value ? getAgent(cluster.value.scannerId) : undefined))

const q = ref('')
const namespace = ref('')
const selectedId = ref('')

const namespaceOptions = computed(() =>
  [...new Set(workloads.value.map((w) => w.namespace))].sort().map((value) => ({ value, label: value })),
)

const rows = computed(() => {
  const needle = q.value.trim().toLowerCase()
  return workloads.value.filter((w) => {
    if (namespace.value && w.namespace !== namespace.value) return false
    if (!needle) return true
    return [w.name, w.namespace, w.kind].some((v) => v.toLowerCase().includes(needle))
  })
})

const selected = computed(() => workloads.value.find((w) => w.id === selectedId.value))
const selectedPods = computed(() => (selected.value ? podsOfWorkload(selected.value.id) : []))

// pod 컨테이너들의 범위를 중복 없이 모은다
const coverageOf = (w: K8sWorkload): Coverage[] => [
  ...new Set(podsOfWorkload(w.id).flatMap((p) => p.containers.map((c) => c.coverage))),
]

const excludedCount = computed(() => workloads.value.filter((w) => w.excluded).length)

const filterRows = computed(() => {
  const f = cluster.value?.filter
  if (!f) return []
  return [
    { label: 'namespace', include: f.nsInclude, exclude: f.nsExclude },
    { label: 'label', include: f.labelInclude, exclude: f.labelExclude },
    { label: 'annotation', include: f.annotationInclude, exclude: f.annotationExclude },
  ]
})

const columns: TableColumn<K8sWorkload>[] = [
  { key: 'namespace', label: 'namespace', sortValue: (w) => w.namespace, hideBelow: 'sm' },
  { key: 'kind', label: '종류', sortValue: (w) => w.kind, hideBelow: 'md' },
  { key: 'name', label: '이름', sortValue: (w) => w.name },
  { key: 'replicas', label: 'replicas', align: 'right', sortValue: (w) => w.replicas, hideBelow: 'md' },
  { key: 'coverage', label: '수집 범위' },
  { key: 'vulns', label: '취약점', sortValue: (w) => (w.assetId ? totalOf(severityCountsOfAsset(w.assetId)) : -1) },
  { key: 'pods', label: '' },
]
</script>

<template>
  <div>
    <template v-if="cluster">
      <PageHeader
        :title="cluster.name"
        :subtitle="`Kubernetes ${cluster.version}`"
        :back="{ to: '/kubernetes', label: 'Kubernetes' }"
      />

      <div class="grid grid-cols-1 gap-4 md:grid-cols-2">
        <Panel title="클러스터" class="min-w-0">
          <dl class="kv">
            <dt>버전</dt>
            <dd class="mono">{{ cluster.version }}</dd>
            <dt>연결 방식</dt>
            <dd>{{ cluster.connection === 'in_cluster' ? 'in-cluster' : 'kubeconfig' }}</dd>
            <dt>exec 수집</dt>
            <dd><StatusBadge :tone="cluster.execEnabled ? 'ok' : 'neutral'" :label="cluster.execEnabled ? '사용' : '미사용'" /></dd>
            <dt>Scanner</dt>
            <dd>
              <NuxtLink v-if="scanner" :to="`/agents/${scanner.id}`" class="link mono">{{ scanner.hostname }}</NuxtLink>
              <span v-else class="text-ink-3">—</span>
            </dd>
            <dt>워크로드</dt>
            <dd class="mono">{{ workloads.length }} (제외 {{ excludedCount }})</dd>
            <dt>최근 동기화</dt>
            <dd><TimeAgo :at="cluster.lastSync" /></dd>
          </dl>
        </Panel>

        <Panel title="수집 필터" class="min-w-0">
          <table class="w-full text-sm">
            <thead>
              <tr class="text-left text-xs text-ink-2">
                <th class="py-1 pr-3 font-medium">대상</th>
                <th class="py-1 pr-3 font-medium">include</th>
                <th class="py-1 font-medium">exclude</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="f in filterRows" :key="f.label" class="border-t border-line align-top">
                <td class="whitespace-nowrap py-1.5 pr-3">{{ f.label }}</td>
                <td class="mono py-1.5 pr-3 break-all">{{ f.include.length ? f.include.join(', ') : '—' }}</td>
                <td class="mono py-1.5 break-all">{{ f.exclude.length ? f.exclude.join(', ') : '—' }}</td>
              </tr>
            </tbody>
          </table>
        </Panel>
      </div>

      <p v-if="!cluster.execEnabled" class="note note-warn mt-4">
        exec 수집이 꺼져 있습니다. 이미지 인벤토리만 수집하며 패키지, 프로세스, listen 포트는 확인하지 못합니다. 취약점이 없다는 뜻이 아닙니다.
      </p>

      <FilterBar :count="rows.length" :total="workloads.length" unit="개" class="mt-4">
        <SearchInput v-model="q" placeholder="이름, namespace, 종류" />
        <SelectFilter v-model="namespace" label="namespace" :options="namespaceOptions" />
      </FilterBar>

      <Panel title="워크로드" flush>
        <DataTable
          :columns="columns"
          :rows="rows"
          :row-key="(w) => w.id"
          :page-size="25"
        >
          <template #cell-namespace="{ row }"><span class="mono whitespace-nowrap">{{ row.namespace }}</span></template>
          <template #cell-kind="{ row }">{{ row.kind }}</template>
          <template #cell-name="{ row }">
            <NuxtLink v-if="row.assetId && getAsset(row.assetId)" :to="`/assets/${row.assetId}`" class="font-medium hover:underline">
              {{ row.name }}
            </NuxtLink>
            <span v-else class="font-medium">{{ row.name }}</span>
            <div v-if="row.excluded" class="mt-0.5 flex flex-wrap items-center gap-1.5 text-xs text-ink-3">
              <StatusBadge tone="neutral" label="제외" />
              <span v-if="row.excludedBy" class="mono">{{ row.excludedBy }}</span>
            </div>
          </template>
          <template #cell-replicas="{ row }"><span class="mono whitespace-nowrap">{{ row.replicas }}</span></template>
          <template #cell-coverage="{ row }">
            <div v-if="coverageOf(row).length" class="flex flex-wrap gap-1">
              <CoverageBadge v-for="c in coverageOf(row)" :key="c" :coverage="c" />
            </div>
            <span v-else class="text-ink-3">—</span>
          </template>
          <template #cell-vulns="{ row }">
            <SeverityCounts v-if="row.assetId && getAsset(row.assetId)" :counts="severityCountsOfAsset(row.assetId)" />
            <span v-else class="text-xs text-ink-3">—</span>
          </template>
          <template #cell-pods="{ row }">
            <AppButton size="sm" @click="selectedId = row.id">pod 보기</AppButton>
          </template>
        </DataTable>
      </Panel>

      <Panel v-if="selected" :title="`pod · ${selected.name}`" class="mt-4" flush>
        <template #actions>
          <AppButton size="sm" variant="ghost" @click="selectedId = ''">닫기</AppButton>
        </template>
        <p v-if="selectedPods.length === 0" class="px-3 py-3 text-sm text-ink-2">
          {{ selected.excluded ? '제외된 워크로드라 수집한 pod가 없습니다.' : '수집한 pod가 없습니다.' }}
        </p>
        <div v-else class="overflow-x-auto">
          <table class="w-full border-collapse text-sm">
            <thead>
              <tr class="border-b border-line bg-surface-2 text-left text-xs text-ink-2">
                <th class="px-3 py-2 font-medium">pod</th>
                <th class="hidden px-3 py-2 font-medium md:table-cell">노드</th>
                <th class="hidden px-3 py-2 font-medium sm:table-cell">상태</th>
                <th class="px-3 py-2 font-medium">컨테이너</th>
                <th class="hidden px-3 py-2 font-medium md:table-cell">digest</th>
                <th class="px-3 py-2 font-medium">수집 범위</th>
              </tr>
            </thead>
            <tbody>
              <template v-for="p in selectedPods" :key="p.id">
                <tr v-for="(c, i) in p.containers" :key="`${p.id}/${c.name}`" class="border-b border-line align-top last:border-b-0">
                  <td class="mono px-3 py-2 break-all">{{ i === 0 ? p.name : '' }}</td>
                  <td class="mono hidden px-3 py-2 md:table-cell">{{ i === 0 ? p.node : '' }}</td>
                  <td class="hidden px-3 py-2 sm:table-cell">{{ i === 0 ? p.phase : '' }}</td>
                  <td class="px-3 py-2">
                    {{ c.name }}
                    <div class="mono text-xs break-all text-ink-3">{{ c.imageRef }}</div>
                  </td>
                  <td class="hidden px-3 py-2 md:table-cell">
                    <NuxtLink :to="`/images/${encodeURIComponent(c.imageDigest)}`" class="link mono">{{ shortHash(c.imageDigest) }}</NuxtLink>
                  </td>
                  <td class="px-3 py-2">
                    <CoverageBadge :coverage="c.coverage" :reason="c.coverageReason" />
                    <div v-if="c.coverageReason" class="mt-0.5 text-xs text-ink-3">{{ c.coverageReason }}</div>
                  </td>
                </tr>
              </template>
            </tbody>
          </table>
        </div>
      </Panel>
    </template>

    <template v-else>
      <PageHeader title="클러스터" :back="{ to: '/kubernetes', label: 'Kubernetes' }" />
      <EmptyState title="찾을 수 없음">
        <AppButton to="/kubernetes">클러스터 목록</AppButton>
      </EmptyState>
    </template>
  </div>
</template>
