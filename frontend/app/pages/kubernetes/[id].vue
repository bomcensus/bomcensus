<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import { Pencil, RefreshCw, Trash2 } from '@lucide/vue'
import type { K8sWorkload } from '~/types'
import type { TableColumn } from '~/types/table'
import {
  deleteK8sCluster,
  fetchAll,
  getAgent,
  getK8sCluster,
  listAgents,
  listCredentials,
  listK8sWorkloadPods,
  listK8sWorkloads,
  optional,
  syncK8sCluster,
  toApiError,
  updateK8sCluster,
} from '~/api'

const route = useRoute()
// When only the id changes on the same page, NuxtPage recreates it, so the value at setup time is enough
const id = String(route.params.id)

// ── Loading ───────────────────────────────────────────

const {
  data: detail,
  error,
  refresh,
} = useLoad(`k8s:${id}`, async () => {
  const cluster = await getK8sCluster(id)
  // Absent scannerId means the embedded scanner; a deleted agent only leaves the link out.
  const scanner = cluster.scannerId ? await optional(getAgent(cluster.scannerId)) : undefined
  return { cluster, scanner }
})
const {
  data: workloads,
  pending: workloadsPending,
  error: workloadsError,
  refresh: refreshWorkloads,
} = useLoad(`k8s:${id}:workloads`, () => fetchAll((page) => listK8sWorkloads(id, page)), () => [])

const cluster = computed(() => detail.value?.cluster)
const scanner = computed(() => detail.value?.scanner)

useHead({ title: computed(() => `${cluster.value?.name ?? 'Kubernetes'} · bomcensus`) })

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
const {
  data: selectedPods,
  pending: podsPending,
  error: podsError,
  refresh: refreshPods,
} = useLoad(
  () => `k8s:workload:${selectedId.value}:pods`,
  () => (selectedId.value ? fetchAll((page) => listK8sWorkloadPods(selectedId.value, page)) : Promise.resolve([])),
  () => [],
)

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
  { key: 'pods', label: '' },
]

// ── Sync ──────────────────────────────────────────────

const syncState = ref<'idle' | 'sending' | 'requested'>('idle')
const actionError = ref('')

async function sync() {
  syncState.value = 'sending'
  actionError.value = ''
  try {
    await syncK8sCluster(id)
    syncState.value = 'requested'
    await refresh()
  } catch (e) {
    const err = toApiError(e)
    syncState.value = 'idle'
    actionError.value = err.status === 409 ? `동기화할 수 없는 상태입니다: ${err.message}` : err.message
  }
}

// ── Edit ──────────────────────────────────────────────

// Choices for the edit form
const { data: credentials } = useLoad('credentials', () => fetchAll((page) => listCredentials(page)), () => [])
const { data: agents } = useLoad('agents', () => fetchAll((page) => listAgents(page)), () => [])

const editOpen = ref(false)
const editForm = ref(k8sClusterForm())
const editBusy = ref(false)
const editError = ref('')

function openEdit() {
  editForm.value = k8sClusterForm(cluster.value)
  editError.value = ''
  editOpen.value = true
}

async function save() {
  if (!k8sClusterFormValid(editForm.value) || editBusy.value) return
  editBusy.value = true
  editError.value = ''
  try {
    await updateK8sCluster(id, k8sClusterUpdateBody(editForm.value))
    editOpen.value = false
    await Promise.all([refresh(), refreshWorkloads()])
  } catch (e) {
    const err = toApiError(e)
    editError.value = err.status === 409 ? '같은 이름의 클러스터가 있습니다' : err.message
  } finally {
    editBusy.value = false
  }
}

// ── Delete ────────────────────────────────────────────

const deleteOpen = ref(false)
const deleteBusy = ref(false)
const deleteError = ref('')

function openDelete() {
  deleteError.value = ''
  deleteOpen.value = true
}

async function remove() {
  if (deleteBusy.value) return
  deleteBusy.value = true
  deleteError.value = ''
  try {
    await deleteK8sCluster(id)
    deleteOpen.value = false
    await navigateTo('/kubernetes')
  } catch (e) {
    deleteError.value = toApiError(e).message
  } finally {
    deleteBusy.value = false
  }
}
</script>

<template>
  <div>
    <template v-if="cluster">
      <PageHeader
        :title="cluster.name"
        :subtitle="cluster.version ? `Kubernetes ${cluster.version}` : undefined"
        :back="{ to: '/kubernetes', label: 'Kubernetes' }"
      >
        <template #actions>
          <AppButton variant="primary" :icon="RefreshCw" :disabled="syncState !== 'idle'" @click="sync">
            {{ syncState === 'requested' ? '동기화 요청됨' : '동기화' }}
          </AppButton>
          <AppButton :icon="Pencil" @click="openEdit">편집</AppButton>
          <AppButton variant="danger" :icon="Trash2" @click="openDelete">삭제</AppButton>
        </template>
        <template v-if="actionError" #default>
          <p class="note note-danger" role="alert">{{ actionError }}</p>
        </template>
      </PageHeader>

      <div class="grid grid-cols-1 gap-4 md:grid-cols-2">
        <Panel title="클러스터" class="min-w-0">
          <dl class="kv">
            <dt>버전</dt>
            <dd class="mono">{{ cluster.version ?? '—' }}</dd>
            <dt>연결 방식</dt>
            <dd>{{ cluster.connection === 'in_cluster' ? 'in-cluster' : 'kubeconfig' }}</dd>
            <dt>exec 수집</dt>
            <dd><StatusBadge :tone="cluster.execEnabled ? 'ok' : 'neutral'" :label="cluster.execEnabled ? '사용' : '미사용'" /></dd>
            <dt>Scanner</dt>
            <dd>
              <template v-if="scanner">
                <NuxtLink :to="`/agents/${scanner.id}`" class="link mono">{{ scanner.hostname }}</NuxtLink>
                <span v-if="scanner.description" class="text-ink-3"> {{ scanner.description }}</span>
              </template>
              <span v-else class="text-ink-3">—</span>
            </dd>
            <dt>워크로드</dt>
            <dd class="mono">{{ cluster.workloadCount }} (제외 {{ cluster.excludedCount }})</dd>
            <dt>동기화</dt>
            <dd>
              <StatusBadge :tone="k8sSyncStatusTone[cluster.syncStatus]" :label="k8sSyncStatusLabel[cluster.syncStatus]" />
              <Diagnostic v-if="cluster.syncStatus === 'failed' && cluster.syncMessage" :text="cluster.syncMessage" class="mt-0.5" />
            </dd>
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
        exec 수집이 꺼져 있습니다. 이미지 인벤토리만 수집하며 패키지, 프로세스, listen 포트는 확인하지 못합니다.
      </p>

      <FilterBar :count="rows.length" :total="workloads.length" unit="개" class="mt-4">
        <SearchInput v-model="q" placeholder="이름, namespace, 종류" />
        <SelectFilter v-model="namespace" label="namespace" :options="namespaceOptions" />
      </FilterBar>

      <Panel title="워크로드" flush>
        <LoadError v-if="workloadsError" :error="workloadsError" @retry="refreshWorkloads" />
        <DataTable
          v-else
          :loading="workloadsPending"
          :columns="columns"
          :rows="rows"
          :row-key="(w) => w.id"
          :page-size="25"
        >
          <template #cell-namespace="{ row }"><span class="mono whitespace-nowrap">{{ row.namespace }}</span></template>
          <template #cell-kind="{ row }">{{ row.kind }}</template>
          <template #cell-name="{ row }">
            <NuxtLink v-if="row.assetId" :to="`/assets/${row.assetId}`" class="font-medium hover:underline">
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
            <div v-if="row.coverages.length" class="flex flex-wrap gap-1">
              <CoverageBadge v-for="c in row.coverages" :key="c" :coverage="c" />
            </div>
            <span v-else class="text-ink-3">—</span>
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
        <LoadError v-if="podsError" :error="podsError" @retry="refreshPods" />
        <LoadingText v-else-if="podsPending" />
        <p v-else-if="selectedPods.length === 0" class="px-3 py-3 text-sm text-ink-2">
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
                  <td class="hidden px-3 py-2 sm:table-cell">{{ i === 0 ? podPhaseLabel[p.phase] : '' }}</td>
                  <td class="px-3 py-2">
                    {{ c.name }}
                    <div class="mono text-xs break-all text-ink-3">{{ c.imageRef }}</div>
                  </td>
                  <td class="hidden px-3 py-2 md:table-cell">
                    <NuxtLink v-if="c.imageDigest" :to="`/images/${encodeURIComponent(c.imageDigest)}`" class="link mono">{{ shortHash(c.imageDigest) }}</NuxtLink>
                    <span v-else class="text-ink-3">—</span>
                  </td>
                  <td class="px-3 py-2">
                    <CoverageBadge :coverage="c.coverage" :reason="c.coverageReason" />
                    <Diagnostic v-if="c.coverageReason" :text="c.coverageReason" class="mt-0.5" />
                  </td>
                </tr>
              </template>
            </tbody>
          </table>
        </div>
      </Panel>

      <AppModal v-model:open="editOpen" title="클러스터 편집" wide>
        <form id="cluster-edit-form" @submit.prevent="save">
          <K8sClusterFields v-model="editForm" :credentials="credentials" :agents="agents" />
          <p v-if="editError" class="note note-danger mt-3" role="alert">{{ editError }}</p>
        </form>
        <template #footer>
          <AppButton @click="editOpen = false">취소</AppButton>
          <AppButton type="submit" form="cluster-edit-form" variant="primary" :disabled="!k8sClusterFormValid(editForm) || editBusy">저장</AppButton>
        </template>
      </AppModal>

      <AppModal v-model:open="deleteOpen" title="클러스터 삭제">
        <p class="text-sm"><strong>{{ cluster.name }}</strong> 클러스터를 삭제합니다.</p>
        <p class="note note-warn mt-3">워크로드 자산과 수집 내용이 함께 삭제됩니다. 되돌릴 수 없습니다.</p>
        <p v-if="deleteError" class="note note-danger mt-3" role="alert">{{ deleteError }}</p>
        <template #footer>
          <AppButton @click="deleteOpen = false">취소</AppButton>
          <AppButton variant="danger" :disabled="deleteBusy" @click="remove">삭제</AppButton>
        </template>
      </AppModal>
    </template>

    <template v-else>
      <PageHeader title="클러스터" :back="{ to: '/kubernetes', label: 'Kubernetes' }" />
      <Panel>
        <LoadError v-if="error" :error="error" :back="{ to: '/kubernetes', label: '클러스터 목록' }" @retry="refresh" />
        <LoadingText v-else />
      </Panel>
    </template>
  </div>
</template>
