<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import { Plus } from '@lucide/vue'
import type { K8sCluster } from '~/types'
import type { TableColumn } from '~/types/table'
import { createK8sCluster, fetchAll, listAgents, listCredentials, listK8sClusters, toApiError, type QueryOf } from '~/api'

useHead({ title: 'Kubernetes · bomcensus' })

const { items: clusters, total, pending, error, refresh, q, sort, page, size } = useServerList(
  'k8s-clusters',
  (p) => listK8sClusters(p as QueryOf<typeof listK8sClusters>),
  { sort: 'name', url: true },
)
// Scanner hostnames; a failed agent lookup only leaves the column empty
const { data: agents } = useLoad('k8s-clusters:agents', () => fetchAll((page) => listAgents(page)), () => [])

const scannerOf = (c: K8sCluster) => agents.value.find((a) => a.id === c.scannerId)
const scannerName = (c: K8sCluster) => scannerOf(c)?.hostname

const columns: TableColumn<K8sCluster>[] = [
  { key: 'name', label: '이름', sort: 'name' },
  { key: 'version', label: '버전', sort: 'version', hideBelow: 'sm' },
  { key: 'connection', label: '연결 방식', sort: 'connection', hideBelow: 'md' },
  { key: 'exec', label: 'exec 수집', sort: 'execEnabled' },
  { key: 'scanner', label: 'Scanner', hideBelow: 'lg' },
  { key: 'workloads', label: '워크로드', align: 'right', sort: 'workloadCount', sortDesc: true },
  { key: 'excluded', label: '제외', align: 'right', hideBelow: 'sm' },
  { key: 'syncStatus', label: '동기화' },
  { key: 'lastSync', label: '최근 동기화', align: 'right', sort: 'lastSync', sortDesc: true, hideBelow: 'sm' },
]

// ── Create ────────────────────────────────────────────

const { data: credentials } = useLoad('credentials', () => fetchAll((page) => listCredentials(page)), () => [])

const createOpen = ref(false)
const createForm = ref(k8sClusterForm())
const createBusy = ref(false)
const createError = ref('')

function openCreate() {
  createForm.value = k8sClusterForm()
  createError.value = ''
  createOpen.value = true
}

async function create() {
  if (!k8sClusterFormValid(createForm.value) || createBusy.value) return
  createBusy.value = true
  createError.value = ''
  try {
    await createK8sCluster(k8sClusterBody(createForm.value))
    createOpen.value = false
    await refresh()
  } catch (e) {
    const err = toApiError(e)
    createError.value = err.status === 409 ? '같은 이름의 클러스터가 있습니다' : err.message
  } finally {
    createBusy.value = false
  }
}
</script>

<template>
  <div>
    <PageHeader title="Kubernetes">
      <template #actions>
        <AppButton variant="primary" :icon="Plus" @click="openCreate">클러스터 추가</AppButton>
      </template>
    </PageHeader>

    <FilterBar :count="total" unit="개">
      <SearchInput v-model="q" placeholder="이름, 버전" />
    </FilterBar>

    <Panel flush>
      <LoadError v-if="error" :error="error" @retry="refresh" />
      <DataTable
        v-else
        v-model:sort="sort"
        v-model:page="page"
        v-model:size="size"
        :loading="pending"
        :columns="columns"
        :rows="clusters"
        :total="total"
        :row-key="(c) => c.id"
        :row-to="(c) => `/kubernetes/${c.id}`"
      >
        <template #cell-name="{ row }">
          <NuxtLink :to="`/kubernetes/${row.id}`" class="font-medium hover:underline">{{ row.name }}</NuxtLink>
        </template>
        <template #cell-version="{ row }"><span v-if="row.version" class="mono whitespace-nowrap">{{ row.version }}</span><span v-else class="text-ink-3">—</span></template>
        <template #cell-connection="{ row }">{{ row.connection === 'in_cluster' ? 'in-cluster' : 'kubeconfig' }}</template>
        <template #cell-exec="{ row }">
          <StatusBadge :tone="row.execEnabled ? 'ok' : 'neutral'" :label="row.execEnabled ? '사용' : '미사용'" />
        </template>
        <template #cell-scanner="{ row }">
          <template v-if="scannerName(row)">
            <span class="mono">{{ scannerName(row) }}</span>
            <div v-if="scannerOf(row)?.description" class="text-xs text-ink-3">{{ scannerOf(row)?.description }}</div>
          </template>
          <span v-else class="text-ink-3">—</span>
        </template>
        <template #cell-workloads="{ row }"><span class="mono whitespace-nowrap">{{ row.workloadCount }}</span></template>
        <template #cell-excluded="{ row }"><span class="mono whitespace-nowrap">{{ row.excludedCount }}</span></template>
        <template #cell-syncStatus="{ row }">
          <StatusBadge :tone="k8sSyncStatusTone[row.syncStatus]" :label="k8sSyncStatusLabel[row.syncStatus]" />
          <div v-if="row.syncStatus === 'failed' && row.syncMessage" class="mt-0.5 break-all text-xs text-ink-2">{{ row.syncMessage }}</div>
        </template>
        <template #cell-lastSync="{ row }"><TimeAgo :at="row.lastSync" class="text-ink-2" /></template>
      </DataTable>
    </Panel>

    <AppModal v-model:open="createOpen" title="클러스터 추가" wide>
      <form id="cluster-create-form" @submit.prevent="create">
        <K8sClusterFields v-model="createForm" :credentials="credentials" :agents="agents" />
        <p v-if="createError" class="note note-danger mt-3" role="alert">{{ createError }}</p>
      </form>
      <template #footer>
        <AppButton @click="createOpen = false">취소</AppButton>
        <AppButton type="submit" form="cluster-create-form" variant="primary" :disabled="!k8sClusterFormValid(createForm) || createBusy">추가</AppButton>
      </template>
    </AppModal>
  </div>
</template>
