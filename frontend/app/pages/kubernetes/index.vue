<script setup lang="ts">
import type { K8sCluster } from '~/types'
import type { TableColumn } from '~/types/table'
import { clusters, getAgent, workloadsOfCluster } from '~/mock'

useHead({ title: 'Kubernetes · bomcensus' })

const workloadsIn = (c: K8sCluster) => workloadsOfCluster(c.id)
const excludedIn = (c: K8sCluster) => workloadsIn(c).filter((w) => w.excluded).length
const scannerName = (c: K8sCluster) => getAgent(c.scannerId)?.hostname

const columns: TableColumn<K8sCluster>[] = [
  { key: 'name', label: '이름', sortValue: (c) => c.name },
  { key: 'version', label: '버전', sortValue: (c) => c.version, hideBelow: 'sm' },
  { key: 'connection', label: '연결 방식', sortValue: (c) => c.connection, hideBelow: 'md' },
  { key: 'exec', label: 'exec 수집', sortValue: (c) => Number(c.execEnabled) },
  { key: 'scanner', label: 'Scanner', sortValue: (c) => scannerName(c) ?? '', hideBelow: 'lg' },
  { key: 'workloads', label: '워크로드', align: 'right', sortValue: (c) => workloadsIn(c).length },
  { key: 'excluded', label: '제외', align: 'right', sortValue: (c) => excludedIn(c), hideBelow: 'sm' },
  { key: 'lastSync', label: '최근 동기화', align: 'right', sortValue: (c) => c.lastSync, hideBelow: 'sm' },
]
</script>

<template>
  <div>
    <PageHeader title="Kubernetes" />

    <Panel flush>
      <DataTable
        :columns="columns"
        :rows="clusters"
        :row-key="(c) => c.id"
        :row-to="(c) => `/kubernetes/${c.id}`"
      >
        <template #cell-name="{ row }">
          <NuxtLink :to="`/kubernetes/${row.id}`" class="font-medium hover:underline">{{ row.name }}</NuxtLink>
        </template>
        <template #cell-version="{ row }"><span class="mono whitespace-nowrap">{{ row.version }}</span></template>
        <template #cell-connection="{ row }">{{ row.connection === 'in_cluster' ? 'in-cluster' : 'kubeconfig' }}</template>
        <template #cell-exec="{ row }">
          <StatusBadge :tone="row.execEnabled ? 'ok' : 'neutral'" :label="row.execEnabled ? '사용' : '미사용'" />
        </template>
        <template #cell-scanner="{ row }">
          <span v-if="scannerName(row)" class="mono">{{ scannerName(row) }}</span>
          <span v-else class="text-ink-3">—</span>
        </template>
        <template #cell-workloads="{ row }"><span class="mono whitespace-nowrap">{{ workloadsIn(row).length }}</span></template>
        <template #cell-excluded="{ row }"><span class="mono whitespace-nowrap">{{ excludedIn(row) }}</span></template>
        <template #cell-lastSync="{ row }"><TimeAgo :at="row.lastSync" class="text-ink-2" /></template>
      </DataTable>
    </Panel>
  </div>
</template>
