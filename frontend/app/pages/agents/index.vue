<script setup lang="ts">
import type { Agent, AgentStatus, ConnMode, TlsMode } from '~/types'
import type { TableColumn } from '~/types/table'
import { agents as mockAgents } from '~/mock'

useHead({ title: '에이전트 · bomcensus' })

// 승인은 이 페이지의 복사본에만 반영된다
const agents = ref<Agent[]>(mockAgents.map((a) => ({ ...a })))

const tab = ref('agent')
const q = ref('')
const status = ref('')
const conn = ref('')
const tls = ref('')

const tabs = computed(() => [
  { key: 'agent', label: '에이전트', count: agents.value.filter((a) => a.kind === 'agent').length },
  { key: 'scanner', label: 'Scanner', count: agents.value.filter((a) => a.kind === 'scanner').length },
])

const ofTab = computed(() => agents.value.filter((a) => a.kind === tab.value))
const pending = computed(() => ofTab.value.filter((a) => a.status === 'pending_approval'))

const rows = computed(() => {
  const needle = q.value.trim().toLowerCase()
  return ofTab.value.filter((a) => {
    if (status.value && a.status !== status.value) return false
    if (conn.value && a.connMode !== conn.value) return false
    if (tls.value && a.tlsMode !== tls.value) return false
    if (!needle) return true
    return [a.hostname, a.address, a.id, a.os, a.listenAddress].some((v) => v?.toLowerCase().includes(needle))
  })
})

const columns: TableColumn<Agent>[] = [
  { key: 'hostname', label: '호스트명', sortValue: (a) => a.hostname },
  { key: 'status', label: '상태', sortValue: (a) => a.status },
  { key: 'version', label: '버전', sortValue: (a) => a.version, hideBelow: 'sm' },
  { key: 'conn', label: '연결', sortValue: (a) => a.connMode, hideBelow: 'md' },
  { key: 'tls', label: 'TLS 모드', sortValue: (a) => a.tlsMode, hideBelow: 'md' },
  { key: 'privilege', label: '권한', sortValue: (a) => a.privilege, hideBelow: 'lg' },
  { key: 'address', label: '주소', sortValue: (a) => a.address, hideBelow: 'lg' },
  { key: 'lastSeen', label: '최근 접속', align: 'right', sortValue: (a) => a.lastSeen, hideBelow: 'sm' },
]

const statusOptions = (Object.keys(agentStatusLabel) as AgentStatus[]).map((value) => ({ value, label: agentStatusLabel[value] }))
const connOptions = (Object.keys(connModeLabel) as ConnMode[]).map((value) => ({ value, label: connModeLabel[value] }))
const tlsOptions = (Object.keys(tlsModeLabel) as TlsMode[]).map((value) => ({ value, label: tlsModeLabel[value] }))
</script>

<template>
  <div>
    <PageHeader title="에이전트" />

    <AppTabs v-model="tab" :tabs="tabs" class="mb-3" />

    <button
      v-if="pending.length"
      type="button"
      class="mb-3 inline-flex h-7 items-center gap-1.5 whitespace-nowrap rounded-md border border-line-strong bg-surface px-2 text-xs font-medium hover:bg-surface-2"
      @click="status = 'pending_approval'"
    >
      승인 대기 <span class="mono">{{ pending.length }}</span>
    </button>

    <FilterBar :count="rows.length" :total="ofTab.length" unit="개">
      <SearchInput v-model="q" placeholder="호스트명, 주소, ID" />
      <SelectFilter v-model="status" label="상태" :options="statusOptions" />
      <SelectFilter v-model="conn" label="연결 모드" :options="connOptions" />
      <SelectFilter v-model="tls" label="TLS 모드" :options="tlsOptions" />
    </FilterBar>

    <Panel flush>
      <DataTable
        :columns="columns"
        :rows="rows"
        :row-key="(a) => a.id"
        :row-to="(a) => `/agents/${a.id}`"
        :initial-sort="{ key: 'hostname', dir: 'asc' }"
      >
        <template #cell-hostname="{ row }">
          <NuxtLink :to="`/agents/${row.id}`" class="font-medium hover:underline">{{ row.hostname }}</NuxtLink>
          <div class="mono whitespace-nowrap text-xs text-ink-3">{{ row.id }}</div>
        </template>
        <template #cell-status="{ row }">
          <StatusBadge dot :tone="agentStatusTone[row.status]" :label="agentStatusLabel[row.status]" />
        </template>
        <template #cell-version="{ row }">
          <span class="mono whitespace-nowrap">{{ row.version }}</span>
          <div v-if="row.updateState !== 'up_to_date'" class="mt-0.5">
            <StatusBadge :tone="updateStateTone[row.updateState]" :label="`업데이트 ${updateStateLabel[row.updateState]}`" />
          </div>
        </template>
        <template #cell-conn="{ row }">
          {{ connModeLabel[row.connMode] }}
          <div v-if="row.connMode === 'listen' && row.listenAddress" class="mono whitespace-nowrap text-xs text-ink-3">{{ row.listenAddress }}</div>
        </template>
        <template #cell-tls="{ row }">
          <StatusBadge :tone="tlsModeTone[row.tlsMode]" :label="tlsModeLabel[row.tlsMode]" />
          <div v-if="row.tlsInterceptedBy" class="mt-0.5 text-xs text-ink-3">중간에서 풀림: {{ row.tlsInterceptedBy }}</div>
        </template>
        <template #cell-privilege="{ row }">{{ privilegeLabel[row.privilege] }}</template>
        <template #cell-address="{ row }"><span class="mono whitespace-nowrap">{{ row.address }}</span></template>
        <template #cell-lastSeen="{ row }"><TimeAgo :at="row.lastSeen" class="whitespace-nowrap text-ink-2" /></template>
      </DataTable>
    </Panel>
  </div>
</template>
