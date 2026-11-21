<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import { Plus } from '@lucide/vue'
import type { Agent, AgentStatus, ConnMode, ListenTarget, ListenTargetState, TlsMode } from '~/types'
import type { TableColumn } from '~/types/table'
import type { Tone } from '~/utils/labels'
import {
  createListenTarget,
  deleteListenTarget,
  fetchAll,
  listAgents,
  listListenTargets,
  listRegisterKeys,
  toApiError,
  updateListenTarget,
} from '~/api'

useHead({ title: '에이전트 · bomcensus' })

const { data: agents, pending, error, refresh } = useLoad('agents', () => fetchAll((page) => listAgents(page)), () => [])
const {
  data: targets,
  pending: targetsPending,
  error: targetsError,
  refresh: refreshTargets,
} = useLoad('listen-targets', () => fetchAll((page) => listListenTargets(page)), () => [])
const { data: registerKeys } = useLoad('register-keys', () => fetchAll((page) => listRegisterKeys(page)), () => [])

const tab = ref('agent')
const q = ref('')
const status = ref('')
const conn = ref('')
const tls = ref('')

// Counts are left out until the list has loaded
const countOf = (loading: boolean, n: number) => (loading ? undefined : n)
const tabs = computed(() => [
  { key: 'agent', label: '에이전트', count: countOf(pending.value, agents.value.filter((a) => a.kind === 'agent').length) },
  { key: 'scanner', label: 'Scanner', count: countOf(pending.value, agents.value.filter((a) => a.kind === 'scanner').length) },
  { key: 'listen', label: 'listen 대상', count: countOf(targetsPending.value, targets.value.length) },
])

const ofTab = computed(() => agents.value.filter((a) => a.kind === tab.value))
const pendingApproval = computed(() => ofTab.value.filter((a) => a.status === 'pending_approval'))

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

// ── Listen targets ────────────────────────────────────

const targetStateLabel: Record<ListenTargetState, string> = {
  connecting: '연결 중',
  connected: '온라인',
  disconnected: '오프라인',
  failed: '실패',
}
const targetStateTone: Record<ListenTargetState, Tone> = {
  connecting: 'info',
  connected: 'ok',
  disconnected: 'warn',
  failed: 'danger',
}

const agentById = computed(() => new Map(agents.value.map((a) => [a.id, a])))
const keyById = computed(() => new Map(registerKeys.value.map((k) => [k.id, k])))

const targetColumns: TableColumn<ListenTarget>[] = [
  { key: 'address', label: '주소', sortValue: (t) => t.address },
  { key: 'agent', label: 'Agent', sortValue: (t) => (t.agentId ? agentById.value.get(t.agentId)?.hostname ?? t.agentId : undefined) },
  { key: 'state', label: '상태', sortValue: (t) => t.state },
  { key: 'lastError', label: '최근 오류', hideBelow: 'md' },
  { key: 'lastConnectedAt', label: '최근 접속', align: 'right', sortValue: (t) => t.lastConnectedAt, hideBelow: 'sm' },
  { key: 'actions', label: '', align: 'right' },
]

// Only agent keys that can still enroll are offered.
// The key already set on the edited target stays selectable.
const keyOptions = computed(() =>
  registerKeys.value.filter((k) => k.target === 'agent' && (k.state === 'valid' || k.id === editing.value?.registerKeyId)),
)

// Set while the form edits an existing target; unset when it adds one.
const editing = ref<ListenTarget>()

const addOpen = ref(false)
const addForm = reactive({ address: '', registerKeyId: '' })
const addBusy = ref(false)
const addError = ref('')
// host:port, where host may be a bracketed IPv6 address
const hostPortRe = /^(\[[0-9a-fA-F:.]+\]|[^\s:[\]]+):(\d{1,5})$/
const addressError = computed(() => {
  const v = addForm.address.trim()
  if (!v || hostPortRe.test(v)) return ''
  return 'host:port 형식이 아닙니다'
})
const addValid = computed(() => !!addForm.address.trim() && !addressError.value)

function openAdd() {
  editing.value = undefined
  Object.assign(addForm, { address: '', registerKeyId: '' })
  addError.value = ''
  addOpen.value = true
}

function openEdit(t: ListenTarget) {
  editing.value = t
  Object.assign(addForm, { address: t.address, registerKeyId: t.registerKeyId ?? '' })
  addError.value = ''
  addOpen.value = true
}

async function addTarget() {
  if (!addValid.value || addBusy.value) return
  addBusy.value = true
  addError.value = ''
  try {
    if (editing.value) {
      await updateListenTarget(editing.value.id, { address: addForm.address.trim(), registerKeyId: addForm.registerKeyId || null })
    } else {
      await createListenTarget({ address: addForm.address.trim(), registerKeyId: addForm.registerKeyId || undefined })
    }
    addOpen.value = false
    await refreshTargets()
  } catch (e) {
    const err = toApiError(e)
    addError.value = err.status === 409 ? '이미 등록된 주소입니다' : err.message
  } finally {
    addBusy.value = false
  }
}

const deleteTarget = ref<ListenTarget>()
const deleteOpen = computed({
  get: () => !!deleteTarget.value,
  set: (v) => {
    if (!v) deleteTarget.value = undefined
  },
})
const deleteBusy = ref(false)
const deleteError = ref('')

function askDelete(t: ListenTarget) {
  deleteError.value = ''
  deleteTarget.value = t
}

async function removeTarget() {
  const t = deleteTarget.value
  if (!t || deleteBusy.value) return
  deleteBusy.value = true
  deleteError.value = ''
  try {
    await deleteListenTarget(t.id)
    deleteTarget.value = undefined
    await refreshTargets()
  } catch (e) {
    deleteError.value = toApiError(e).message
  } finally {
    deleteBusy.value = false
  }
}
</script>

<template>
  <div>
    <PageHeader title="에이전트">
      <template v-if="tab === 'listen'" #actions>
        <AppButton variant="primary" :icon="Plus" @click="openAdd">대상 추가</AppButton>
      </template>
    </PageHeader>

    <AppTabs v-model="tab" :tabs="tabs" query-key="tab" class="mb-3" />

    <template v-if="tab === 'listen'">
      <Panel flush>
        <LoadError v-if="targetsError" :error="targetsError" @retry="refreshTargets" />
        <DataTable
          v-else
          :columns="targetColumns"
          :rows="targets"
          :row-key="(t) => t.id"
          :initial-sort="{ key: 'address', dir: 'asc' }"
          :loading="targetsPending"
        >
          <template #cell-address="{ row }">
            <span class="mono whitespace-nowrap font-medium">{{ row.address }}</span>
            <div v-if="row.registerKeyId" class="text-xs text-ink-3">
              Register Key {{ keyById.get(row.registerKeyId)?.name ?? row.registerKeyId }}
            </div>
          </template>
          <template #cell-agent="{ row }">
            <template v-if="row.agentId">
              <NuxtLink :to="`/agents/${row.agentId}`" class="link">{{ agentById.get(row.agentId)?.hostname ?? row.agentId }}</NuxtLink>
            </template>
            <span v-else class="text-ink-3">—</span>
          </template>
          <template #cell-state="{ row }">
            <StatusBadge dot :tone="targetStateTone[row.state]" :label="targetStateLabel[row.state]" />
          </template>
          <template #cell-lastError="{ row }">
            <Diagnostic v-if="row.lastError" :text="row.lastError" />
            <span v-else class="text-ink-3">—</span>
          </template>
          <template #cell-lastConnectedAt="{ row }">
            <TimeAgo v-if="row.lastConnectedAt" :at="row.lastConnectedAt" class="whitespace-nowrap text-ink-2" />
            <span v-else class="text-ink-3">—</span>
          </template>
          <template #cell-actions="{ row }">
            <span class="inline-flex items-center gap-1.5">
              <AppButton size="sm" @click="openEdit(row)">편집</AppButton>
              <AppButton size="sm" variant="danger" @click="askDelete(row)">삭제</AppButton>
            </span>
          </template>
        </DataTable>
      </Panel>
    </template>

    <template v-else>
      <button
        v-if="pendingApproval.length"
        type="button"
        class="mb-3 inline-flex h-7 items-center gap-1.5 whitespace-nowrap rounded-md border border-line-strong bg-surface px-2 text-xs font-medium hover:bg-surface-2"
        @click="status = 'pending_approval'"
      >
        승인 대기 <span class="mono">{{ pendingApproval.length }}</span>
      </button>

      <FilterBar :count="rows.length" :total="ofTab.length" unit="개">
        <SearchInput v-model="q" placeholder="호스트명, 주소, ID" />
        <SelectFilter v-model="status" label="상태" :options="statusOptions" />
        <SelectFilter v-model="conn" label="연결 모드" :options="connOptions" />
        <SelectFilter v-model="tls" label="TLS 모드" :options="tlsOptions" />
      </FilterBar>

      <Panel flush>
        <LoadError v-if="error" :error="error" @retry="refresh" />
        <DataTable
          v-else
          :columns="columns"
          :rows="rows"
          :row-key="(a) => a.id"
          :row-to="(a) => `/agents/${a.id}`"
          :initial-sort="{ key: 'hostname', dir: 'asc' }"
          :loading="pending"
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
    </template>

    <AppModal v-model:open="addOpen" :title="editing ? '대상 편집' : '대상 추가'">
      <form id="listen-target-form" class="grid grid-cols-1 gap-3" @submit.prevent="addTarget">
        <FormField label="주소" hint="host:port" :error="addressError">
          <input v-model="addForm.address" class="input mono w-full" placeholder="10.0.0.5:9443" />
        </FormField>
        <FormField label="Register Key">
          <select v-model="addForm.registerKeyId" class="select w-full">
            <option value="">제한 없음</option>
            <option v-for="k in keyOptions" :key="k.id" :value="k.id">{{ k.name }} ({{ k.id }})</option>
          </select>
        </FormField>
        <p v-if="addError" class="note note-danger" role="alert">{{ addError }}</p>
      </form>
      <template #footer>
        <AppButton @click="addOpen = false">취소</AppButton>
        <AppButton type="submit" form="listen-target-form" variant="primary" :disabled="!addValid || addBusy">{{ editing ? '저장' : '추가' }}</AppButton>
      </template>
    </AppModal>

    <AppModal v-model:open="deleteOpen" title="listen 대상 삭제">
      <p class="text-sm">
        <span class="mono font-medium">{{ deleteTarget?.address }}</span>에 더 이상 접속하지 않습니다.
      </p>
      <p v-if="deleteTarget?.agentId" class="note note-warn mt-3">
        연결된 Agent는 폐기되지 않고, 같은 주소를 다시 추가할 때까지 오프라인으로 남습니다.
      </p>
      <p v-if="deleteError" class="note note-danger mt-3" role="alert">{{ deleteError }}</p>
      <template #footer>
        <AppButton @click="deleteOpen = false">취소</AppButton>
        <AppButton variant="danger" :disabled="deleteBusy" @click="removeTarget">삭제</AppButton>
      </template>
    </AppModal>
  </div>
</template>
