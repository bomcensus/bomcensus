<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import { Plus } from '@lucide/vue'
import type { RegisterKey, RegisterKeyState } from '~/types'
import type { TableColumn } from '~/types/table'
import type { Tone } from '~/utils/labels'
import { createRegisterKey, fetchAll, listAssetGroups, listRegisterKeys, revokeRegisterKey, toApiError, type QueryOf } from '~/api'

useHead({ title: 'Register Key · bomcensus' })

const { items: keys, total, pending, error, refresh, q, filters, sort, page, size } = useServerList(
  'register-keys',
  (p) => listRegisterKeys(p as QueryOf<typeof listRegisterKeys>),
  { filters: { target: '', state: '' }, sort: 'state', url: true },
)
const { data: groups } = useLoad('asset-groups', () => fetchAll((page) => listAssetGroups(page)), () => [])

const stateLabel: Record<RegisterKeyState, string> = { valid: '유효', expired: '만료', revoked: '폐기', exhausted: '소진' }
const stateTone: Record<RegisterKeyState, Tone> = { valid: 'ok', expired: 'neutral', revoked: 'neutral', exhausted: 'warn' }

const columns: TableColumn<RegisterKey>[] = [
  { key: 'name', label: '이름', sort: 'name' },
  { key: 'keyId', label: 'key-id', hideBelow: 'md' },
  { key: 'target', label: '대상', sort: 'target', hideBelow: 'sm' },
  { key: 'state', label: '상태', sort: 'state' },
  { key: 'expires', label: '만료', sort: 'expiresAt', hideBelow: 'sm' },
  { key: 'cidrs', label: '허용 IP', hideBelow: 'lg' },
  { key: 'uses', label: '사용', sort: 'usedCount', sortDesc: true, hideBelow: 'md' },
  { key: 'approval', label: '승인 방식', sort: 'approval', hideBelow: 'md' },
  { key: 'relaxed', label: 'TLS 완화 허용', hideBelow: 'md' },
  { key: 'group', label: '기본 그룹', hideBelow: 'lg' },
  { key: 'actions', label: '', align: 'right' },
]

const targetLabel = { agent: 'Agent', scanner: 'Scanner' } as const
const approvalLabel = { auto: '자동', manual: '수동 승인' } as const
const targetOptions = Object.entries(targetLabel).map(([value, label]) => ({ value, label }))
const stateOptions = (Object.keys(stateLabel) as RegisterKeyState[]).map((value) => ({ value, label: stateLabel[value] }))

// ── Revoke ─────────────────────────────────────────────
const revokeTarget = ref<RegisterKey>()
const revokeOpen = computed({
  get: () => !!revokeTarget.value,
  set: (v) => {
    if (!v) revokeTarget.value = undefined
  },
})
const revokeBusy = ref(false)
const revokeError = ref('')

function askRevoke(k: RegisterKey) {
  revokeError.value = ''
  revokeTarget.value = k
}

async function revoke() {
  const t = revokeTarget.value
  if (!t || revokeBusy.value) return
  revokeBusy.value = true
  revokeError.value = ''
  try {
    await revokeRegisterKey(t.id)
    revokeTarget.value = undefined
    await refresh()
  } catch (e) {
    const err = toApiError(e)
    revokeError.value = err.status === 409 ? '이미 폐기된 키입니다' : err.message
  } finally {
    revokeBusy.value = false
  }
}

// ── Create ─────────────────────────────────────────────
const createOpen = ref(false)
const form = reactive({
  name: '',
  target: 'agent' as RegisterKey['target'],
  expiresAt: '',
  cidrs: '',
  maxUses: 1,
  approval: 'manual' as RegisterKey['approval'],
  allowRelaxedTls: false,
  group: '',
  tags: '',
})
const errors = reactive({ name: '', cidrs: '', maxUses: '' })
const createBusy = ref(false)
const createError = ref('')

const cidrRe = /^(\d{1,3}(\.\d{1,3}){3}\/\d{1,2}|[0-9a-fA-F:]+\/\d{1,3})$/

function openCreate() {
  Object.assign(form, { name: '', target: 'agent', expiresAt: '', cidrs: '', maxUses: 1, approval: 'manual', allowRelaxedTls: false, group: '', tags: '' })
  Object.assign(errors, { name: '', cidrs: '', maxUses: '' })
  createError.value = ''
  createOpen.value = true
}

const enrollment = ref('')
const resultOpen = ref(false)

async function create() {
  if (createBusy.value) return
  const cidrs = form.cidrs.split('\n').map((s) => s.trim()).filter(Boolean)
  errors.name = form.name.trim() ? '' : '이름을 입력합니다'
  const bad = cidrs.find((c) => !cidrRe.test(c))
  errors.cidrs = bad ? `CIDR 형식이 아닙니다: ${bad}` : ''
  errors.maxUses = Number.isInteger(form.maxUses) && form.maxUses >= 0 ? '' : '0 이상의 정수를 입력합니다'
  if (errors.name || errors.cidrs || errors.maxUses) return

  createBusy.value = true
  createError.value = ''
  try {
    const created = await createRegisterKey({
      name: form.name.trim(),
      target: form.target,
      expiresAt: form.expiresAt ? new Date(form.expiresAt).toISOString() : undefined,
      allowedCidrs: cidrs,
      maxUses: form.maxUses,
      approval: form.approval,
      allowRelaxedTls: form.allowRelaxedTls,
      defaultGroup: form.group.trim() || undefined,
      defaultTags: form.tags.split(',').map((s) => s.trim()).filter(Boolean),
    })
    enrollment.value = created.enrollment
    createOpen.value = false
    resultOpen.value = true
    await refresh()
  } catch (e) {
    createError.value = toApiError(e).message
  } finally {
    createBusy.value = false
  }
}

// On close, also clear the string from memory
watch(resultOpen, (open) => {
  if (!open) enrollment.value = ''
})

const meta = useMeta()
// agentAddress is host:port; without it the example keeps a placeholder.
const installExample = computed(
  () => `bomcensus-agent enroll --server https://${meta.value?.agentAddress ?? '<서버 주소>:8443'} ${enrollment.value}`,
)
</script>

<template>
  <div>
    <PageHeader title="Register Key">
      <template #actions>
        <AppButton variant="primary" :icon="Plus" @click="openCreate">Register Key 생성</AppButton>
      </template>
    </PageHeader>

    <FilterBar :count="total" unit="개">
      <SearchInput v-model="q" placeholder="이름, key-id" />
      <SelectFilter v-model="filters.target" label="대상" :options="targetOptions" />
      <SelectFilter v-model="filters.state" label="상태" :options="stateOptions" />
    </FilterBar>

    <Panel flush>
      <LoadError v-if="error" :error="error" @retry="refresh" />
      <DataTable
        v-else
        v-model:sort="sort"
        v-model:page="page"
        v-model:size="size"
        :columns="columns"
        :rows="keys"
        :total="total"
        :row-key="(k) => k.id"
        :loading="pending"
      >
        <template #cell-name="{ row }">
          <span class="whitespace-nowrap font-medium">{{ row.name }}</span>
          <div v-if="row.defaultTags.length" class="text-xs text-ink-3">{{ row.defaultTags.join(', ') }}</div>
        </template>
        <template #cell-keyId="{ row }"><span class="mono whitespace-nowrap text-xs">{{ row.id }}</span></template>
        <template #cell-target="{ row }">{{ targetLabel[row.target] }}</template>
        <template #cell-state="{ row }">
          <StatusBadge dot :tone="stateTone[row.state]" :label="stateLabel[row.state]" />
        </template>
        <template #cell-expires="{ row }">
          <template v-if="row.expiresAt">
            <span class="whitespace-nowrap">{{ formatDate(row.expiresAt) }}</span>
            <div class="whitespace-nowrap text-xs text-ink-3">{{ formatRelative(row.expiresAt) }}</div>
          </template>
          <span v-else class="text-ink-3">없음</span>
        </template>
        <template #cell-cidrs="{ row }">
          <div v-if="row.allowedCidrs.length" class="mono text-xs">
            <div v-for="c in row.allowedCidrs" :key="c" class="whitespace-nowrap">{{ c }}</div>
          </div>
          <span v-else class="text-ink-3">제한 없음</span>
        </template>
        <template #cell-uses="{ row }">
          <span class="mono whitespace-nowrap">{{ row.usedCount }}/{{ row.maxUses === 0 ? '무제한' : row.maxUses }}</span>
        </template>
        <template #cell-approval="{ row }">{{ approvalLabel[row.approval] }}</template>
        <template #cell-relaxed="{ row }">{{ row.allowRelaxedTls ? '허용' : '허용 안 함' }}</template>
        <template #cell-group="{ row }">{{ row.defaultGroup || '—' }}</template>
        <template #cell-actions="{ row }">
          <AppButton v-if="row.state !== 'revoked'" size="sm" variant="danger" @click="askRevoke(row)">폐기</AppButton>
        </template>
      </DataTable>
    </Panel>

    <AppModal v-model:open="createOpen" title="Register Key 생성" wide>
      <form id="key-form" class="grid grid-cols-1 gap-3 md:grid-cols-2" @submit.prevent="create">
        <FormField label="이름" :error="errors.name" class="md:col-span-2">
          <input v-model="form.name" class="input w-full" placeholder="예: 서울 IDC 웹 서버" />
        </FormField>
        <FormField label="대상">
          <select v-model="form.target" class="select w-full">
            <option value="agent">Agent</option>
            <option value="scanner">Scanner</option>
          </select>
        </FormField>
        <FormField label="만료 시각" hint="비우면 만료되지 않습니다">
          <input v-model="form.expiresAt" type="datetime-local" class="input w-full" />
        </FormField>
        <FormField label="허용 IP" hint="줄마다 CIDR 하나" :error="errors.cidrs" class="md:col-span-2">
          <textarea v-model="form.cidrs" rows="3" class="input mono w-full" placeholder="10.20.0.0/16" />
        </FormField>
        <FormField label="최대 사용 횟수" hint="0은 무제한입니다" :error="errors.maxUses">
          <input v-model.number="form.maxUses" type="number" min="0" step="1" class="input w-full" />
        </FormField>
        <FormField label="승인 방식">
          <select v-model="form.approval" class="select w-full">
            <option value="manual">수동 승인</option>
            <option value="auto">자동</option>
          </select>
        </FormField>
        <FormField label="기본 그룹">
          <input v-model="form.group" list="key-groups" class="input w-full" />
          <datalist id="key-groups"><option v-for="g in groups" :key="g.name" :value="g.name" /></datalist>
        </FormField>
        <FormField label="태그" hint="쉼표로 구분합니다">
          <input v-model="form.tags" class="input w-full" />
        </FormField>
        <label class="inline-flex items-center gap-1.5 text-sm md:col-span-2">
          <input v-model="form.allowRelaxedTls" type="checkbox" class="accent-(--accent)" /> TLS 완화 허용 (system, none 모드)
        </label>
        <p v-if="form.allowRelaxedTls" class="note note-warn md:col-span-2">
          완화 모드에서는 전송 중 보고 내용이 읽힐 수 있습니다. 인증과 무결성은 메시지 서명으로 유지됩니다.
        </p>
        <p v-if="createError" class="note note-danger md:col-span-2" role="alert">{{ createError }}</p>
      </form>
      <template #footer>
        <AppButton @click="createOpen = false">취소</AppButton>
        <AppButton type="submit" form="key-form" variant="primary" :disabled="createBusy">생성</AppButton>
      </template>
    </AppModal>

    <AppModal v-model:open="resultOpen" title="등록 문자열" wide>
      <div class="note note-warn mb-3">이 문자열은 다시 볼 수 없습니다. 서버는 secret을 보관하지 않습니다. 지금 복사해 두어야 합니다.</div>
      <CopyField :value="enrollment" label="등록 문자열" />
      <p class="mt-3 text-xs text-ink-3">형식: bc1.&lt;ca-hash&gt;.&lt;key-id&gt;.&lt;secret&gt;</p>
      <h3 class="mb-1 mt-4 text-sm font-semibold">설치 명령 (예시)</h3>
      <CopyField :value="installExample" label="설치 명령 예시" />
      <template #footer>
        <AppButton variant="primary" @click="resultOpen = false">닫기</AppButton>
      </template>
    </AppModal>

    <AppModal v-model:open="revokeOpen" title="Register Key 폐기">
      <p class="text-sm">
        <strong>{{ revokeTarget?.name }}</strong> 키를 폐기합니다. 이후 이 키로는 등록할 수 없습니다. 이미 등록된 에이전트는 영향을 받지 않습니다.
      </p>
      <p v-if="revokeError" class="note note-danger mt-3" role="alert">{{ revokeError }}</p>
      <template #footer>
        <AppButton @click="revokeOpen = false">취소</AppButton>
        <AppButton variant="danger" :disabled="revokeBusy" @click="revoke">폐기</AppButton>
      </template>
    </AppModal>
  </div>
</template>
