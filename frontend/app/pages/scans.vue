<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import { Plus, Play } from '@lucide/vue'
import type { Credential, CredentialKind, IntegrityMode, ScanResult, ScanTarget } from '~/types'
import type { TableColumn } from '~/types/table'
import type { Tone } from '~/utils/labels'
import {
  createCredential,
  createScanTarget,
  deleteCredential,
  deleteScanTarget,
  fetchAll,
  listAgents,
  listCredentials,
  listDetectDirs,
  listScanTargets,
  rotateCredentialSecret,
  runScanTarget,
  toApiError,
  updateScanTarget,
} from '~/api'

useHead({ title: 'Agentless 수집 · bomcensus' })

const {
  data: targets,
  pending: targetsPending,
  error: targetsError,
  refresh: refreshTargets,
} = useLoad('scan-targets', () => fetchAll((page) => listScanTargets(page)), () => [])
const {
  data: credentials,
  pending: credentialsPending,
  error: credentialsError,
  refresh: refreshCredentials,
} = useLoad('credentials', () => fetchAll((page) => listCredentials(page)), () => [])
const { data: agents } = useLoad('agents', () => fetchAll((page) => listAgents(page)), () => [])
const { data: detectDirs, refresh: refreshDetectDirs } = useLoad('detect-dirs', async () => (await listDetectDirs()).items, () => [])

const tab = ref('targets')

const countOf = (loading: boolean, n: number) => (loading ? undefined : n)
const tabs = computed(() => [
  { key: 'targets', label: '대상', count: countOf(targetsPending.value, targets.value.length) },
  { key: 'credentials', label: '자격증명', count: countOf(credentialsPending.value, credentials.value.length) },
])

const credentialKindLabel: Record<CredentialKind, string> = {
  ssh_key: 'SSH 키',
  ssh_password: 'SSH 비밀번호',
  kubeconfig: 'kubeconfig',
}
const protocolLabel: Record<ScanTarget['protocol'], string> = { ssh: 'SSH' }
const resultLabel: Record<ScanResult, string> = { ok: '성공', partial: '부분', failed: '실패' }
const resultTone: Record<ScanResult, Tone> = { ok: 'ok', partial: 'warn', failed: 'danger' }

const credentialById = computed(() => new Map(credentials.value.map((c) => [c.id, c])))
const agentById = computed(() => new Map(agents.value.map((a) => [a.id, a])))
const credentialName = (t: ScanTarget) => credentialById.value.get(t.credentialId)?.name ?? t.credentialId
// Absent scannerId means the server's embedded scanner.
const scannerName = (t: ScanTarget) => (t.scannerId ? agentById.value.get(t.scannerId)?.hostname ?? t.scannerId : '내장 Scanner')
const detectDirById = computed(() => new Map(detectDirs.value.map((d) => [d.id, d])))
const detectPaths = (t: ScanTarget) => t.detectDirIds.map((id) => detectDirById.value.get(id)?.path ?? id)

const intervalPresets = [
  { minutes: 0, label: '수동' },
  { minutes: 60, label: '1시간' },
  { minutes: 360, label: '6시간' },
  { minutes: 1440, label: '24시간' },
]
function intervalLabel(minutes: number): string {
  if (minutes === 0) return '수동'
  if (minutes % 60 === 0) return `${minutes / 60}시간`
  return `${minutes}분`
}

// Keeps the algorithm prefix ("SHA256:") and the first 12 characters.
function shortFingerprint(fp: string): string {
  const i = fp.indexOf(':')
  const head = i >= 0 ? fp.slice(0, i + 1) : ''
  const body = fp.slice(head.length)
  return body.length > 12 ? `${head}${body.slice(0, 12)}…` : fp
}

const targetColumns: TableColumn<ScanTarget>[] = [
  { key: 'name', label: '이름', sortValue: (t) => t.name },
  { key: 'protocol', label: '프로토콜', sortValue: (t) => t.protocol, hideBelow: 'sm' },
  { key: 'address', label: '주소', sortValue: (t) => t.address },
  { key: 'credential', label: '자격증명', sortValue: credentialName, hideBelow: 'lg' },
  { key: 'scanner', label: 'Scanner', sortValue: scannerName, hideBelow: 'lg' },
  { key: 'sudo', label: 'sudo', hideBelow: 'md' },
  { key: 'hostKey', label: 'host key', hideBelow: 'md' },
  { key: 'schedule', label: '일정', sortValue: (t) => t.intervalMinutes, hideBelow: 'md' },
  { key: 'detectDirs', label: '감지 대상 디렉터리', sortValue: (t) => t.detectDirIds.length, hideBelow: 'lg' },
  { key: 'integrity', label: '파일 무결성', sortValue: (t) => (t.integrityEnabled ? 1 : 0), hideBelow: 'lg' },
  { key: 'lastRun', label: '최근 결과', sortValue: (t) => t.lastRun?.at ?? '' },
  { key: 'actions', label: '', align: 'right' },
]

const credentialColumns: TableColumn<Credential>[] = [
  { key: 'name', label: '이름', sortValue: (c) => c.name },
  { key: 'kind', label: '종류', sortValue: (c) => c.kind },
  { key: 'username', label: '사용자', sortValue: (c) => c.username ?? '', hideBelow: 'sm' },
  { key: 'fingerprint', label: '공개 키 fingerprint', sortValue: (c) => c.publicKeyFingerprint ?? '', hideBelow: 'md' },
  { key: 'usedBy', label: '사용 대상', align: 'right', sortValue: (c) => c.usedBy },
  { key: 'createdAt', label: '생성일', sortValue: (c) => c.createdAt, hideBelow: 'sm' },
  { key: 'actions', label: '', align: 'right' },
]

// ── Run ───────────────────────────────────────────────

// Targets for which collection was requested from this screen
const requested = ref<Set<string>>(new Set())
const running = ref<string>()
const targetActionError = ref('')

async function runNow(t: ScanTarget) {
  if (running.value) return
  running.value = t.id
  targetActionError.value = ''
  try {
    await runScanTarget(t.id)
    requested.value = new Set(requested.value).add(t.id)
    await refreshTargets()
  } catch (e) {
    const err = toApiError(e)
    targetActionError.value = err.status === 409 ? `${t.name}: 수집할 수 없는 상태입니다: ${err.message}` : `${t.name}: ${err.message}`
  } finally {
    running.value = undefined
  }
}

// ── Add target ────────────────────────────────────────

const targetOpen = ref(false)
const emptyTarget = () => ({
  name: '',
  address: '',
  port: 22,
  credentialId: '',
  scannerId: '',
  sudo: false,
  hostKeyMode: 'tofu' as 'pinned' | 'tofu',
  hostKey: '',
  intervalMinutes: 0,
  resetHostKey: false,
  detectDirIds: [] as string[],
  integrity: 'inherit' as IntegrityMode,
})
const targetForm = reactive(emptyTarget())
// Set while the form edits an existing target; unset when it adds one.
const editingTarget = ref<ScanTarget>()
const targetBusy = ref(false)
const targetError = ref('')
const scannerOptions = computed(() => agents.value.filter((a) => a.kind === 'scanner' && a.status !== 'revoked'))
const sshCredentials = computed(() => credentials.value.filter((c) => c.kind === 'ssh_key' || c.kind === 'ssh_password'))
const portValid = computed(() => Number.isInteger(targetForm.port) && targetForm.port >= 1 && targetForm.port <= 65535)
const intervalValid = computed(() => Number.isInteger(targetForm.intervalMinutes) && targetForm.intervalMinutes >= 0)
const targetValid = computed(
  () =>
    !!targetForm.name.trim() &&
    !!targetForm.address.trim() &&
    !!targetForm.credentialId &&
    portValid.value &&
    intervalValid.value &&
    (!!editingTarget.value || targetForm.hostKeyMode === 'tofu' || !!targetForm.hostKey.trim()),
)

function openTarget() {
  editingTarget.value = undefined
  Object.assign(targetForm, emptyTarget())
  targetError.value = ''
  targetOpen.value = true
}

function openEditTarget(t: ScanTarget) {
  editingTarget.value = t
  Object.assign(targetForm, emptyTarget(), {
    name: t.name,
    address: t.address,
    port: t.port,
    credentialId: t.credentialId,
    scannerId: t.scannerId ?? '',
    sudo: t.sudo,
    intervalMinutes: t.intervalMinutes,
    detectDirIds: [...t.detectDirIds],
    integrity: t.integrity,
  })
  targetError.value = ''
  targetOpen.value = true
}

async function addTarget() {
  if (!targetValid.value || targetBusy.value) return
  targetBusy.value = true
  targetError.value = ''
  try {
    const editing = editingTarget.value
    if (editing) {
      await updateScanTarget(editing.id, {
        name: targetForm.name.trim(),
        port: targetForm.port,
        credentialId: targetForm.credentialId,
        scannerId: targetForm.scannerId || null,
        sudo: targetForm.sudo,
        intervalMinutes: targetForm.intervalMinutes,
        resetHostKey: editing.hostKeyPinned && targetForm.resetHostKey ? true : undefined,
        detectDirIds: targetForm.detectDirIds,
        integrity: targetForm.integrity,
      })
    } else {
      await createScanTarget({
        name: targetForm.name.trim(),
        protocol: 'ssh',
        address: targetForm.address.trim(),
        port: targetForm.port,
        credentialId: targetForm.credentialId,
        scannerId: targetForm.scannerId || undefined,
        sudo: targetForm.sudo,
        hostKey: targetForm.hostKeyMode === 'pinned' ? targetForm.hostKey.trim() : undefined,
        intervalMinutes: targetForm.intervalMinutes,
        detectDirIds: targetForm.detectDirIds,
        integrity: targetForm.integrity,
      })
    }
    targetOpen.value = false
    await Promise.all([refreshTargets(), refreshCredentials(), refreshDetectDirs()])
  } catch (e) {
    const err = toApiError(e)
    targetError.value = err.status === 409 ? '같은 이름이나 주소의 대상이 있습니다' : err.message
  } finally {
    targetBusy.value = false
  }
}

// ── Delete target ─────────────────────────────────────

const deleteTargetRow = ref<ScanTarget>()
const deleteTargetOpen = computed({
  get: () => !!deleteTargetRow.value,
  set: (v) => {
    if (!v) deleteTargetRow.value = undefined
  },
})
const deleteTargetBusy = ref(false)
const deleteTargetError = ref('')

function askDeleteTarget(t: ScanTarget) {
  deleteTargetError.value = ''
  deleteTargetRow.value = t
}

async function removeTarget() {
  const t = deleteTargetRow.value
  if (!t || deleteTargetBusy.value) return
  deleteTargetBusy.value = true
  deleteTargetError.value = ''
  try {
    await deleteScanTarget(t.id)
    deleteTargetRow.value = undefined
    await Promise.all([refreshTargets(), refreshCredentials()])
  } catch (e) {
    deleteTargetError.value = toApiError(e).message
  } finally {
    deleteTargetBusy.value = false
  }
}

// ── Add credential ────────────────────────────────────

const credOpen = ref(false)
// Secrets live only in this form and are cleared when the modal closes.
const emptyCred = () => ({
  name: '',
  kind: 'ssh_key' as CredentialKind,
  username: '',
  privateKey: '',
  passphrase: '',
  password: '',
  kubeconfig: '',
})
const credForm = reactive(emptyCred())
// Set while the form replaces the secret of an existing credential; unset when it adds one.
const rotatingCred = ref<Credential>()
const credBusy = ref(false)
const credError = ref('')
const credValid = computed(() => {
  if (!credForm.name.trim()) return false
  switch (credForm.kind) {
    case 'ssh_key':
      return !!credForm.username.trim() && !!credForm.privateKey.trim()
    case 'ssh_password':
      return !!credForm.username.trim() && !!credForm.password
    case 'kubeconfig':
      return !!credForm.kubeconfig.trim()
  }
  return false
})

watch(credOpen, (open) => {
  if (!open) Object.assign(credForm, emptyCred())
})

function openCred() {
  rotatingCred.value = undefined
  Object.assign(credForm, emptyCred())
  credError.value = ''
  credOpen.value = true
}

function openRotate(c: Credential) {
  rotatingCred.value = c
  Object.assign(credForm, emptyCred(), { name: c.name, kind: c.kind, username: c.username ?? '' })
  credError.value = ''
  credOpen.value = true
}

async function readFileInto(e: Event, field: 'privateKey' | 'kubeconfig') {
  const input = e.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  try {
    credForm[field] = await file.text()
  } catch (err) {
    credError.value = toApiError(err).message
  }
  input.value = ''
}

async function addCred() {
  if (!credValid.value || credBusy.value) return
  credBusy.value = true
  credError.value = ''
  const f = credForm
  const secret = {
    ...(f.kind === 'ssh_key' && { username: f.username.trim(), privateKey: f.privateKey, passphrase: f.passphrase || undefined }),
    ...(f.kind === 'ssh_password' && { username: f.username.trim(), password: f.password }),
    ...(f.kind === 'kubeconfig' && { kubeconfig: f.kubeconfig }),
  }
  try {
    if (rotatingCred.value) await rotateCredentialSecret(rotatingCred.value.id, secret)
    else await createCredential({ name: f.name.trim(), kind: f.kind, ...secret })
    credOpen.value = false
    await refreshCredentials()
  } catch (e) {
    const err = toApiError(e)
    credError.value = err.status === 409 ? '같은 이름의 자격증명이 있습니다' : err.message
  } finally {
    credBusy.value = false
  }
}

// ── Delete credential ─────────────────────────────────

const deleteCred = ref<Credential>()
const deleteCredOpen = computed({
  get: () => !!deleteCred.value,
  set: (v) => {
    if (!v) deleteCred.value = undefined
  },
})
const deleteCredBusy = ref(false)
const deleteCredError = ref('')

function askDeleteCred(c: Credential) {
  deleteCredError.value = ''
  deleteCred.value = c
}

async function removeCred() {
  const c = deleteCred.value
  if (!c || deleteCredBusy.value) return
  deleteCredBusy.value = true
  deleteCredError.value = ''
  try {
    await deleteCredential(c.id)
    deleteCred.value = undefined
    await refreshCredentials()
  } catch (e) {
    const err = toApiError(e)
    deleteCredError.value = err.status === 409 ? '사용 중인 자격증명은 삭제할 수 없습니다' : err.message
  } finally {
    deleteCredBusy.value = false
  }
}
</script>

<template>
  <div>
    <PageHeader title="Agentless 수집">
      <template #actions>
        <AppButton v-if="tab === 'targets'" variant="primary" :icon="Plus" @click="openTarget">대상 추가</AppButton>
        <AppButton v-else variant="primary" :icon="Plus" @click="openCred">자격증명 추가</AppButton>
      </template>
    </PageHeader>

    <AppTabs v-model="tab" :tabs="tabs" query-key="tab" />

    <div class="mt-4">
      <template v-if="tab === 'targets'">
        <p v-if="targetActionError" class="note note-danger mb-3" role="alert">{{ targetActionError }}</p>
        <Panel flush>
          <LoadError v-if="targetsError" :error="targetsError" @retry="refreshTargets" />
          <DataTable
            v-else
            :columns="targetColumns"
            :rows="targets"
            :row-key="(t) => t.id"
            :page-size="25"
            :initial-sort="{ key: 'name', dir: 'asc' }"
            :loading="targetsPending"
          >
            <template #cell-name="{ row }">
              <NuxtLink v-if="row.assetId" :to="`/assets/${row.assetId}`" class="link whitespace-nowrap font-medium">{{ row.name }}</NuxtLink>
              <span v-else class="whitespace-nowrap font-medium">{{ row.name }}</span>
            </template>
            <template #cell-protocol="{ row }">{{ protocolLabel[row.protocol] }}</template>
            <template #cell-address="{ row }"><span class="mono whitespace-nowrap">{{ row.address }}:{{ row.port }}</span></template>
            <template #cell-credential="{ row }">{{ credentialName(row) }}</template>
            <template #cell-scanner="{ row }">
              <template v-if="row.scannerId">
                <NuxtLink :to="`/agents/${row.scannerId}`" class="link whitespace-nowrap">{{ scannerName(row) }}</NuxtLink>
                <div v-if="agentById.get(row.scannerId)?.description" class="text-xs text-ink-3">{{ agentById.get(row.scannerId)?.description }}</div>
              </template>
              <span v-else class="whitespace-nowrap">{{ scannerName(row) }}</span>
            </template>
            <template #cell-sudo="{ row }"><span class="whitespace-nowrap">{{ row.sudo ? '사용' : '미사용' }}</span></template>
            <template #cell-hostKey="{ row }">
              <template v-if="row.hostKeyPinned">
                고정
                <div v-if="row.hostKeyFingerprint" class="mono whitespace-nowrap text-xs text-ink-3" :title="row.hostKeyFingerprint">{{ shortFingerprint(row.hostKeyFingerprint) }}</div>
              </template>
              <span v-else>최초 접속 시 저장</span>
            </template>
            <template #cell-schedule="{ row }"><span class="whitespace-nowrap">{{ intervalLabel(row.intervalMinutes) }}</span></template>
            <template #cell-detectDirs="{ row }">
              <span v-if="row.detectDirIds.length === 0" class="whitespace-nowrap text-ink-3">실행 중인 것만</span>
              <span v-for="p in detectPaths(row)" v-else :key="p" class="mono block text-xs [overflow-wrap:anywhere]">{{ p }}</span>
            </template>
            <template #cell-integrity="{ row }">
              <NuxtLink v-if="row.assetId" :to="`/assets/${row.assetId}?tab=integrity`" class="hover:underline">
                <StatusBadge :tone="row.integrityEnabled ? 'ok' : 'neutral'" :label="row.integrityEnabled ? '켜짐' : '꺼짐'" dot />
              </NuxtLink>
              <StatusBadge v-else :tone="row.integrityEnabled ? 'ok' : 'neutral'" :label="row.integrityEnabled ? '켜짐' : '꺼짐'" dot />
              <div v-if="row.integrity !== 'inherit'" class="text-xs text-ink-3">{{ integrityModeLabel[row.integrity] }}</div>
            </template>
            <template #cell-lastRun="{ row }">
              <template v-if="row.lastRun">
                <div class="flex flex-wrap items-center gap-1.5">
                  <StatusBadge :tone="resultTone[row.lastRun.result]" :label="resultLabel[row.lastRun.result]" />
                  <span class="whitespace-nowrap text-xs text-ink-2">{{ row.lastRun.durationSec }}초</span>
                  <TimeAgo :at="row.lastRun.at" class="text-xs text-ink-3" />
                </div>
                <Diagnostic v-if="row.lastRun.message" :text="row.lastRun.message" scan class="mt-0.5" />
              </template>
              <span v-else class="text-ink-3">수집 이력 없음</span>
            </template>
            <template #cell-actions="{ row }">
              <span class="inline-flex items-center gap-1.5">
                <span v-if="requested.has(row.id)" class="whitespace-nowrap text-xs text-ink-2">요청함</span>
                <AppButton v-else size="sm" :icon="Play" :disabled="!!running" @click="runNow(row)">수집 실행</AppButton>
                <AppButton size="sm" @click="openEditTarget(row)">편집</AppButton>
                <AppButton size="sm" variant="danger" @click="askDeleteTarget(row)">삭제</AppButton>
              </span>
            </template>
          </DataTable>
        </Panel>
      </template>

      <Panel v-else flush>
        <LoadError v-if="credentialsError" :error="credentialsError" @retry="refreshCredentials" />
        <DataTable
          v-else
          :columns="credentialColumns"
          :rows="credentials"
          :row-key="(c) => c.id"
          :initial-sort="{ key: 'name', dir: 'asc' }"
          :loading="credentialsPending"
        >
          <template #cell-name="{ row }">
            <span class="font-medium">{{ row.name }}</span>
          </template>
          <template #cell-kind="{ row }">{{ credentialKindLabel[row.kind] }}</template>
          <template #cell-username="{ row }"><span v-if="row.username" class="mono">{{ row.username }}</span><span v-else class="text-ink-3">—</span></template>
          <template #cell-fingerprint="{ row }">
            <span v-if="row.publicKeyFingerprint" class="mono whitespace-nowrap text-xs">{{ row.publicKeyFingerprint }}</span>
            <span v-else class="text-ink-3">—</span>
          </template>
          <template #cell-usedBy="{ row }"><span class="mono whitespace-nowrap">{{ row.usedBy }}</span></template>
          <template #cell-createdAt="{ row }"><span class="whitespace-nowrap">{{ formatDate(row.createdAt) }}</span></template>
          <template #cell-actions="{ row }">
            <span class="inline-flex items-center gap-1.5">
              <AppButton size="sm" @click="openRotate(row)">비밀 교체</AppButton>
              <AppButton size="sm" variant="danger" @click="askDeleteCred(row)">삭제</AppButton>
            </span>
          </template>
        </DataTable>
      </Panel>
    </div>

    <AppModal v-model:open="targetOpen" :title="editingTarget ? '대상 편집' : '대상 추가'">
      <form id="target-form" class="grid grid-cols-1 gap-3" @submit.prevent="addTarget">
        <FormField label="이름"><input v-model="targetForm.name" class="input w-full" /></FormField>
        <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <FormField label="프로토콜">
            <select class="select w-full" disabled>
              <option>SSH</option>
            </select>
          </FormField>
          <FormField label="포트" :error="portValid ? undefined : '1–65535'">
            <input v-model.number="targetForm.port" type="number" min="1" max="65535" class="input mono w-full" />
          </FormField>
        </div>
        <FormField label="주소">
          <input v-model="targetForm.address" class="input mono w-full" placeholder="10.0.0.5" :readonly="!!editingTarget" :disabled="!!editingTarget" />
        </FormField>
        <FormField label="자격증명" :hint="sshCredentials.length ? undefined : 'SSH 자격증명이 없습니다'">
          <select v-model="targetForm.credentialId" class="select w-full">
            <option value="" disabled>선택</option>
            <option v-for="c in sshCredentials" :key="c.id" :value="c.id">{{ c.name }} ({{ credentialKindLabel[c.kind] }})</option>
          </select>
        </FormField>
        <FormField label="Scanner">
          <select v-model="targetForm.scannerId" class="select w-full">
            <option value="">내장 Scanner</option>
            <option v-for="s in scannerOptions" :key="s.id" :value="s.id">{{ agentOptionLabel(s) }}</option>
          </select>
        </FormField>
        <label v-if="editingTarget?.hostKeyPinned" class="inline-flex items-center gap-1.5 text-sm">
          <input v-model="targetForm.resetHostKey" type="checkbox" class="accent-(--accent)" /> host key 초기화
        </label>
        <FormField v-if="!editingTarget" label="host key">
          <select v-model="targetForm.hostKeyMode" class="select w-full">
            <option value="tofu">최초 접속 시 저장</option>
            <option value="pinned">고정</option>
          </select>
        </FormField>
        <FormField v-if="!editingTarget && targetForm.hostKeyMode === 'pinned'" label="host 공개 키" hint="<type> <base64>">
          <textarea v-model="targetForm.hostKey" rows="2" class="input mono w-full" placeholder="ssh-ed25519 AAAA…" />
        </FormField>
        <label class="inline-flex items-center gap-1.5 text-sm"><input v-model="targetForm.sudo" type="checkbox" class="accent-(--accent)" /> sudo 사용</label>
        <FormField label="수집 주기 (분)" hint="0은 수동" :error="intervalValid ? undefined : '0 이상의 정수를 입력합니다'">
          <input v-model.number="targetForm.intervalMinutes" type="number" min="0" step="1" class="input mono w-full" />
        </FormField>
        <div class="-mt-1 flex flex-wrap gap-1.5">
          <AppButton
            v-for="p in intervalPresets"
            :key="p.minutes"
            size="sm"
            :variant="targetForm.intervalMinutes === p.minutes ? 'primary' : 'secondary'"
            @click="targetForm.intervalMinutes = p.minutes"
          >
            {{ p.label }}
          </AppButton>
        </div>
        <fieldset>
          <legend class="mb-1 block text-xs font-medium text-ink-2">감지 대상 디렉터리</legend>
          <DetectDirPicker v-model="targetForm.detectDirIds" :dirs="detectDirs" :disabled="targetBusy" />
          <p class="mt-1 text-xs text-ink-3">고른 디렉터리만 하위까지 탐색합니다. 고르지 않으면 실행 중인 소프트웨어만 수집합니다.</p>
        </fieldset>
        <FormField label="파일 무결성 검사" hint="기본값은 설정 › 파일 무결성의 Agentless (SSH) 기본값입니다.">
          <select v-model="targetForm.integrity" class="select w-full">
            <option v-for="m in (['inherit', 'on', 'off'] as const)" :key="m" :value="m">{{ integrityModeLabel[m] }}</option>
          </select>
        </FormField>
        <p v-if="targetError" class="note note-danger" role="alert">{{ targetError }}</p>
      </form>
      <template #footer>
        <AppButton @click="targetOpen = false">취소</AppButton>
        <AppButton variant="primary" type="submit" form="target-form" :disabled="!targetValid || targetBusy">{{ editingTarget ? '저장' : '추가' }}</AppButton>
      </template>
    </AppModal>

    <AppModal v-model:open="deleteTargetOpen" title="대상 삭제">
      <p class="text-sm"><strong>{{ deleteTargetRow?.name }}</strong> 대상을 삭제합니다. 수집된 자산은 남습니다.</p>
      <p v-if="deleteTargetError" class="note note-danger mt-3" role="alert">{{ deleteTargetError }}</p>
      <template #footer>
        <AppButton @click="deleteTargetOpen = false">취소</AppButton>
        <AppButton variant="danger" :disabled="deleteTargetBusy" @click="removeTarget">삭제</AppButton>
      </template>
    </AppModal>

    <AppModal v-model:open="credOpen" :title="rotatingCred ? '비밀 교체' : '자격증명 추가'" wide>
      <form id="cred-form" class="grid grid-cols-1 gap-3" @submit.prevent="addCred">
        <FormField label="이름"><input v-model="credForm.name" class="input w-full" :disabled="!!rotatingCred" /></FormField>
        <FormField label="종류">
          <select v-model="credForm.kind" class="select w-full" :disabled="!!rotatingCred">
            <option v-for="(label, value) in credentialKindLabel" :key="value" :value="value">{{ label }}</option>
          </select>
        </FormField>
        <FormField v-if="credForm.kind !== 'kubeconfig'" label="사용자">
          <input v-model="credForm.username" class="input mono w-full" autocomplete="off" />
        </FormField>
        <template v-if="credForm.kind === 'ssh_key'">
          <FormField label="개인 키" hint="OpenSSH 또는 PEM">
            <textarea v-model="credForm.privateKey" rows="5" class="input mono w-full" spellcheck="false" autocomplete="off" />
          </FormField>
          <input type="file" class="input w-full" aria-label="개인 키 파일" @change="readFileInto($event, 'privateKey')" />
          <FormField label="passphrase">
            <input v-model="credForm.passphrase" type="password" autocomplete="new-password" class="input w-full" />
          </FormField>
        </template>
        <FormField v-else-if="credForm.kind === 'ssh_password'" label="비밀번호">
          <input v-model="credForm.password" type="password" autocomplete="new-password" class="input w-full" />
        </FormField>
        <template v-else>
          <FormField label="kubeconfig" hint="YAML">
            <textarea v-model="credForm.kubeconfig" rows="8" class="input mono w-full" spellcheck="false" autocomplete="off" />
          </FormField>
          <input type="file" class="input w-full" aria-label="kubeconfig 파일" @change="readFileInto($event, 'kubeconfig')" />
        </template>
        <p v-if="credError" class="note note-danger" role="alert">{{ credError }}</p>
      </form>
      <template #footer>
        <AppButton @click="credOpen = false">취소</AppButton>
        <AppButton variant="primary" type="submit" form="cred-form" :disabled="!credValid || credBusy">{{ rotatingCred ? '교체' : '추가' }}</AppButton>
      </template>
    </AppModal>

    <AppModal v-model:open="deleteCredOpen" title="자격증명 삭제">
      <p class="text-sm"><strong>{{ deleteCred?.name }}</strong> 자격증명을 삭제합니다.</p>
      <p v-if="deleteCred && deleteCred.usedBy > 0" class="note note-warn mt-3">
        사용 대상이 {{ deleteCred.usedBy }}개 있습니다. 사용 중인 자격증명은 삭제할 수 없습니다.
      </p>
      <p v-if="deleteCredError" class="note note-danger mt-3" role="alert">{{ deleteCredError }}</p>
      <template #footer>
        <AppButton @click="deleteCredOpen = false">취소</AppButton>
        <AppButton variant="danger" :disabled="deleteCredBusy" @click="removeCred">삭제</AppButton>
      </template>
    </AppModal>
  </div>
</template>
