<script setup lang="ts">
import { Plus, Play } from '@lucide/vue'
import type { Credential, ScanTarget } from '~/types'
import type { TableColumn } from '~/types/table'
import { agents, credentials as credentialSource, getAgent, getCredential, MOCK_NOW, scanTargets as targetSource } from '~/mock'

useHead({ title: 'Agentless 수집 · bomcensus' })

const tab = ref('targets')
const targets = ref<ScanTarget[]>([...targetSource])
const credentials = ref<Credential[]>([...credentialSource])
// 이 화면에서 수집을 요청한 대상
const requested = ref<Set<string>>(new Set())

const tabs = computed(() => [
  { key: 'targets', label: '대상', count: targets.value.length },
  { key: 'credentials', label: '자격증명', count: credentials.value.length },
])

const credentialKindLabel: Record<Credential['kind'], string> = {
  ssh_key: 'SSH 키',
  ssh_password: 'SSH 비밀번호',
  winrm: 'WinRM',
  kubeconfig: 'kubeconfig',
}
const protocolLabel: Record<ScanTarget['protocol'], string> = { ssh: 'SSH', winrm: 'WinRM' }
const resultLabel: Record<'ok' | 'partial' | 'failed', string> = { ok: '성공', partial: '부분', failed: '실패' }
const resultTone: Record<'ok' | 'partial' | 'failed', Tone> = { ok: 'ok', partial: 'warn', failed: 'danger' }

const targetColumns: TableColumn<ScanTarget>[] = [
  { key: 'name', label: '이름', sortValue: (t) => t.name },
  { key: 'protocol', label: '프로토콜', sortValue: (t) => t.protocol, hideBelow: 'sm' },
  { key: 'address', label: '주소', sortValue: (t) => t.address },
  { key: 'credential', label: '자격증명', sortValue: (t) => getCredential(t.credentialId)?.name ?? '', hideBelow: 'lg' },
  { key: 'scanner', label: 'Scanner', sortValue: (t) => getAgent(t.scannerId)?.hostname ?? '', hideBelow: 'lg' },
  { key: 'sudo', label: 'sudo', hideBelow: 'md' },
  { key: 'hostKey', label: 'host key', hideBelow: 'md' },
  { key: 'schedule', label: '일정', hideBelow: 'md' },
  { key: 'lastRun', label: '최근 결과', sortValue: (t) => t.lastRun?.at ?? '' },
  { key: 'actions', label: '', align: 'right' },
]

const credentialColumns: TableColumn<Credential>[] = [
  { key: 'name', label: '이름', sortValue: (c) => c.name },
  { key: 'kind', label: '종류', sortValue: (c) => c.kind },
  { key: 'username', label: '사용자', sortValue: (c) => c.username ?? '', hideBelow: 'sm' },
  { key: 'usedBy', label: '사용 대상', align: 'right', sortValue: (c) => usedBy(c.id) },
  { key: 'createdAt', label: '생성일', sortValue: (c) => c.createdAt, hideBelow: 'sm' },
]

// 목록에 추가한 대상까지 반영해 센다
const usedBy = (credentialId: string) => targets.value.filter((t) => t.credentialId === credentialId).length

function runNow(t: ScanTarget) {
  requested.value = new Set(requested.value).add(t.id)
}

// 대상 추가
const targetOpen = ref(false)
const emptyTarget = () => ({
  name: '',
  protocol: 'ssh' as ScanTarget['protocol'],
  address: '',
  port: '22',
  credentialId: '',
  scannerId: '',
  sudo: false,
  hostKey: 'tofu' as 'pinned' | 'tofu',
  schedule: '매일 03:00',
})
const targetForm = reactive(emptyTarget())
const scannerOptions = computed(() => agents.filter((a) => a.kind === 'scanner'))
const credentialOptions = computed(() =>
  credentials.value.filter((c) => (targetForm.protocol === 'ssh' ? c.kind.startsWith('ssh') : c.kind === 'winrm')),
)
const targetValid = computed(
  () => !!targetForm.name.trim() && !!targetForm.address.trim() && !!targetForm.credentialId && !!targetForm.scannerId && Number(targetForm.port) > 0,
)

watch(
  () => targetForm.protocol,
  (p) => {
    targetForm.port = p === 'ssh' ? '22' : '5986'
    targetForm.credentialId = ''
  },
)

function openTarget() {
  Object.assign(targetForm, emptyTarget())
  targetOpen.value = true
}

function addTarget() {
  if (!targetValid.value) return
  targets.value.push({
    id: `target-new-${targets.value.length + 1}`,
    name: targetForm.name.trim(),
    protocol: targetForm.protocol,
    address: targetForm.address.trim(),
    port: Number(targetForm.port),
    credentialId: targetForm.credentialId,
    scannerId: targetForm.scannerId,
    sudo: targetForm.protocol === 'ssh' && targetForm.sudo,
    hostKeyPinned: targetForm.protocol === 'ssh' ? targetForm.hostKey === 'pinned' : undefined,
    schedule: targetForm.schedule.trim(),
  })
  targetOpen.value = false
}

// 자격증명 추가
const credOpen = ref(false)
const emptyCred = () => ({ name: '', kind: 'ssh_key' as Credential['kind'], username: '' })
const credForm = reactive(emptyCred())
const credValid = computed(() => !!credForm.name.trim() && (credForm.kind === 'kubeconfig' || !!credForm.username.trim()))

function openCred() {
  Object.assign(credForm, emptyCred())
  credOpen.value = true
}

function addCred() {
  if (!credValid.value) return
  credentials.value.push({
    id: `cred-new-${credentials.value.length + 1}`,
    name: credForm.name.trim(),
    kind: credForm.kind,
    username: credForm.kind === 'kubeconfig' ? undefined : credForm.username.trim(),
    usedBy: 0,
    createdAt: MOCK_NOW,
  })
  credOpen.value = false
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
      <Panel v-if="tab === 'targets'" flush>
        <DataTable
          :columns="targetColumns"
          :rows="targets"
          :row-key="(t) => t.id"
          :page-size="25"
        >
          <template #cell-name="{ row }">
            <NuxtLink v-if="row.assetId" :to="`/assets/${row.assetId}`" class="link font-medium">{{ row.name }}</NuxtLink>
            <span v-else class="font-medium">{{ row.name }}</span>
          </template>
          <template #cell-protocol="{ row }">{{ protocolLabel[row.protocol] }}</template>
          <template #cell-address="{ row }"><span class="mono whitespace-nowrap">{{ row.address }}:{{ row.port }}</span></template>
          <template #cell-credential="{ row }">{{ getCredential(row.credentialId)?.name ?? '—' }}</template>
          <template #cell-scanner="{ row }">{{ getAgent(row.scannerId)?.hostname ?? '—' }}</template>
          <template #cell-sudo="{ row }">{{ row.protocol === 'ssh' ? (row.sudo ? '사용' : '미사용') : '—' }}</template>
          <template #cell-hostKey="{ row }">
            <template v-if="row.protocol === 'ssh'">{{ row.hostKeyPinned ? '고정' : '최초 접속 시 저장' }}</template>
            <span v-else class="text-ink-3">—</span>
          </template>
          <template #cell-schedule="{ row }">{{ row.schedule }}</template>
          <template #cell-lastRun="{ row }">
            <template v-if="row.lastRun">
              <div class="flex flex-wrap items-center gap-1.5">
                <StatusBadge :tone="resultTone[row.lastRun.result]" :label="resultLabel[row.lastRun.result]" />
                <span class="whitespace-nowrap text-xs text-ink-2">{{ row.lastRun.durationSec }}초</span>
                <TimeAgo :at="row.lastRun.at" class="text-xs text-ink-3" />
              </div>
              <div v-if="row.lastRun.message" class="mt-0.5 text-xs text-ink-2">{{ row.lastRun.message }}</div>
            </template>
            <span v-else class="text-ink-3">수집 이력 없음</span>
          </template>
          <template #cell-actions="{ row }">
            <span v-if="requested.has(row.id)" class="text-xs text-ink-2">요청함</span>
            <AppButton v-else size="sm" :icon="Play" @click="runNow(row)">수집 실행</AppButton>
          </template>
        </DataTable>
      </Panel>

      <template v-else>
        <Panel flush>
          <DataTable
            :columns="credentialColumns"
            :rows="credentials"
            :row-key="(c) => c.id"
          >
            <template #cell-name="{ row }"><span class="font-medium">{{ row.name }}</span></template>
            <template #cell-kind="{ row }">{{ credentialKindLabel[row.kind] }}</template>
            <template #cell-username="{ row }"><span v-if="row.username" class="mono">{{ row.username }}</span><span v-else class="text-ink-3">—</span></template>
            <template #cell-usedBy="{ row }"><span class="mono whitespace-nowrap">{{ usedBy(row.id) }}</span></template>
            <template #cell-createdAt="{ row }"><span class="whitespace-nowrap">{{ formatDate(row.createdAt) }}</span></template>
          </DataTable>
        </Panel>
      </template>
    </div>

    <AppModal v-model:open="targetOpen" title="대상 추가">
      <form id="target-form" class="grid grid-cols-1 gap-3" @submit.prevent="addTarget">
        <FormField label="이름"><input v-model="targetForm.name" class="input w-full" /></FormField>
        <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <FormField label="프로토콜">
            <select v-model="targetForm.protocol" class="select w-full">
              <option value="ssh">SSH</option>
              <option value="winrm">WinRM</option>
            </select>
          </FormField>
          <FormField label="포트"><input v-model="targetForm.port" class="input mono w-full" inputmode="numeric" /></FormField>
        </div>
        <FormField label="주소"><input v-model="targetForm.address" class="input mono w-full" placeholder="10.0.0.5" /></FormField>
        <FormField label="자격증명" :hint="credentialOptions.length ? undefined : '이 프로토콜에 쓸 자격증명이 없습니다. 자격증명 탭에서 먼저 추가합니다.'">
          <select v-model="targetForm.credentialId" class="select w-full">
            <option value="" disabled>선택</option>
            <option v-for="c in credentialOptions" :key="c.id" :value="c.id">{{ c.name }}</option>
          </select>
        </FormField>
        <FormField label="Scanner">
          <select v-model="targetForm.scannerId" class="select w-full">
            <option value="" disabled>선택</option>
            <option v-for="s in scannerOptions" :key="s.id" :value="s.id">{{ s.hostname }}</option>
          </select>
        </FormField>
        <template v-if="targetForm.protocol === 'ssh'">
          <FormField label="host key">
            <select v-model="targetForm.hostKey" class="select w-full">
              <option value="tofu">최초 접속 시 저장</option>
              <option value="pinned">고정</option>
            </select>
          </FormField>
          <label class="inline-flex items-center gap-1.5 text-sm"><input v-model="targetForm.sudo" type="checkbox" class="accent-(--accent)" /> sudo 사용</label>
        </template>
        <FormField label="일정"><input v-model="targetForm.schedule" class="input w-full" /></FormField>
      </form>
      <template #footer>
        <AppButton @click="targetOpen = false">취소</AppButton>
        <AppButton variant="primary" type="submit" :disabled="!targetValid" @click="addTarget">추가</AppButton>
      </template>
    </AppModal>

    <AppModal v-model:open="credOpen" title="자격증명 추가">
      <form class="grid grid-cols-1 gap-3" @submit.prevent="addCred">
        <FormField label="이름"><input v-model="credForm.name" class="input w-full" /></FormField>
        <FormField label="종류">
          <select v-model="credForm.kind" class="select w-full">
            <option v-for="(label, value) in credentialKindLabel" :key="value" :value="value">{{ label }}</option>
          </select>
        </FormField>
        <FormField v-if="credForm.kind !== 'kubeconfig'" label="사용자"><input v-model="credForm.username" class="input mono w-full" /></FormField>
        <FormField v-if="credForm.kind === 'ssh_key' || credForm.kind === 'kubeconfig'" label="파일">
          <input type="file" class="input w-full" />
        </FormField>
        <FormField v-else label="비밀번호"><input type="password" autocomplete="new-password" class="input w-full" /></FormField>
      </form>
      <template #footer>
        <AppButton @click="credOpen = false">취소</AppButton>
        <AppButton variant="primary" :disabled="!credValid" @click="addCred">추가</AppButton>
      </template>
    </AppModal>
  </div>
</template>
