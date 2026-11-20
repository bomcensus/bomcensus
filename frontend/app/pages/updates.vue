<script setup lang="ts">
import { Upload } from '@lucide/vue'
import type { Release, UpdateSettings } from '~/types'
import type { TableColumn } from '~/types/table'
import { MOCK_NOW, agents, releases as mockReleases, updateSettings } from '~/mock'

useHead({ title: '업데이트 · bomcensus' })

// 릴리스 등록과 배포 버전 변경은 이 페이지의 복사본에만 반영된다
const releases = ref<Release[]>(mockReleases.map((r) => ({ ...r })))
const settings = ref<UpdateSettings>({ ...updateSettings })

const sourceLabel = { online: '온라인', upload: '업로드' } as const

const releaseColumns: TableColumn<Release>[] = [
  { key: 'version', label: '버전', sortValue: (r) => r.version },
  { key: 'publishedAt', label: '게시일', sortValue: (r) => r.publishedAt },
  { key: 'source', label: '출처', sortValue: (r) => r.source, hideBelow: 'sm' },
  { key: 'verified', label: '서명 검증', sortValue: (r) => Number(r.verified) },
]
const outdatedColumns: TableColumn<(typeof agents)[number]>[] = [
  { key: 'hostname', label: '호스트명', sortValue: (a) => a.hostname },
  { key: 'version', label: '버전', sortValue: (a) => a.version },
  { key: 'updateState', label: '업데이트 상태', sortValue: (a) => a.updateState },
  { key: 'lastSeen', label: '최근 접속', align: 'right', sortValue: (a) => a.lastSeen, hideBelow: 'sm' },
]

// ── 배포 현황 ────────────────────────────────────────
const liveAgents = computed(() => agents.filter((a) => a.kind === 'agent' && a.status !== 'revoked'))
const onTarget = computed(() => liveAgents.value.filter((a) => a.version === settings.value.targetVersion).length)
const percent = computed(() => (liveAgents.value.length > 0 ? Math.round((onTarget.value / liveAgents.value.length) * 100) : 0))

const outdated = computed(() =>
  agents.filter((a) => a.status !== 'revoked' && (a.version !== settings.value.targetVersion || a.updateState !== 'up_to_date')),
)

// ── 릴리스 업로드 ────────────────────────────────────
const uploadOpen = ref(false)
const upload = reactive({ version: '', fileName: '', error: '' })
const semver = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/

function openUpload() {
  Object.assign(upload, { version: '', fileName: '', error: '' })
  uploadOpen.value = true
}
function onFile(e: Event) {
  upload.fileName = (e.target as HTMLInputElement).files?.[0]?.name ?? ''
}
function submitUpload() {
  const version = upload.version.trim().replace(/^v/, '')
  if (!upload.fileName) return void (upload.error = '파일을 선택합니다')
  if (!semver.test(version)) return void (upload.error = '버전은 1.2.3 형식입니다')
  if (releases.value.some((r) => r.version === version)) return void (upload.error = '이미 등록된 버전입니다')
  // 목업: 검증은 실제로 수행하지 않고 통과한 것으로 등록한다
  releases.value.unshift({ version, publishedAt: MOCK_NOW, source: 'upload', verified: true, notes: '' })
  uploadOpen.value = false
}

// ── 배포 버전 변경 ───────────────────────────────────
const changeOpen = ref(false)
const change = reactive({ version: '', interval: 60, error: '' })
const verifiedReleases = computed(() => releases.value.filter((r) => r.verified))

function openChange() {
  Object.assign(change, { version: settings.value.targetVersion, interval: settings.value.checkIntervalMinutes, error: '' })
  changeOpen.value = true
}

// 숫자 비교는 점 단위로 한다. 사전식 비교는 1.10 < 1.9 가 되어 틀린다
function cmpVersion(a: string, b: string): number {
  const pa = a.split(/[.-]/).map((n) => parseInt(n, 10) || 0)
  const pb = b.split(/[.-]/).map((n) => parseInt(n, 10) || 0)
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0)
    if (d !== 0) return d
  }
  return 0
}
const downgradeCount = computed(
  () => liveAgents.value.filter((a) => change.version && cmpVersion(a.version, change.version) > 0).length,
)

function saveChange() {
  if (!change.version) return void (change.error = '배포할 버전을 선택합니다')
  if (!Number.isInteger(change.interval) || change.interval < 1) return void (change.error = '확인 주기는 1분 이상의 정수입니다')
  settings.value = { targetVersion: change.version, checkIntervalMinutes: change.interval }
  changeOpen.value = false
}
</script>

<template>
  <div>
    <PageHeader title="업데이트" />

    <Panel title="배포 버전">
      <template #actions>
        <AppButton size="sm" @click="openChange">변경</AppButton>
      </template>
      <div class="grid grid-cols-1 gap-4 md:grid-cols-3">
        <div class="min-w-0">
          <div class="text-xs text-ink-3">배포 버전</div>
          <div class="mono whitespace-nowrap text-2xl">{{ settings.targetVersion || '—' }}</div>
        </div>
        <div class="min-w-0">
          <div class="text-xs text-ink-3">적용된 Agent</div>
          <div class="mono whitespace-nowrap text-lg">{{ onTarget }} / {{ liveAgents.length }}</div>
          <div class="mt-1.5 h-1.5 overflow-hidden rounded-sm bg-surface-2" role="img" :aria-label="`${onTarget} / ${liveAgents.length}`">
            <div class="h-full bg-accent" :style="{ width: `${percent}%` }" />
          </div>
        </div>
        <div class="min-w-0">
          <div class="text-xs text-ink-3">확인 주기</div>
          <div class="mono whitespace-nowrap text-lg">{{ settings.checkIntervalMinutes }}분</div>
        </div>
      </div>
    </Panel>

    <div class="mt-4">
      <Panel title="릴리스" flush>
        <template #actions>
          <AppButton size="sm" :icon="Upload" @click="openUpload">릴리스 업로드</AppButton>
        </template>
        <DataTable
          :columns="releaseColumns"
          :rows="releases"
          :row-key="(r) => r.version"
          :initial-sort="{ key: 'publishedAt', dir: 'desc' }"
        >
          <template #cell-version="{ row }">
            <span class="mono whitespace-nowrap font-medium">{{ row.version }}</span>
            <StatusBadge v-if="row.version === settings.targetVersion" class="ml-2" tone="info" label="배포 중" />
          </template>
          <template #cell-publishedAt="{ row }"><span class="whitespace-nowrap">{{ formatDate(row.publishedAt) }}</span></template>
          <template #cell-source="{ row }">{{ sourceLabel[row.source] }}</template>
          <template #cell-verified="{ row }">
            <StatusBadge :tone="row.verified ? 'ok' : 'danger'" :label="row.verified ? '검증됨' : '검증 실패'" />
          </template>
        </DataTable>
      </Panel>
    </div>

    <div class="mt-4">
      <Panel title="미적용 에이전트" flush>
        <DataTable
          :columns="outdatedColumns"
          :rows="outdated"
          :row-key="(a) => a.id"
          :row-to="(a) => `/agents/${a.id}`"
        >
          <template #cell-hostname="{ row }">
            <NuxtLink :to="`/agents/${row.id}`" class="font-medium hover:underline">{{ row.hostname }}</NuxtLink>
          </template>
          <template #cell-version="{ row }"><span class="mono whitespace-nowrap">{{ row.version }}</span></template>
          <template #cell-updateState="{ row }">
            <StatusBadge :tone="updateStateTone[row.updateState]" :label="updateStateLabel[row.updateState]" />
          </template>
          <template #cell-lastSeen="{ row }"><TimeAgo :at="row.lastSeen" class="whitespace-nowrap text-ink-2" /></template>
        </DataTable>
      </Panel>
    </div>

    <AppModal v-model:open="uploadOpen" title="릴리스 업로드">
      <div class="grid grid-cols-1 gap-3">
        <FormField label="릴리스 파일">
          <input type="file" class="input w-full" @change="onFile" />
        </FormField>
        <FormField label="버전" hint="예: 1.4.2">
          <input v-model="upload.version" class="input mono w-full" />
        </FormField>
        <p v-if="upload.error" class="text-xs text-critical">{{ upload.error }}</p>
      </div>
      <template #footer>
        <AppButton @click="uploadOpen = false">취소</AppButton>
        <AppButton variant="primary" @click="submitUpload">검증 후 등록</AppButton>
      </template>
    </AppModal>

    <AppModal v-model:open="changeOpen" title="배포 버전 변경">
      <div class="grid grid-cols-1 gap-3">
        <FormField label="배포 버전" hint="서명 검증을 통과한 릴리스만 고를 수 있습니다">
          <select v-model="change.version" class="select mono w-full">
            <option value="" disabled>선택</option>
            <option v-for="r in verifiedReleases" :key="r.version" :value="r.version">{{ r.version }}</option>
          </select>
        </FormField>
        <FormField label="확인 주기 (분)">
          <input v-model.number="change.interval" type="number" min="1" step="1" class="input w-full" />
        </FormField>
        <p v-if="downgradeCount > 0" class="note note-warn">
          선택한 버전보다 높은 버전을 쓰는 Agent가 {{ downgradeCount }}개 있습니다. Agent는 낮은 버전으로 내려가지 않습니다.
        </p>
        <p v-if="change.error" class="text-xs text-critical">{{ change.error }}</p>
      </div>
      <template #footer>
        <AppButton @click="changeOpen = false">취소</AppButton>
        <AppButton variant="primary" @click="saveChange">저장</AppButton>
      </template>
    </AppModal>
  </div>
</template>
