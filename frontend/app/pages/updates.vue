<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import { Upload } from '@lucide/vue'
import type { Agent, Release } from '~/types'
import type { TableColumn } from '~/types/table'
import { fetchAll, getUpdateSettings, listAgents, listReleases, setUpdateSettings, toApiError, uploadRelease, type QueryOf } from '~/api'

useHead({ title: '업데이트 · bomcensus' })

const {
  items: releases,
  total: releasesTotal,
  pending: releasesPending,
  error: releasesError,
  refresh: refreshReleaseList,
  q: releaseQ,
  filters: releaseFilters,
  sort: releaseSort,
  page: releasePage,
  size: releaseSize,
} = useServerList('releases', (p) => listReleases(p as QueryOf<typeof listReleases>), {
  filters: { source: '', verified: false },
  sort: '-version',
  url: true,
})
// Verified releases are the choices of the rollout version
const { data: verifiedReleases, refresh: refreshVerified } = useLoad(
  'releases:verified',
  () => fetchAll((page) => listReleases({ ...page, verified: true })),
  () => [],
)
async function refreshReleases() {
  await Promise.all([refreshReleaseList(), refreshVerified()])
}
const { data: settings, error: settingsError, refresh: refreshSettings } = useLoad('update-settings', () => getUpdateSettings())
const targetVersion = computed(() => settings.value?.targetVersion ?? null)

// Rollout numbers over agents that are not revoked, from list totals
const { data: rollout, error: rolloutError } = useLoad(
  () => `updates:rollout:${targetVersion.value ?? ''}`,
  async () => {
    const count = (q: QueryOf<typeof listAgents>) => listAgents({ ...q, kind: 'agent', limit: 1 }).then((r) => r.total)
    const v = targetVersion.value
    const [all, revoked, on, onRevoked] = await Promise.all([
      count({}),
      count({ status: 'revoked' }),
      v ? count({ version: v }) : 0,
      v ? count({ version: v, status: 'revoked' }) : 0,
    ])
    return { live: all - revoked, onTarget: on - onRevoked }
  },
)

// Agents and scanners that are not revoked and not on the deployed version or not up to date
const {
  items: outdated,
  total: outdatedTotal,
  pending: outdatedPending,
  error: outdatedError,
  refresh: refreshOutdated,
  sort: outdatedSort,
  page: outdatedPage,
  size: outdatedSize,
} = useServerList('outdated', (p) => listAgents({ ...p, outdated: true } as QueryOf<typeof listAgents>), {
  sort: 'hostname',
  url: 'outdated',
  deps: () => targetVersion.value,
})

const sourceLabel = { online: '온라인', upload: '업로드' } as const

const releaseColumns: TableColumn<Release>[] = [
  { key: 'version', label: '버전', sort: 'version', sortDesc: true },
  { key: 'publishedAt', label: '게시일', sort: 'publishedAt', sortDesc: true },
  { key: 'source', label: '출처', hideBelow: 'sm' },
  { key: 'platforms', label: '플랫폼', hideBelow: 'md' },
  { key: 'verified', label: '서명 검증' },
]
const sourceOptions = Object.entries(sourceLabel).map(([value, label]) => ({ value, label }))
const outdatedColumns: TableColumn<Agent>[] = [
  { key: 'hostname', label: '호스트명', sort: 'hostname' },
  { key: 'version', label: '버전', sort: 'version' },
  { key: 'updateState', label: '업데이트 상태', sort: 'updateState', sortDesc: true },
  { key: 'lastSeen', label: '최근 접속', align: 'right', sort: 'lastSeen', sortDesc: true, hideBelow: 'sm' },
]

// ── Rollout status ────────────────────────────────────────
const percent = computed(() => {
  const r = rollout.value
  return r && r.live > 0 ? Math.round((r.onTarget / r.live) * 100) : 0
})

// ── Release upload ────────────────────────────────────
const uploadOpen = ref(false)
const uploadFile = ref<File>()
const uploadBusy = ref(false)
const uploadError = ref('')

function openUpload() {
  uploadFile.value = undefined
  uploadError.value = ''
  uploadOpen.value = true
}
function onFile(e: Event) {
  uploadFile.value = (e.target as HTMLInputElement).files?.[0]
  uploadError.value = ''
}
async function submitUpload() {
  if (!uploadFile.value || uploadBusy.value) return
  uploadBusy.value = true
  uploadError.value = ''
  try {
    await uploadRelease(uploadFile.value)
    uploadOpen.value = false
    await refreshReleases()
  } catch (e) {
    const err = toApiError(e)
    uploadError.value = err.status === 409 ? '이미 등록된 버전입니다' : err.status === 413 ? '파일이 너무 큽니다' : err.message
  } finally {
    uploadBusy.value = false
  }
}

// ── Rollout version change ───────────────────────────────────
const changeOpen = ref(false)
const change = reactive({ version: '', interval: 60, error: '' })
const changeBusy = ref(false)

// Versions of the agents that are not revoked, loaded when the dialog opens, for the downgrade warning
const changeAgents = ref<Agent[]>([])

async function openChange() {
  Object.assign(change, {
    version: settings.value?.targetVersion ?? '',
    interval: settings.value?.checkIntervalMinutes ?? 60,
    error: '',
  })
  changeAgents.value = []
  changeOpen.value = true
  try {
    const all = await fetchAll((page) => listAgents({ ...page, kind: 'agent' }))
    changeAgents.value = all.filter((a) => a.status !== 'revoked')
  } catch {
    // The warning is left out when the agents cannot be loaded
  }
}

// Compare numerically per dot-separated part. Lexical comparison gives 1.10 < 1.9, which is wrong
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
  () => changeAgents.value.filter((a) => change.version && cmpVersion(a.version, change.version) > 0).length,
)

async function saveChange() {
  if (changeBusy.value) return
  if (!Number.isInteger(change.interval) || change.interval < 1 || change.interval > 10080) {
    change.error = '확인 주기는 1–10080분의 정수입니다'
    return
  }
  changeBusy.value = true
  change.error = ''
  try {
    await setUpdateSettings({ targetVersion: change.version || null, checkIntervalMinutes: change.interval })
    changeOpen.value = false
    await refreshSettings()
  } catch (e) {
    change.error = toApiError(e).message
  } finally {
    changeBusy.value = false
  }
}
</script>

<template>
  <div>
    <PageHeader title="업데이트" />

    <Panel title="배포 버전">
      <template v-if="settings" #actions>
        <AppButton size="sm" @click="openChange">변경</AppButton>
      </template>
      <LoadError v-if="settingsError" :error="settingsError" @retry="refreshSettings" />
      <LoadingText v-else-if="!settings" />
      <div v-else class="grid grid-cols-1 gap-4 md:grid-cols-3">
        <div class="min-w-0">
          <div class="text-xs text-ink-3">배포 버전</div>
          <div v-if="settings.targetVersion" class="mono whitespace-nowrap text-2xl">{{ settings.targetVersion }}</div>
          <div v-else class="whitespace-nowrap text-2xl text-ink-3">지정 안 됨</div>
        </div>
        <div class="min-w-0">
          <div class="text-xs text-ink-3">적용된 Agent</div>
          <template v-if="rollout && !rolloutError">
            <div class="mono whitespace-nowrap text-lg">{{ rollout.onTarget }} / {{ rollout.live }}</div>
            <div class="mt-1.5 h-1.5 overflow-hidden rounded-sm bg-surface-2" role="img" :aria-label="`${rollout.onTarget} / ${rollout.live}`">
              <div class="h-full bg-accent" :style="{ width: `${percent}%` }" />
            </div>
          </template>
          <div v-else class="mono text-lg text-ink-3">—</div>
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
        <div class="border-b border-line px-3 pt-3">
          <FilterBar :count="releasesTotal" unit="개">
            <SearchInput v-model="releaseQ" placeholder="버전, 릴리스 노트" />
            <SelectFilter v-model="releaseFilters.source" label="출처" :options="sourceOptions" />
            <label class="inline-flex items-center gap-1.5 text-sm">
              <input v-model="releaseFilters.verified" type="checkbox" class="accent-(--accent)" /> 검증된 것만
            </label>
          </FilterBar>
        </div>
        <LoadError v-if="releasesError" :error="releasesError" @retry="refreshReleases" />
        <DataTable
          v-else
          v-model:sort="releaseSort"
          v-model:page="releasePage"
          v-model:size="releaseSize"
          :columns="releaseColumns"
          :rows="releases"
          :total="releasesTotal"
          :row-key="(r) => r.version"
          :loading="releasesPending"
        >
          <template #cell-version="{ row }">
            <span class="mono whitespace-nowrap font-medium">{{ row.version }}</span>
            <StatusBadge v-if="row.version === targetVersion" class="ml-2" tone="info" label="배포 중" />
          </template>
          <template #cell-publishedAt="{ row }"><span class="whitespace-nowrap">{{ formatDate(row.publishedAt) }}</span></template>
          <template #cell-source="{ row }">{{ sourceLabel[row.source] }}</template>
          <template #cell-platforms="{ row }">
            <span v-if="row.platforms.length" class="mono text-xs">{{ row.platforms.join(', ') }}</span>
            <span v-else class="text-ink-3">—</span>
          </template>
          <template #cell-verified="{ row }">
            <StatusBadge :tone="row.verified ? 'ok' : 'danger'" :label="row.verified ? '검증됨' : '검증 실패'" />
          </template>
        </DataTable>
      </Panel>
    </div>

    <div class="mt-4">
      <Panel title="미적용 에이전트" flush>
        <LoadError v-if="outdatedError" :error="outdatedError" @retry="refreshOutdated" />
        <DataTable
          v-else
          v-model:sort="outdatedSort"
          v-model:page="outdatedPage"
          v-model:size="outdatedSize"
          :columns="outdatedColumns"
          :rows="outdated"
          :total="outdatedTotal"
          :row-key="(a) => a.id"
          :row-to="(a) => `/agents/${a.id}`"
          :loading="outdatedPending"
        >
          <template #cell-hostname="{ row }">
            <NuxtLink :to="`/agents/${row.id}`" class="font-medium hover:underline">{{ row.hostname }}</NuxtLink>
          </template>
          <template #cell-version="{ row }"><span class="mono whitespace-nowrap">{{ row.version }}</span></template>
          <template #cell-updateState="{ row }">
            <StatusBadge :tone="updateStateTone[row.updateState]" :label="updateStateLabel[row.updateState]" />
            <div v-if="row.updateMessage" class="mt-0.5 text-xs text-ink-2">{{ row.updateMessage }}</div>
          </template>
          <template #cell-lastSeen="{ row }"><TimeAgo :at="row.lastSeen" class="whitespace-nowrap text-ink-2" /></template>
        </DataTable>
      </Panel>
    </div>

    <AppModal v-model:open="uploadOpen" title="릴리스 업로드">
      <form id="release-form" class="grid grid-cols-1 gap-3" @submit.prevent="submitUpload">
        <FormField label="릴리스 파일" hint="bomcensus-<버전>.tar">
          <input type="file" accept=".tar,application/x-tar" class="input w-full" @change="onFile" />
        </FormField>
        <p v-if="uploadError" class="note note-danger" role="alert">{{ uploadError }}</p>
      </form>
      <template #footer>
        <AppButton @click="uploadOpen = false">취소</AppButton>
        <AppButton type="submit" form="release-form" variant="primary" :disabled="!uploadFile || uploadBusy">검증 후 등록</AppButton>
      </template>
    </AppModal>

    <AppModal v-model:open="changeOpen" title="배포 버전 변경">
      <form id="rollout-form" class="grid grid-cols-1 gap-3" @submit.prevent="saveChange">
        <FormField label="배포 버전" hint="서명 검증을 통과한 릴리스만 고를 수 있습니다">
          <select v-model="change.version" class="select mono w-full">
            <option value="">없음</option>
            <option v-for="r in verifiedReleases" :key="r.version" :value="r.version">{{ r.version }}</option>
          </select>
        </FormField>
        <FormField label="확인 주기 (분)">
          <input v-model.number="change.interval" type="number" min="1" max="10080" step="1" class="input w-full" />
        </FormField>
        <p v-if="!change.version" class="note note-warn">배포 버전이 없으면 Agent에 업데이트를 배포하지 않습니다.</p>
        <p v-if="downgradeCount > 0" class="note note-warn">
          선택한 버전보다 높은 버전을 쓰는 Agent가 {{ downgradeCount }}개 있습니다. Agent는 낮은 버전으로 내려가지 않습니다.
        </p>
        <p v-if="change.error" class="note note-danger" role="alert">{{ change.error }}</p>
      </form>
      <template #footer>
        <AppButton @click="changeOpen = false">취소</AppButton>
        <AppButton type="submit" form="rollout-form" variant="primary" :disabled="changeBusy">저장</AppButton>
      </template>
    </AppModal>
  </div>
</template>
