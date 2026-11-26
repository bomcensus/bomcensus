<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { IntegrityGroup, IntegrityStatus } from '~/types'
import { getIntegritySummary, listIntegrityFileNodes, listIntegrityFiles } from '~/api'

useHead({ title: '파일 무결성 · bomcensus' })

const route = useRoute()
const router = useRouter()

type View = 'files' | 'rules'
const view = computed<View>(() => (route.query.view === 'rules' ? 'rules' : 'files'))
const tabModel = computed({
  get: () => view.value as string,
  set: (v: string) => router.replace({ query: { ...route.query, view: v === 'files' ? undefined : v, key: undefined } }),
})

// ── Filters ───────────────────────────────────────────

const q = ref('')
const status = ref('')
const qDebounced = ref('')
let qTimer: ReturnType<typeof setTimeout> | undefined
watch(q, (v) => {
  clearTimeout(qTimer)
  qTimer = setTimeout(() => (qDebounced.value = v.trim()), 300)
})
const statusOptions = (['modified', 'missing'] as const).map((s) => ({ value: s, label: integrityStatusLabel[s] }))
// Paging of the list. Any other change starts over from the first page.
const page = ref(0)
const size = ref(50)
const conditions = computed(() => ({
  q: qDebounced.value || undefined,
  status: (status.value || undefined) as IntegrityStatus | undefined,
}))
watch([() => JSON.stringify(conditions.value), size], () => (page.value = 0))
const filters = computed(() => ({ ...conditions.value, limit: size.value, offset: page.value * size.value }))

const { data: summary, refresh: refreshSummary } = useLoad('integrity:summary', getIntegritySummary)
const { data: list, pending, error, refresh: refreshList } = useLoad(
  () => `integrity:files:${JSON.stringify(filters.value)}`,
  () => (view.value === 'files' ? listIntegrityFiles(filters.value) : Promise.resolve(undefined)),
)
// Allowing files can empty the last page; go back to the page that is now last.
watch(list, (l) => {
  if (l && !l.items.length && page.value > 0) page.value = Math.max(0, Math.ceil(l.total / size.value) - 1)
})

// A group is selected by path, status and content.
const keyOf = (g: IntegrityGroup) => `${g.status}|${g.actualSha256 ?? ''}|${g.path}`
const selectedKey = computed(() => (typeof route.query.key === 'string' ? route.query.key : ''))
const current = computed(() => {
  const items = list.value?.items ?? []
  return items.find((g) => keyOf(g) === selectedKey.value) ?? items[0]
})
function select(g: IntegrityGroup) {
  router.replace({ query: { ...route.query, key: keyOf(g) } })
}

const { data: nodes, error: nodesError, refresh: refreshNodes } = useLoad(
  () => `integrity:nodes:${current.value ? keyOf(current.value) : ''}`,
  () =>
    current.value
      ? listIntegrityFileNodes({ path: current.value.path, status: current.value.status, sha256: current.value.actualSha256 ?? '', limit: 500 })
      : Promise.resolve(undefined),
)

// ── Allow ─────────────────────────────────────────────

const allowOpen = ref(false)
const allowNodes = computed(() => (nodes.value?.items ?? []).map((n) => ({ assetId: n.assetId, assetName: n.assetName })))

async function changed() {
  await Promise.all([refreshSummary(), refreshList(), refreshNodes()])
}

const tabs = computed(() => [
  { key: 'files', label: '검사 결과', count: summary.value?.groups },
  { key: 'rules', label: '허용 규칙', count: summary.value?.rules },
])
const short = (h: string) => `${h.slice(0, 12)}…`
</script>

<template>
  <div>
    <PageHeader title="파일 무결성" subtitle="패키지 DB의 해시와 다른 파일입니다. 허용한 항목은 빠집니다." />

    <div class="mb-4 grid grid-cols-2 gap-2 lg:grid-cols-4">
      <StatTile label="확인 필요한 변경" :value="summary?.groups ?? '—'" :tone="summary?.groups ? 'danger' : 'neutral'" />
      <StatTile label="영향받은 노드" :value="summary?.assets ?? '—'" />
      <StatTile label="최근 회차 완료 노드" :value="summary ? `${summary.completed} / ${summary.tracked}` : '—'" />
      <StatTile label="허용 규칙" :value="summary?.rules ?? '—'" />
    </div>

    <AppTabs v-model="tabModel" :tabs="tabs" class="mb-3" />

    <IntegrityRuleList v-if="view === 'rules'" @changed="changed" />

    <template v-else>
      <FilterBar :count="list?.total" unit="개">
        <SearchInput v-model="q" placeholder="경로, 패키지, 호스트" />
        <SelectFilter v-model="status" label="상태" :options="statusOptions" />
      </FilterBar>

      <div class="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,28rem)_minmax(0,1fr)]">
        <Panel flush class="min-w-0 self-start">
          <LoadError v-if="error" :error="error" @retry="refreshList" />
          <LoadingText v-else-if="pending && !list" class="p-3.5" />
          <p v-else-if="!list?.items.length" class="px-3.5 py-3 text-sm text-ink-2">확인할 변경이 없습니다.</p>
          <ul v-else class="max-h-[70vh] overflow-y-auto">
            <li v-for="g in list.items" :key="keyOf(g)">
              <button
                type="button"
                class="grid w-full grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-2.5 border-b border-line px-3.5 py-2.5 text-left hover:bg-surface-2"
                :class="current && keyOf(g) === keyOf(current) ? 'bg-accent-soft' : ''"
                :aria-current="current && keyOf(g) === keyOf(current) ? 'true' : undefined"
                @click="select(g)"
              >
                <StatusBadge :tone="integrityStatusTone[g.status]" :label="integrityStatusLabel[g.status]" />
                <span class="min-w-0">
                  <span class="mono block truncate text-sm" :title="g.path">{{ g.path }}</span>
                  <span class="block truncate text-xs text-ink-3" :title="[`${g.package} ${g.version}`, g.actualSha256].filter(Boolean).join('\n')">
                    {{ g.package }} {{ g.version }}<template v-if="g.actualSha256"> · <span class="mono">{{ short(g.actualSha256) }}</span></template>
                  </span>
                </span>
                <span class="mono text-sm font-semibold">{{ g.assets }}</span>
              </button>
            </li>
          </ul>
          <TablePager v-if="list && (list.total > size || page > 0)" v-model:page="page" v-model:size="size" :total="list.total" compact />
        </Panel>

        <div class="min-w-0">
          <Panel v-if="!current"><p class="text-sm text-ink-2">왼쪽에서 항목을 고르세요.</p></Panel>
          <div v-else class="grid grid-cols-1 gap-4">
            <Panel>
              <StatusBadge :tone="integrityStatusTone[current.status]" :label="integrityStatusLabel[current.status]" />
              <h2 class="mono mt-2 break-all text-base font-semibold">{{ current.path }}</h2>
              <p class="mt-1 text-xs text-ink-2">{{ current.pkgType }} · {{ current.package }} {{ current.version }}</p>
              <dl class="kv mt-3">
                <dt>기대값 ({{ integrityAlgoLabel[current.algo] ?? current.algo }})</dt>
                <dd class="mono break-all text-xs">{{ current.expected }}</dd>
                <dt>실제값 ({{ integrityAlgoLabel[current.algo] ?? current.algo }})</dt>
                <dd class="mono break-all text-xs text-critical">{{ current.status === 'missing' ? '파일 없음' : current.actual }}</dd>
                <template v-if="current.status === 'modified' && current.algo !== 'sha256'">
                  <dt>허용 기준 SHA-256</dt>
                  <dd class="mono break-all text-xs">{{ current.actualSha256 }}</dd>
                </template>
                <dt>처음 발견</dt>
                <dd>{{ formatDateTime(current.firstSeen) }}</dd>
              </dl>
              <div class="mt-3 flex flex-wrap gap-2">
                <AppButton variant="primary" :disabled="!nodes?.items.length" @click="allowOpen = true">허용…</AppButton>
              </div>
              <p class="mt-2 text-xs text-ink-3">같은 경로라도 해시가 다르면 다른 항목입니다.</p>
            </Panel>

            <Panel title="노드" flush>
              <LoadError v-if="nodesError" :error="nodesError" @retry="refreshNodes" />
              <LoadingText v-else-if="!nodes" class="p-3.5" />
              <div v-else class="overflow-x-auto">
                <table class="w-full min-w-[640px] border-collapse text-sm">
                  <thead>
                    <tr class="border-b border-line text-left text-xs text-ink-3">
                      <th class="py-2 pl-3.5 font-normal">노드</th>
                      <th class="px-3 py-2 font-normal">수집</th>
                      <th class="px-3 py-2 font-normal">버전</th>
                      <th class="px-3 py-2 font-normal">mtime</th>
                      <th class="py-2 pl-3 pr-3.5 font-normal">ctime</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="n in nodes.items" :key="n.id" class="border-b border-line last:border-b-0">
                      <td class="py-2 pl-3.5">
                        <NuxtLink :to="`/assets/${n.assetId}?tab=integrity`" class="mono hover:underline">{{ n.assetName || n.assetId }}</NuxtLink>
                      </td>
                      <td class="px-3 py-2 text-xs">{{ n.collector === 'ssh' ? 'SSH' : '에이전트' }}</td>
                      <td class="mono px-3 py-2 text-xs">{{ n.version }}</td>
                      <td class="px-3 py-2 text-xs">{{ n.mtime ? formatDateTime(n.mtime) : '—' }}</td>
                      <td class="py-2 pl-3 pr-3.5 text-xs">{{ n.ctime ? formatDateTime(n.ctime) : '—' }}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </Panel>
          </div>
        </div>
      </div>
    </template>

    <IntegrityAllowModal
      v-if="current"
      v-model:open="allowOpen"
      :path="current.path"
      :status="current.status"
      :sha256="current.actualSha256"
      :nodes="allowNodes"
      @saved="changed"
    />
  </div>
</template>
