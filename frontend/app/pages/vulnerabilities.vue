<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { Exposure, ExposureCounts, Severity, VulnLocation } from '~/types'
import {
  getVulnerability,
  getVulnerabilitySummary,
  getVulnerableComponent,
  listVulnerabilities,
  listVulnerableComponents,
} from '~/api'

useHead({ title: '취약점 · bomcensus' })

const route = useRoute()
const router = useRouter()

type View = 'cve' | 'component'
const view = computed<View>(() => (route.query.view === 'component' ? 'component' : 'cve'))
const selected = computed(() => (typeof route.query.id === 'string' ? route.query.id : ''))

function go(v: View, id = '') {
  router.replace({ query: { ...route.query, view: v, id: id || undefined } })
}

// ── Filters ───────────────────────────────────────────

const q = ref('')
const severity = ref('')
const exposure = ref('')
const kevOnly = ref(false)
// The search goes to the server once typing pauses.
const qDebounced = ref('')
let qTimer: ReturnType<typeof setTimeout> | undefined
watch(q, (v) => {
  clearTimeout(qTimer)
  qTimer = setTimeout(() => (qDebounced.value = v.trim()), 300)
})

const filters = computed(() => ({
  q: qDebounced.value || undefined,
  severity: (severity.value || undefined) as Severity | undefined,
  exposure: (exposure.value || undefined) as Exposure | undefined,
  kev: kevOnly.value ? true : undefined,
  limit: 500,
}))

const severityOptions = (['critical', 'high', 'medium', 'low'] as const).map((s) => ({ value: s, label: severityLabel[s] }))
const exposureOptions = (['listening', 'running', 'installed', 'unknown'] as const).map((e) => ({ value: e, label: exposureLabel[e] }))

const { data: summary } = useLoad('vulns:summary', getVulnerabilitySummary)

const listKey = computed(() => `vulns:${view.value}:${JSON.stringify(filters.value)}`)
const { data: cveList, pending: cvesPending, error: cvesError, refresh: refreshCves } = useLoad(
  () => `${listKey.value}:cves`,
  () => (view.value === 'cve' ? listVulnerabilities(filters.value) : Promise.resolve(undefined)),
)
const { data: compList, pending: compsPending, error: compsError, refresh: refreshComps } = useLoad(
  () => `${listKey.value}:components`,
  () => (view.value === 'component' ? listVulnerableComponents(filters.value) : Promise.resolve(undefined)),
)

// The first item is shown when nothing is selected.
const current = computed(() => {
  if (selected.value) return selected.value
  if (view.value === 'cve') return cveList.value?.items[0]?.vulnId ?? ''
  return compList.value?.items[0]?.componentId ?? ''
})

const { data: cveDetail, error: cveError, refresh: refreshCve } = useLoad(
  () => `vulns:cve:${view.value === 'cve' ? current.value : ''}`,
  () => (view.value === 'cve' && current.value ? getVulnerability(current.value) : Promise.resolve(undefined)),
)
const { data: compDetail, error: compError, refresh: refreshComp } = useLoad(
  () => `vulns:component:${view.value === 'component' ? current.value : ''}`,
  () => (view.value === 'component' && current.value ? getVulnerableComponent(current.value) : Promise.resolve(undefined)),
)

// ── Formatting ────────────────────────────────────────

const severityText: Record<Severity, string> = {
  critical: 'text-critical',
  high: 'text-high',
  medium: 'text-medium',
  low: 'text-low',
  none: 'text-ink-3',
}

function mix(c: ExposureCounts): string {
  return (['listening', 'running', 'installed', 'unknown'] as const)
    .filter((e) => c[e] > 0)
    .map((e) => `${exposureLabel[e]} ${c[e]}`)
    .join(' · ')
}

// Advisory texts are wrapped at a fixed width; blank lines separate paragraphs.
const paragraphs = (text: string) =>
  text
    .split(/\n\s*\n/)
    .map((p) => p.replace(/\s*\n\s*/g, ' ').trim())
    .filter(Boolean)

const pct = (n?: number) => (n === undefined ? '—' : `${(n * 100).toFixed(1)}%`)

function where(l: VulnLocation): string {
  const kind = l.assetKind === 'workload' ? '워크로드' : '호스트'
  if (!l.container) return kind
  return `${kind} · ${l.container} · ${findingLayerLabel[l.layer]}`
}

function processText(l: VulnLocation): string {
  const p = l.processes[0]
  if (!p) return ''
  const exe = p.exe.split('/').pop() ?? p.exe
  const more = l.processes.length > 1 ? ` 외 ${l.processes.length - 1}` : ''
  return `${exe} · pid ${p.pid}${p.ports.length ? ` · ${p.ports.join(', ')}` : ''}${more}`
}

// Long location lists show the first rows; the rest open on demand.
const locationLimit = 10
const showAllLocations = ref(false)
watch(current, () => (showAllLocations.value = false))
const visible = (ls: VulnLocation[]) => (showAllLocations.value ? ls : ls.slice(0, locationLimit))

const tabs = computed(() => [
  { key: 'cve', label: 'CVE', count: summary.value?.totals.cves },
  { key: 'component', label: '컴포넌트', count: summary.value?.totals.components },
])
const tabModel = computed({ get: () => view.value as string, set: (v: string) => go(v as View) })
</script>

<template>
  <div>
    <PageHeader title="취약점">
      <template #subtitle>
        <template v-if="summary?.revision !== undefined">취약점 데이터 rev {{ summary.revision }} · {{ formatDateTime(summary.checkedAt) }}</template>
        <template v-else-if="summary">feed 서버에 아직 연결하지 않았습니다. <NuxtLink to="/settings/feed" class="link">설정 › 취약점 피드</NuxtLink></template>
      </template>
    </PageHeader>

    <AppTabs v-model="tabModel" :tabs="tabs" class="mb-3" />

    <FilterBar :count="view === 'cve' ? cveList?.total : compList?.total" unit="개">
      <SearchInput v-model="q" :placeholder="view === 'cve' ? 'CVE, 요약, 컴포넌트' : '컴포넌트, 버전, CVE'" />
      <SelectFilter v-model="severity" label="심각도" :options="severityOptions" />
      <SelectFilter v-model="exposure" label="영향도" :options="exposureOptions" />
      <label class="inline-flex items-center gap-1.5 text-sm">
        <input v-model="kevOnly" type="checkbox" class="size-[15px] accent-(--accent)" /> KEV만
      </label>
    </FilterBar>

    <div class="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,22rem)_minmax(0,1fr)]">
      <!-- List -->
      <Panel flush class="min-w-0 self-start">
        <template v-if="view === 'cve'">
          <LoadError v-if="cvesError" :error="cvesError" @retry="refreshCves" />
          <LoadingText v-else-if="cvesPending && !cveList" class="p-3.5" />
          <p v-else-if="!cveList?.items.length" class="px-3.5 py-3 text-sm text-ink-2">열린 취약점이 없습니다.</p>
          <ul v-else class="max-h-[70vh] overflow-y-auto">
            <li v-for="v in cveList.items" :key="v.vulnId">
              <button
                type="button"
                class="block w-full border-b border-line px-3.5 py-2.5 text-left hover:bg-surface-2"
                :class="v.vulnId === current ? 'bg-accent-soft' : ''"
                :aria-current="v.vulnId === current ? 'true' : undefined"
                @click="go('cve', v.vulnId)"
              >
                <span class="flex items-center gap-1.5">
                  <span v-if="v.severity" class="text-[11px]" :class="severityText[v.severity]">■</span>
                  <span class="mono text-sm font-medium">{{ v.vulnId }}</span>
                  <StatusBadge v-if="v.kev" tone="danger" label="KEV" />
                  <span class="mono ml-auto text-xs text-ink-2">{{ v.score !== undefined ? v.score.toFixed(1) : '—' }}</span>
                </span>
                <span v-if="v.summary" class="mt-0.5 line-clamp-1 block text-xs text-ink-2">{{ v.summary }}</span>
                <span class="mt-1 flex items-center gap-2 text-xs text-ink-3">
                  <ExposureMeter :exposure="v.exposure" />
                  <span>자산 {{ v.assets }} · EPSS {{ pct(v.epss) }}</span>
                </span>
              </button>
            </li>
          </ul>
          <p v-if="cveList && cveList.total > cveList.items.length" class="px-3.5 py-2 text-xs text-ink-3">
            {{ cveList.items.length }}개만 보입니다. 검색이나 필터로 좁히세요.
          </p>
        </template>

        <template v-else>
          <LoadError v-if="compsError" :error="compsError" @retry="refreshComps" />
          <LoadingText v-else-if="compsPending && !compList" class="p-3.5" />
          <p v-else-if="!compList?.items.length" class="px-3.5 py-3 text-sm text-ink-2">취약한 컴포넌트가 없습니다.</p>
          <ul v-else class="max-h-[70vh] overflow-y-auto">
            <li v-for="c in compList.items" :key="c.componentId">
              <button
                type="button"
                class="block w-full border-b border-line px-3.5 py-2.5 text-left hover:bg-surface-2"
                :class="c.componentId === current ? 'bg-accent-soft' : ''"
                :aria-current="c.componentId === current ? 'true' : undefined"
                @click="go('component', c.componentId)"
              >
                <span class="flex items-center gap-1.5">
                  <span v-if="c.severity" class="text-[11px]" :class="severityText[c.severity]">■</span>
                  <span class="truncate text-sm font-medium">{{ c.name }}</span>
                  <StatusBadge v-if="c.kev" tone="danger" label="KEV" />
                  <span class="mono ml-auto text-xs text-ink-2">{{ c.score !== undefined ? c.score.toFixed(1) : '—' }}</span>
                </span>
                <span class="mono mt-0.5 block truncate text-xs text-ink-2">
                  {{ c.version }}<template v-if="c.fixedVersion"> → {{ c.fixedVersion }}</template>
                </span>
                <span class="mt-1 flex items-center gap-2 text-xs text-ink-3">
                  <ExposureMeter :exposure="c.exposure" />
                  <span>CVE {{ c.cves }} · 자산 {{ c.assets }}</span>
                </span>
              </button>
            </li>
          </ul>
          <p v-if="compList && compList.total > compList.items.length" class="px-3.5 py-2 text-xs text-ink-3">
            {{ compList.items.length }}개만 보입니다. 검색이나 필터로 좁히세요.
          </p>
        </template>
      </Panel>

      <!-- Detail -->
      <div class="min-w-0">
        <template v-if="view === 'cve'">
          <Panel v-if="cveError"><LoadError :error="cveError" @retry="refreshCve" /></Panel>
          <Panel v-else-if="!current"><p class="text-sm text-ink-2">왼쪽에서 취약점을 고르세요.</p></Panel>
          <Panel v-else-if="!cveDetail || cveDetail.vulnerability.vulnId !== current"><LoadingText /></Panel>
          <div v-else class="grid grid-cols-1 gap-4">
            <Panel>
              <div class="flex flex-wrap items-center gap-2">
                <SeverityBadge :severity="cveDetail.vulnerability.severity" :score="cveDetail.vulnerability.score" />
                <StatusBadge v-if="cveDetail.vulnerability.kev" tone="danger" :label="`KEV · ${cveDetail.vulnerability.kev.dateAdded}`" />
                <span class="text-xs text-ink-2">EPSS {{ pct(cveDetail.vulnerability.epss) }}</span>
                <span v-for="c in cveDetail.vulnerability.cvss.slice(0, 1)" :key="c.vector" class="mono break-all text-xs text-ink-3">{{ c.vector }}</span>
              </div>
              <h2 class="mono mt-2 text-lg font-semibold">{{ cveDetail.vulnerability.vulnId }}</h2>
              <p v-if="cveDetail.vulnerability.summary" class="mt-1 text-sm font-medium">{{ cveDetail.vulnerability.summary }}</p>
              <div v-if="cveDetail.vulnerability.description" class="mt-1 grid max-w-[90ch] gap-2 text-sm text-ink-2">
                <p v-for="(para, i) in paragraphs(cveDetail.vulnerability.description)" :key="i">{{ para }}</p>
              </div>
              <p v-if="cveDetail.vulnerability.kev?.requiredAction" class="note note-danger mt-3">
                CISA 조치: {{ cveDetail.vulnerability.kev.requiredAction }}
              </p>
              <dl class="kv mt-3">
                <template v-if="cveDetail.vulnerability.aliases.length">
                  <dt>별칭</dt>
                  <dd class="mono text-xs">{{ cveDetail.vulnerability.aliases.join(', ') }}</dd>
                </template>
                <template v-if="cveDetail.vulnerability.cwes.length">
                  <dt>CWE</dt>
                  <dd class="mono text-xs">{{ cveDetail.vulnerability.cwes.join(', ') }}</dd>
                </template>
                <template v-if="cveDetail.vulnerability.published">
                  <dt>공개</dt>
                  <dd>{{ formatDate(cveDetail.vulnerability.published) }}</dd>
                </template>
                <template v-if="cveDetail.vulnerability.references.length">
                  <dt>참고</dt>
                  <dd class="grid gap-0.5">
                    <a
                      v-for="r in cveDetail.vulnerability.references.slice(0, 5)"
                      :key="r"
                      :href="r"
                      target="_blank"
                      rel="noopener noreferrer"
                      class="link break-all text-xs"
                    >{{ r }}</a>
                  </dd>
                </template>
              </dl>
            </Panel>

            <Panel title="조치" flush>
              <table class="w-full border-collapse text-sm">
                <thead>
                  <tr class="border-b border-line text-left text-xs text-ink-3">
                    <th class="py-2 pl-3.5 font-normal">컴포넌트</th>
                    <th class="px-3 py-2 font-normal">수정</th>
                    <th class="hidden px-3 py-2 font-normal md:table-cell">근거</th>
                    <th class="px-3 py-2 font-normal">영향도</th>
                    <th class="py-2 pl-3 pr-3.5 text-right font-normal">자산</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="c in cveDetail.components" :key="c.componentId" class="border-b border-line align-top last:border-b-0">
                    <td class="py-2 pl-3.5">
                      <NuxtLink :to="`/vulnerabilities?view=component&id=${c.componentId}`" class="font-medium hover:underline">{{ c.name }}</NuxtLink>
                      <span class="mono ml-1 text-xs text-ink-2">{{ c.version }}</span>
                    </td>
                    <td class="px-3 py-2">
                      <span v-if="c.fixedVersion" class="mono whitespace-nowrap text-xs">→ {{ c.fixedVersion }}</span>
                      <span v-else class="text-xs text-ink-3">{{ fixStateLabel[c.fixState] }}</span>
                    </td>
                    <td class="hidden px-3 py-2 text-xs text-ink-2 md:table-cell">
                      {{ c.method === 'cpe' ? `CPE ${c.cpeMatch === 'exact' ? '일치' : '범위'}${c.rangeSource ? ` · ${c.rangeSource}` : ''}` : c.advisories.map((a) => a.id).join(', ') }}
                      <div v-if="c.platforms.length" class="text-ink-3">조건: {{ c.platforms.join(', ') }}</div>
                    </td>
                    <td class="px-3 py-2"><ExposureMeter :exposure="c.exposure" /></td>
                    <td class="mono py-2 pl-3 pr-3.5 text-right">{{ c.assets }}</td>
                  </tr>
                </tbody>
              </table>
            </Panel>

            <Panel title="위치" flush>
              <VulnLocations :items="visible(cveDetail.locations)" :where="where" :process-text="processText" />
              <button
                v-if="cveDetail.locations.length > locationLimit && !showAllLocations"
                type="button"
                class="link px-3.5 py-2.5 text-sm"
                @click="showAllLocations = true"
              >
                + {{ cveDetail.locations.length - locationLimit }}개 더 보기
              </button>
            </Panel>
          </div>
        </template>

        <template v-else>
          <Panel v-if="compError"><LoadError :error="compError" @retry="refreshComp" /></Panel>
          <Panel v-else-if="!current"><p class="text-sm text-ink-2">왼쪽에서 컴포넌트를 고르세요.</p></Panel>
          <Panel v-else-if="!compDetail || compDetail.component.componentId !== current"><LoadingText /></Panel>
          <div v-else class="grid grid-cols-1 gap-4">
            <Panel>
              <div class="flex flex-wrap items-center gap-2">
                <SeverityBadge :severity="compDetail.component.severity" :score="compDetail.component.score" />
                <span class="text-xs text-ink-2">{{ componentTypeLabel[compDetail.component.type] ?? compDetail.component.type }}</span>
              </div>
              <h2 class="mt-2 text-lg font-semibold">
                <NuxtLink :to="`/components/${compDetail.component.componentId}`" class="hover:underline">{{ compDetail.component.name }}</NuxtLink>
                <span class="mono ml-2 text-base font-normal text-ink-2">{{ compDetail.component.version }}</span>
              </h2>
              <p class="mt-1 text-sm">
                <template v-if="compDetail.component.fixedVersion">
                  <span class="mono font-medium">→ {{ compDetail.component.fixedVersion }}</span>
                  <span class="text-ink-2"> 로 올리면 CVE {{ compDetail.component.cves - (compDetail.component.unfixed ?? 0) }}개가 해결됩니다.</span>
                  <span v-if="compDetail.component.unfixed" class="text-ink-2"> 수정 버전이 없는 CVE {{ compDetail.component.unfixed }}개가 남습니다.</span>
                </template>
                <span v-else class="text-ink-2">수정 버전이 아직 없습니다.</span>
              </p>
              <dl class="kv mt-3">
                <dt>CVE</dt>
                <dd>
                  <span class="mono">{{ compDetail.component.cves }}</span>
                  <span class="ml-2 inline-flex gap-1.5">
                    <span
                      v-for="s in (['critical', 'high', 'medium', 'low'] as const).filter((s) => compDetail!.component.severityCounts[s] > 0)"
                      :key="s"
                      class="text-xs"
                      :class="severityText[s]"
                    >{{ severityLabel[s] }} {{ compDetail.component.severityCounts[s] }}</span>
                  </span>
                  <StatusBadge v-if="compDetail.component.kev" class="ml-1" tone="danger" :label="`KEV ${compDetail.component.kev}`" />
                </dd>
                <dt>영향도</dt>
                <dd>{{ mix(compDetail.component.exposureCounts) }}</dd>
                <dt>자산</dt>
                <dd class="mono">{{ compDetail.component.assets }}</dd>
                <template v-if="compDetail.component.processes.length">
                  <dt>프로세스</dt>
                  <dd class="mono text-xs">{{ compDetail.component.processes.map((p) => `${p.exe.split('/').pop()} ×${p.count}`).join(' · ') }}</dd>
                </template>
                <template v-if="compDetail.component.purl">
                  <dt>purl</dt>
                  <dd class="mono break-all text-xs">{{ compDetail.component.purl }}</dd>
                </template>
              </dl>
            </Panel>

            <Panel title="CVE" flush>
              <table class="w-full border-collapse text-sm">
                <thead>
                  <tr class="border-b border-line text-left text-xs text-ink-3">
                    <th class="py-2 pl-3.5 font-normal">CVSS</th>
                    <th class="px-3 py-2 font-normal">CVE</th>
                    <th class="px-3 py-2 font-normal">수정</th>
                    <th class="px-3 py-2 font-normal">영향도</th>
                    <th class="hidden py-2 pl-3 pr-3.5 font-normal md:table-cell">프로세스</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="v in compDetail.cves" :key="v.vulnId" class="border-b border-line align-top last:border-b-0">
                    <td class="py-2 pl-3.5">
                      <span class="inline-flex items-center gap-1.5 whitespace-nowrap">
                        <span v-if="v.severity" class="text-[11px]" :class="severityText[v.severity]">■</span>
                        <span class="mono">{{ v.score !== undefined ? v.score.toFixed(1) : '—' }}</span>
                      </span>
                    </td>
                    <td class="px-3 py-2">
                      <NuxtLink :to="`/vulnerabilities?view=cve&id=${encodeURIComponent(v.vulnId)}`" class="mono font-medium hover:underline">{{ v.vulnId }}</NuxtLink>
                      <StatusBadge v-if="v.kev" class="ml-1" tone="danger" label="KEV" />
                      <div v-if="v.summary" class="max-w-[52ch] text-xs text-ink-2">{{ v.summary }}</div>
                    </td>
                    <td class="px-3 py-2">
                      <span v-if="v.fixedVersion" class="mono whitespace-nowrap text-xs">→ {{ v.fixedVersion }}</span>
                      <span v-else-if="v.fixState" class="text-xs text-ink-3">{{ fixStateLabel[v.fixState] }}</span>
                    </td>
                    <td class="px-3 py-2"><ExposureMeter :exposure="v.exposure" /></td>
                    <td class="mono hidden py-2 pl-3 pr-3.5 text-xs text-ink-2 md:table-cell">
                      <template v-if="v.processes?.length">
                        {{ v.processes[0]!.exe.split('/').pop() }}<template v-if="v.processes[0]!.ports.length"> · {{ v.processes[0]!.ports.join(', ') }}</template>
                      </template>
                    </td>
                  </tr>
                </tbody>
              </table>
            </Panel>

            <Panel title="위치" flush>
              <VulnLocations :items="visible(compDetail.locations)" :where="where" :process-text="processText" />
              <button
                v-if="compDetail.locations.length > locationLimit && !showAllLocations"
                type="button"
                class="link px-3.5 py-2.5 text-sm"
                @click="showAllLocations = true"
              >
                + {{ compDetail.locations.length - locationLimit }}개 더 보기
              </button>
            </Panel>
          </div>
        </template>
      </div>
    </div>
  </div>
</template>
