<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { ComponentAssetRow, ComponentVulnerability, DetectMethod } from '~/types'
import type { TableColumn } from '~/types/table'
import type { TriState } from '~/composables/useServerList'
import { getComponent, listComponentAssets, listComponentVulnerabilities, type QueryOf } from '~/api'

const route = useRoute()
// When only the id changes on the same page, NuxtPage recreates it, so the value at setup time is enough
const id = String(route.params.id)

const { data: component, error, refresh } = useLoad(`component:${id}`, () => getComponent(id))
const {
  items: installed,
  total: installedTotal,
  pending: installedPending,
  error: installedError,
  refresh: refreshInstalled,
  q: installedQuery,
  filters: installedFilters,
  sort: installedSort,
  page: installedPage,
  size: installedSize,
} = useServerList(`component:${id}:assets`, (p) => listComponentAssets(id, p as QueryOf<typeof listComponentAssets>), {
  filters: { method: '', inUse: '' as TriState },
  sort: 'asset',
})
const methodOptions = (Object.keys(detectMethodLabel) as DetectMethod[]).map((value) => ({ value, label: detectMethodLabel[value] }))

const {
  data: vulns,
  pending: vulnsPending,
  error: vulnsError,
  refresh: refreshVulns,
} = useLoad(`component:${id}:vulns`, () => listComponentVulnerabilities(id))

useHead({ title: computed(() => `${component.value?.name ?? '컴포넌트'} · bomcensus`) })

const vulnColumns: TableColumn<ComponentVulnerability>[] = [
  { key: 'vulnId', label: '취약점', sortValue: (r) => r.vulnId },
  { key: 'severity', label: '심각도', sortValue: (r) => -(r.score ?? -1) },
  { key: 'kev', label: 'KEV', sortValue: (r) => (r.kev ? 0 : 1), hideBelow: 'sm' },
  { key: 'epss', label: 'EPSS', align: 'right', sortValue: (r) => -(r.epss ?? -1), hideBelow: 'sm' },
  { key: 'fix', label: '수정', sortValue: (r) => r.fixState },
  { key: 'source', label: '근거', hideBelow: 'md' },
]

const matchNote = computed(() => {
  const m = vulns.value?.match
  if (!m) return '아직 feed 서버로 확인하지 않았습니다.'
  if (m.status === 'unsupported') return `feed 서버에 이 컴포넌트의 데이터가 없습니다. 취약점이 없다는 뜻은 아닙니다.${m.reason ? ` (${m.reason})` : ''}`
  if (m.status === 'invalid') return `식별자를 해석하지 못했습니다.${m.reason ? ` (${m.reason})` : ''}`
  return ''
})

const assetColumns: TableColumn<ComponentAssetRow>[] = [
  { key: 'asset', label: '자산', sort: 'asset' },
  { key: 'locations', label: '위치', hideBelow: 'md' },
  { key: 'method', label: '탐지 방법', sort: 'method', hideBelow: 'sm' },
  { key: 'inUse', label: '실행 중', sort: 'inUse', sortDesc: true },
  { key: 'firstSeen', label: '최초 발견', align: 'right', sort: 'firstSeen', sortDesc: true, hideBelow: 'sm' },
  { key: 'raw', label: '출력', align: 'right' },
]

const rawRow = ref<ComponentAssetRow>()
const rawOpen = ref(false)
function showRaw(row: ComponentAssetRow) {
  rawRow.value = row
  rawOpen.value = true
}
</script>

<template>
  <div>
    <template v-if="!component">
      <PageHeader title="컴포넌트" :back="{ to: '/components', label: '컴포넌트' }" />
      <Panel>
        <LoadError v-if="error" :error="error" :back="{ to: '/components', label: '컴포넌트 목록' }" @retry="refresh" />
        <LoadingText v-else />
      </Panel>
    </template>

    <template v-else>
      <PageHeader
        :title="`${component.name} ${versionText(component.version, component.build)}`"
        :subtitle="`${componentTypeLabel[component.type]} · ${originLabel[component.origin]}`"
        :back="{ to: '/components', label: '컴포넌트' }"
      />

      <Panel title="정보">
        <dl class="kv">
          <dt>purl</dt>
          <dd><CopyField :value="component.purl" /></dd>
          <dt>CPE</dt>
          <dd><span v-if="component.cpe" class="mono break-all">{{ component.cpe }}</span><span v-else class="text-ink-3">—</span></dd>
          <template v-if="component.build">
            <dt>빌드</dt>
            <dd><span class="mono">{{ component.build }}</span></dd>
          </template>
          <dt>종류</dt>
          <dd>{{ componentTypeLabel[component.type] }}</dd>
          <dt>출처</dt>
          <dd>{{ originLabel[component.origin] }}</dd>
          <dt>소스 패키지</dt>
          <dd>
            <template v-if="component.sourceName">
              {{ component.sourceName }}
              <span v-if="component.sourceVersion" class="mono whitespace-nowrap text-ink-2">{{ component.sourceVersion }}</span>
            </template>
            <span v-else class="text-ink-3">—</span>
          </dd>
          <dt>배포판</dt>
          <dd>{{ component.distro ?? '—' }}</dd>
          <dt>아키텍처</dt>
          <dd><span class="mono">{{ component.arch ?? '—' }}</span></dd>
          <dt>벤더</dt>
          <dd>{{ component.vendor ?? '—' }}</dd>
        </dl>
      </Panel>

      <div class="mt-4">
        <Panel title="취약점" :description="vulns?.match ? `${formatDateTime(vulns.match.matchedAt)} 확인 · 데이터 리비전 ${vulns.match.revision}${vulns.match.osKey ? ` · ${vulns.match.osKey}` : ''}` : undefined" flush>
          <LoadError v-if="vulnsError" :error="vulnsError" @retry="refreshVulns" />
          <LoadingText v-else-if="vulnsPending && !vulns" class="p-3.5" />
          <p v-else-if="matchNote" class="px-3.5 py-3 text-sm text-ink-2">{{ matchNote }}</p>
          <DataTable
            v-else
            :columns="vulnColumns"
            :rows="vulns?.items ?? []"
            :row-key="(r) => `${r.vulnId}/${r.method}`"
            :page-size="25"
            empty="알려진 취약점이 없습니다"
          >
            <template #cell-vulnId="{ row }">
              <span class="mono whitespace-nowrap font-medium">{{ row.vulnId }}</span>
              <div v-if="row.summary" class="max-w-[48ch] text-xs text-ink-2">{{ row.summary }}</div>
            </template>
            <template #cell-severity="{ row }"><SeverityBadge :severity="row.severity" :score="row.score" /></template>
            <template #cell-kev="{ row }">
              <StatusBadge v-if="row.kev" tone="danger" label="KEV" />
              <span v-else class="text-ink-3">—</span>
            </template>
            <template #cell-epss="{ row }">
              <span v-if="row.epss !== undefined" class="mono whitespace-nowrap">{{ (row.epss * 100).toFixed(1) }}%</span>
              <span v-else class="text-ink-3">—</span>
            </template>
            <template #cell-fix="{ row }">
              <span v-if="fixTarget(row)" class="mono whitespace-nowrap" :title="lastAffectedHint(row)">→ {{ fixTarget(row) }}</span>
              <span v-else class="whitespace-nowrap text-ink-2">{{ fixStateLabel[row.fixState] }}</span>
            </template>
            <template #cell-source="{ row }">
              <span class="text-xs text-ink-2">
                {{ row.method === 'cpe' ? `CPE ${row.cpeMatch === 'exact' ? '일치' : '범위'}${row.rangeSource ? ` · ${row.rangeSource}` : ''}` : row.advisories.map((a) => a.id).join(', ') }}
              </span>
              <div v-if="row.buildUnknown" class="mt-0.5" :title="buildUnknownHint"><StatusBadge tone="warn" label="빌드 미확인" /></div>
              <div v-if="row.platforms.length" class="text-xs text-ink-3">조건: {{ row.platforms.join(', ') }}</div>
              <div v-if="row.affectedRanges?.length" class="text-xs text-ink-3">취약 범위: <span class="mono">{{ row.affectedRanges.map(rangeText).join(', ') }}</span></div>
            </template>
          </DataTable>
        </Panel>
      </div>

      <div class="mt-4">
        <Panel title="설치 자산" flush>
          <div class="px-3.5 pt-3">
            <FilterBar :count="installedTotal" unit="곳">
              <SearchInput v-model="installedQuery" placeholder="자산, 컨테이너, 경로" />
              <SelectFilter v-model="installedFilters.method" label="탐지 방법" :options="methodOptions" />
              <SelectFilter v-model="installedFilters.inUse" label="실행" :options="triStateOptions('실행 중', '실행 안 함')" />
            </FilterBar>
          </div>
          <LoadError v-if="installedError" :error="installedError" @retry="refreshInstalled" />
          <DataTable
            v-else
            v-model:sort="installedSort"
            v-model:page="installedPage"
            v-model:size="installedSize"
            :columns="assetColumns"
            :rows="installed"
            :total="installedTotal"
            :row-key="(r) => `${r.assetId}/${r.container ?? ''}`"
            :row-to="(r) => `/assets/${r.assetId}`"
            :loading="installedPending"
          >
            <template #cell-asset="{ row }">
              <NuxtLink :to="`/assets/${row.assetId}`" class="font-medium hover:underline">{{ row.asset.name }}</NuxtLink>
              <div v-if="row.container" class="mono whitespace-nowrap text-xs text-ink-3">
                {{ row.container }}<template v-if="row.layer"> · {{ layerLabel[row.layer] }}</template>
              </div>
            </template>
            <template #cell-locations="{ row }">
              <span v-if="row.locations.length" :title="row.locations.join('\n')">
                <span class="mono break-all text-xs">{{ row.locations[0] }}</span>
                <span v-if="row.locations.length > 1" class="text-xs text-ink-3"> 외 {{ row.locations.length - 1 }}</span>
              </span>
              <span v-else class="text-ink-3">—</span>
            </template>
            <template #cell-method="{ row }">{{ detectMethodLabel[row.method] }}</template>
            <template #cell-inUse="{ row }">
              <StatusBadge :tone="row.inUse ? 'warn' : 'neutral'" :label="row.inUse ? '실행 중' : '실행 안 함'" />
            </template>
            <template #cell-firstSeen="{ row }"><span class="whitespace-nowrap">{{ formatDate(row.firstSeen) }}</span></template>
            <template #cell-raw="{ row }">
              <AppButton v-if="row.versionRaw" size="sm" @click="showRaw(row)">출력 보기</AppButton>
            </template>
          </DataTable>
        </Panel>
      </div>

      <AppModal v-model:open="rawOpen" title="버전 출력" wide>
        <template v-if="rawRow">
          <p class="mb-2 text-sm text-ink-2">{{ rawRow.asset.name }}</p>
          <p v-if="rawRow.versionCommand" class="mono mb-2 break-all text-xs">{{ rawRow.versionCommand }}</p>
          <pre class="pre">{{ rawRow.versionRaw }}</pre>
        </template>
        <template #footer><AppButton @click="rawOpen = false">닫기</AppButton></template>
      </AppModal>
    </template>
  </div>
</template>
