<script setup lang="ts">
import type { FindingRow } from '~/mock'
import type { FindingStatus } from '~/types'
import type { TableColumn } from '~/types/table'
import { componentsOfVuln, findingsOfVuln, getVuln } from '~/mock'

const route = useRoute()
const id = computed(() => String(route.params.id ?? ''))
const vuln = computed(() => getVuln(id.value))

useHead({ title: computed(() => `${vuln.value?.id ?? '취약점'} · bomcensus`) })

const matches = computed(() => componentsOfVuln(id.value))
const findingRows = computed(() => findingsOfVuln(id.value))

const status = ref('')
const filtered = computed(() => findingRows.value.filter((f) => !status.value || f.status === status.value))
const statusOptions = (Object.keys(findingStatusLabel) as FindingStatus[]).map((value) => ({ value, label: findingStatusLabel[value] }))

type MatchRow = (typeof matches.value)[number]

const matchColumns: TableColumn<MatchRow>[] = [
  { key: 'component', label: '컴포넌트', sortValue: (r) => r.component.name },
  { key: 'origin', label: '출처', hideBelow: 'sm' },
  { key: 'fix', label: '수정 상태' },
  { key: 'basis', label: '판정 근거', hideBelow: 'md' },
  { key: 'advisory', label: '권고 ID', hideBelow: 'lg' },
]

const findingColumns: TableColumn<FindingRow>[] = [
  { key: 'asset', label: '자산', sortValue: (r) => r.asset.name },
  { key: 'component', label: '컴포넌트', hideBelow: 'sm' },
  { key: 'status', label: '상태', sortValue: (r) => r.status },
  { key: 'inUse', label: '실행 중', sortValue: (r) => (r.inUse ? 0 : 1), hideBelow: 'md' },
  { key: 'exposed', label: '노출', sortValue: (r) => (r.exposed ? 0 : 1), hideBelow: 'md' },
  { key: 'firstDetected', label: '최초 탐지', align: 'right', sortValue: (r) => r.firstDetected, hideBelow: 'sm' },
]
</script>

<template>
  <div>
    <EmptyState v-if="!vuln" title="찾을 수 없음">
      <AppButton to="/vulnerabilities">목록으로</AppButton>
    </EmptyState>

    <template v-else>
      <PageHeader :title="vuln.id" :subtitle="vuln.title" :back="{ to: '/vulnerabilities', label: '취약점' }" />

      <Panel title="정보">
        <dl class="kv">
          <dt>심각도</dt>
          <dd><SeverityBadge :severity="vuln.severity" /></dd>
          <dt>CVSS</dt>
          <dd><span class="mono">{{ vuln.cvss?.toFixed(1) ?? '—' }}</span></dd>
          <dt>EPSS</dt>
          <dd><span class="mono">{{ formatEpss(vuln.epss) }}</span></dd>
          <dt>KEV</dt>
          <dd><StatusBadge v-if="vuln.kev" tone="danger" label="KEV 등재" /><span v-else class="text-ink-3">해당 없음</span></dd>
          <dt>별칭</dt>
          <dd>
            <span v-if="vuln.aliases.length" class="mono">{{ vuln.aliases.join(', ') }}</span>
            <span v-else class="text-ink-3">—</span>
          </dd>
          <dt>게시일</dt>
          <dd>{{ formatDate(vuln.publishedAt) }}</dd>
          <dt>수정일</dt>
          <dd>{{ formatDate(vuln.modifiedAt) }}</dd>
          <dt>출처</dt>
          <dd>{{ vuln.sources.join(', ') || '—' }}</dd>
        </dl>
        <p class="mt-3 whitespace-pre-line text-sm text-ink-2">{{ vuln.description }}</p>
      </Panel>

      <div class="mt-4">
        <Panel title="영향 컴포넌트" flush>
          <DataTable
            :columns="matchColumns"
            :rows="matches"
            :row-key="(r) => r.componentId"
            :row-to="(r) => `/components/${encodeURIComponent(r.componentId)}`"
          >
            <template #cell-component="{ row }">
              <NuxtLink :to="`/components/${encodeURIComponent(row.componentId)}`" class="font-medium hover:underline">{{ row.component.name }}</NuxtLink>
              <span class="mono whitespace-nowrap text-ink-2"> {{ row.component.version }}</span>
            </template>
            <template #cell-origin="{ row }">{{ originLabel[row.component.origin] }}</template>
            <template #cell-fix="{ row }">
              {{ fixStateLabel[row.fixState] }}
              <span v-if="row.fixedVersion" class="mono whitespace-nowrap text-ink-2"> {{ row.fixedVersion }}</span>
            </template>
            <template #cell-basis="{ row }">{{ matchBasisLabel[row.basis] }}</template>
            <template #cell-advisory="{ row }"><span class="mono whitespace-nowrap text-xs">{{ row.advisoryId ?? '—' }}</span></template>
          </DataTable>
        </Panel>
      </div>

      <div class="mt-4">
        <FilterBar :count="filtered.length" :total="findingRows.length" unit="건">
          <span class="text-sm font-semibold">영향 자산</span>
          <SelectFilter v-model="status" label="상태" :options="statusOptions" />
        </FilterBar>
        <Panel flush>
          <DataTable
            :columns="findingColumns"
            :rows="filtered"
            :row-key="(r) => r.id"
            :row-to="(r) => `/assets/${r.assetId}`"
            :page-size="25"
          >
            <template #cell-asset="{ row }">
              <NuxtLink :to="`/assets/${row.assetId}`" class="font-medium hover:underline">{{ row.asset.name }}</NuxtLink>
              <div v-if="row.container" class="mono whitespace-nowrap text-xs text-ink-3">{{ row.container }}</div>
            </template>
            <template #cell-component="{ row }">
              {{ row.component.name }} <span class="mono whitespace-nowrap text-ink-2">{{ row.component.version }}</span>
            </template>
            <template #cell-status="{ row }"><StatusBadge :tone="findingStatusTone[row.status]" :label="findingStatusLabel[row.status]" /></template>
            <template #cell-inUse="{ row }">{{ row.inUse ? '실행 중' : '—' }}</template>
            <template #cell-exposed="{ row }">{{ row.exposed ? '외부 노출' : '—' }}</template>
            <template #cell-firstDetected="{ row }"><span class="whitespace-nowrap">{{ formatDate(row.firstDetected) }}</span></template>
          </DataTable>
        </Panel>
      </div>
    </template>
  </div>
</template>
