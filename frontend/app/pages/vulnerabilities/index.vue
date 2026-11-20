<script setup lang="ts">
import type { Severity, Vulnerability } from '~/types'
import type { TableColumn } from '~/types/table'
import { SEVERITIES, affectedAssetCount, componentVulns, compareSeverity, vulnerabilities } from '~/mock'

useHead({ title: '취약점 · bomcensus' })

const q = ref('')
const severity = ref('')
const onlyKev = ref(false)
const onlyAffected = ref(true)

const affected = computed(() => new Map(vulnerabilities.map((v) => [v.id, affectedAssetCount(v.id)])))
const hasFix = computed(() => new Set(componentVulns.filter((cv) => cv.fixedVersion).map((cv) => cv.vulnId)))
const affectedOf = (v: Vulnerability) => affected.value.get(v.id) ?? 0

const rows = computed(() => {
  const needle = q.value.trim().toLowerCase()
  return vulnerabilities.filter((v) => {
    if (severity.value && v.severity !== severity.value) return false
    if (onlyKev.value && !v.kev) return false
    if (onlyAffected.value && affectedOf(v) === 0) return false
    if (!needle) return true
    return v.id.toLowerCase().includes(needle) || v.title.toLowerCase().includes(needle)
  })
})

const columns: TableColumn<Vulnerability>[] = [
  { key: 'id', label: 'ID', sortValue: (v) => v.id },
  { key: 'title', label: '제목', hideBelow: 'md' },
  { key: 'severity', label: '심각도', sortValue: (v) => compareSeverity(v.severity, 'low') },
  { key: 'cvss', label: 'CVSS', align: 'right', sortValue: (v) => v.cvss, hideBelow: 'sm' },
  { key: 'epss', label: 'EPSS', align: 'right', sortValue: (v) => v.epss, hideBelow: 'md' },
  { key: 'kev', label: 'KEV', sortValue: (v) => (v.kev ? 0 : 1) },
  { key: 'affected', label: '영향 자산', align: 'right', sortValue: affectedOf },
  { key: 'fix', label: '수정 버전', hideBelow: 'lg' },
  { key: 'publishedAt', label: '게시일', align: 'right', sortValue: (v) => v.publishedAt, hideBelow: 'lg' },
]

const severityOptions = SEVERITIES.map((value: Severity) => ({ value, label: severityLabel[value] }))
</script>

<template>
  <div>
    <PageHeader title="취약점" />

    <FilterBar :count="rows.length" :total="vulnerabilities.length" unit="건">
      <SearchInput v-model="q" placeholder="ID, 제목" />
      <SelectFilter v-model="severity" label="심각도" :options="severityOptions" />
      <label class="inline-flex items-center gap-1.5 text-sm">
        <input v-model="onlyKev" type="checkbox" class="accent-(--accent)" /> KEV만
      </label>
      <label class="inline-flex items-center gap-1.5 text-sm">
        <input v-model="onlyAffected" type="checkbox" class="accent-(--accent)" /> 영향 자산이 있는 것만
      </label>
    </FilterBar>

    <Panel flush>
      <DataTable
        :columns="columns"
        :rows="rows"
        :row-key="(v) => v.id"
        :row-to="(v) => `/vulnerabilities/${v.id}`"
        :page-size="25"
        :initial-sort="{ key: 'severity', dir: 'asc' }"
      >
        <template #cell-id="{ row }">
          <NuxtLink :to="`/vulnerabilities/${row.id}`" class="mono whitespace-nowrap font-medium hover:underline">{{ row.id }}</NuxtLink>
        </template>
        <template #cell-title="{ row }"><span class="text-ink-2">{{ row.title }}</span></template>
        <template #cell-severity="{ row }"><SeverityBadge :severity="row.severity" /></template>
        <template #cell-cvss="{ row }"><span class="mono whitespace-nowrap">{{ row.cvss?.toFixed(1) ?? '—' }}</span></template>
        <template #cell-epss="{ row }"><span class="mono whitespace-nowrap">{{ formatEpss(row.epss) }}</span></template>
        <template #cell-kev="{ row }">
          <StatusBadge v-if="row.kev" tone="danger" label="KEV" />
          <span v-else class="text-ink-3">—</span>
        </template>
        <template #cell-affected="{ row }"><span class="mono whitespace-nowrap">{{ affectedOf(row) }}</span></template>
        <template #cell-fix="{ row }">{{ hasFix.has(row.id) ? '있음' : '없음' }}</template>
        <template #cell-publishedAt="{ row }"><span class="whitespace-nowrap">{{ formatDate(row.publishedAt) }}</span></template>
      </DataTable>
    </Panel>
  </div>
</template>
