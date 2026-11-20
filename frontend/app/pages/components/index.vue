<script setup lang="ts">
import type { ComponentOrigin, ComponentType, SoftwareComponent } from '~/types'
import type { TableColumn } from '~/types/table'
import { assetComponents, componentVulns, components } from '~/mock'

useHead({ title: '컴포넌트 · bomcensus' })

const q = ref('')
const type = ref('')
const origin = ref('')
const onlyVulnerable = ref(false)

// 컴포넌트별 설치 자산 수와 취약점 건수. 제거된 설치는 세지 않는다.
const installCount = computed(() => {
  const map = new Map<string, number>()
  for (const ac of assetComponents) {
    if (ac.removedAt) continue
    map.set(ac.componentId, (map.get(ac.componentId) ?? 0) + 1)
  }
  return map
})
const vulnCount = computed(() => {
  const map = new Map<string, number>()
  for (const cv of componentVulns) map.set(cv.componentId, (map.get(cv.componentId) ?? 0) + 1)
  return map
})
const installs = (c: SoftwareComponent) => installCount.value.get(c.id) ?? 0
const vulns = (c: SoftwareComponent) => vulnCount.value.get(c.id) ?? 0

const rows = computed(() => {
  const needle = q.value.trim().toLowerCase()
  return components.filter((c) => {
    if (type.value && c.type !== type.value) return false
    if (origin.value && c.origin !== origin.value) return false
    if (onlyVulnerable.value && vulns(c) === 0) return false
    if (!needle) return true
    return c.name.toLowerCase().includes(needle) || c.purl.toLowerCase().includes(needle)
  })
})

const columns: TableColumn<SoftwareComponent>[] = [
  { key: 'name', label: '이름', sortValue: (c) => c.name },
  { key: 'version', label: '버전', sortValue: (c) => c.version, mono: true },
  { key: 'type', label: '종류', sortValue: (c) => c.type, hideBelow: 'sm' },
  { key: 'origin', label: '출처', sortValue: (c) => c.origin, hideBelow: 'md' },
  { key: 'installs', label: '설치 자산', align: 'right', sortValue: installs },
  { key: 'vulns', label: '취약점', align: 'right', sortValue: vulns },
  { key: 'purl', label: 'purl', hideBelow: 'lg', sortValue: (c) => c.purl },
]

const typeOptions = (Object.keys(componentTypeLabel) as ComponentType[]).map((value) => ({ value, label: componentTypeLabel[value] }))
const originOptions = (Object.keys(originLabel) as ComponentOrigin[]).map((value) => ({ value, label: originLabel[value] }))
</script>

<template>
  <div>
    <PageHeader title="컴포넌트" />

    <FilterBar :count="rows.length" :total="components.length" unit="개">
      <SearchInput v-model="q" placeholder="이름, purl" />
      <SelectFilter v-model="type" label="종류" :options="typeOptions" />
      <SelectFilter v-model="origin" label="출처" :options="originOptions" />
      <label class="inline-flex items-center gap-1.5 text-sm">
        <input v-model="onlyVulnerable" type="checkbox" class="accent-(--accent)" /> 취약점 있는 것만
      </label>
    </FilterBar>

    <Panel flush>
      <DataTable
        :columns="columns"
        :rows="rows"
        :row-key="(c) => c.id"
        :row-to="(c) => `/components/${encodeURIComponent(c.id)}`"
        :page-size="25"
      >
        <template #cell-name="{ row }">
          <NuxtLink :to="`/components/${encodeURIComponent(row.id)}`" class="font-medium hover:underline">{{ row.name }}</NuxtLink>
        </template>
        <template #cell-version="{ row }"><span class="whitespace-nowrap">{{ row.version }}</span></template>
        <template #cell-type="{ row }">{{ componentTypeLabel[row.type] }}</template>
        <template #cell-origin="{ row }">{{ originLabel[row.origin] }}</template>
        <template #cell-installs="{ row }"><span class="mono whitespace-nowrap">{{ installs(row) }}</span></template>
        <template #cell-vulns="{ row }">
          <span v-if="vulns(row) > 0" class="mono whitespace-nowrap">{{ vulns(row) }}</span>
          <span v-else class="text-ink-3">—</span>
        </template>
        <template #cell-purl="{ row }"><span class="mono break-all text-xs text-ink-2">{{ row.purl }}</span></template>
      </DataTable>
    </Panel>
  </div>
</template>
