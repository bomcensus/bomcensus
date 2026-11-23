<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { ComponentOrigin, ComponentSummary, ComponentType } from '~/types'
import type { TableColumn } from '~/types/table'
import { fetchAll, listComponents } from '~/api'

useHead({ title: '컴포넌트 · bomcensus' })

const { data: components, pending, error, refresh } = useLoad('components', () => fetchAll((page) => listComponents(page)), () => [])

const q = ref('')
const type = ref('')
const origin = ref('')
const installedOnly = ref(false)
const runningOnly = ref(false)

const rows = computed(() => {
  const needle = q.value.trim().toLowerCase()
  return components.value.filter((c) => {
    if (type.value && c.type !== type.value) return false
    if (origin.value && c.origin !== origin.value) return false
    if (installedOnly.value && c.assetCount === 0) return false
    if (runningOnly.value && c.runningAssetCount === 0) return false
    if (!needle) return true
    return c.name.toLowerCase().includes(needle) || c.purl.toLowerCase().includes(needle)
  })
})

const columns: TableColumn<ComponentSummary>[] = [
  { key: 'name', label: '이름', sortValue: (c) => c.name },
  { key: 'version', label: '버전', sortValue: (c) => c.version, mono: true },
  { key: 'type', label: '종류', sortValue: (c) => c.type, hideBelow: 'sm' },
  { key: 'origin', label: '출처', sortValue: (c) => c.origin, hideBelow: 'md' },
  { key: 'installs', label: '설치 자산', align: 'right', sortValue: (c) => c.assetCount },
  { key: 'running', label: '실행 자산', align: 'right', sortValue: (c) => c.runningAssetCount, hideBelow: 'sm' },
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
        <input v-model="installedOnly" type="checkbox" class="accent-(--accent)" /> 설치된 것만
      </label>
      <label class="inline-flex items-center gap-1.5 text-sm">
        <input v-model="runningOnly" type="checkbox" class="accent-(--accent)" /> 실행 중인 것만
      </label>
    </FilterBar>

    <Panel flush>
      <LoadError v-if="error" :error="error" @retry="refresh" />
      <DataTable
        v-else
        :columns="columns"
        :rows="rows"
        :row-key="(c) => c.id"
        :row-to="(c) => `/components/${encodeURIComponent(c.id)}`"
        :page-size="25"
        :loading="pending"
      >
        <template #cell-name="{ row }">
          <NuxtLink :to="`/components/${encodeURIComponent(row.id)}`" class="font-medium hover:underline">{{ row.name }}</NuxtLink>
        </template>
        <template #cell-version="{ row }"><span class="whitespace-nowrap">{{ row.version }}</span></template>
        <template #cell-type="{ row }">{{ componentTypeLabel[row.type] }}</template>
        <template #cell-origin="{ row }">{{ originLabel[row.origin] }}</template>
        <template #cell-installs="{ row }"><span class="mono whitespace-nowrap">{{ row.assetCount }}</span></template>
        <template #cell-running="{ row }">
          <span class="mono whitespace-nowrap" :class="row.runningAssetCount ? '' : 'text-ink-3'">{{ row.runningAssetCount }}</span>
        </template>
        <template #cell-purl="{ row }"><span class="mono break-all text-xs text-ink-2">{{ row.purl }}</span></template>
      </DataTable>
    </Panel>
  </div>
</template>
