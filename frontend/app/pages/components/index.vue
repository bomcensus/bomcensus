<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { ComponentOrigin, ComponentSummary, ComponentType } from '~/types'
import type { TableColumn } from '~/types/table'
import { listComponents, type QueryOf } from '~/api'

useHead({ title: '컴포넌트 · bomcensus' })

const { items, total, pending, error, refresh, q, filters, sort, page, size } = useServerList(
  'components',
  (p) => listComponents(p as QueryOf<typeof listComponents>),
  { filters: { type: '', origin: '', installed: false, running: false }, sort: 'name', url: true },
)

const columns: TableColumn<ComponentSummary>[] = [
  { key: 'name', label: '이름', sort: 'name' },
  { key: 'version', label: '버전', sort: 'version', mono: true },
  { key: 'type', label: '종류', sort: 'type', hideBelow: 'sm' },
  { key: 'origin', label: '출처', sort: 'origin', hideBelow: 'md' },
  { key: 'installs', label: '설치 자산', align: 'right', sort: 'assetCount', sortDesc: true },
  { key: 'running', label: '실행 자산', align: 'right', sort: 'runningAssetCount', sortDesc: true, hideBelow: 'sm' },
  { key: 'purl', label: 'purl', hideBelow: 'lg', sort: 'purl' },
]

const typeOptions = (Object.keys(componentTypeLabel) as ComponentType[]).map((value) => ({ value, label: componentTypeLabel[value] }))
const originOptions = (Object.keys(originLabel) as ComponentOrigin[]).map((value) => ({ value, label: originLabel[value] }))
</script>

<template>
  <div>
    <PageHeader title="컴포넌트" />

    <FilterBar :count="total" unit="개">
      <SearchInput v-model="q" placeholder="이름, purl" />
      <SelectFilter v-model="filters.type" label="종류" :options="typeOptions" />
      <SelectFilter v-model="filters.origin" label="출처" :options="originOptions" />
      <label class="inline-flex items-center gap-1.5 text-sm">
        <input v-model="filters.installed" type="checkbox" class="accent-(--accent)" /> 설치된 것만
      </label>
      <label class="inline-flex items-center gap-1.5 text-sm">
        <input v-model="filters.running" type="checkbox" class="accent-(--accent)" /> 실행 중인 것만
      </label>
    </FilterBar>

    <Panel flush>
      <LoadError v-if="error" :error="error" @retry="refresh" />
      <DataTable
        v-else
        :columns="columns"
        v-model:sort="sort"
        v-model:page="page"
        v-model:size="size"
        :rows="items"
        :total="total"
        :row-key="(c) => c.id"
        :row-to="(c) => `/components/${encodeURIComponent(c.id)}`"
        :loading="pending"
      >
        <template #cell-name="{ row }">
          <NuxtLink :to="`/components/${encodeURIComponent(row.id)}`" class="font-medium hover:underline">{{ row.name }}</NuxtLink>
        </template>
        <template #cell-version="{ row }"><span class="whitespace-nowrap">{{ versionText(row.version, row.build) }}</span></template>
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
