<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { AssetKind, AssetSummary, CollectMethod, Coverage } from '~/types'
import type { TableColumn } from '~/types/table'
import { fetchAll, listAssetGroups, listAssets, type QueryOf } from '~/api'

useHead({ title: '자산 · bomcensus' })

const { items, total, pending, error, refresh, q, filters, sort, page, size } = useServerList(
  'assets',
  (p) => listAssets(p as QueryOf<typeof listAssets>),
  { filters: { kind: '', group: '', method: '', coverage: '' }, sort: 'name', url: true },
)
const { data: groups } = useLoad('asset-groups', () => fetchAll((page) => listAssetGroups(page)), () => [])

const columns: TableColumn<AssetSummary>[] = [
  { key: 'name', label: '이름', sort: 'name' },
  { key: 'kind', label: '종류', sort: 'kind', hideBelow: 'sm' },
  { key: 'os', label: 'OS', sort: 'os', hideBelow: 'md' },
  { key: 'group', label: '그룹', sort: 'group', hideBelow: 'lg' },
  { key: 'method', label: '수집 방식', sort: 'method', hideBelow: 'md' },
  { key: 'coverage', label: '수집 범위', sort: 'coverage' },
  { key: 'lastSeen', label: '최근 수집', align: 'right', sort: 'lastSeen', sortDesc: true, hideBelow: 'sm' },
]

const kindOptions = (Object.keys(assetKindLabel) as AssetKind[]).map((value) => ({ value, label: assetKindLabel[value] }))
const methodOptions = (Object.keys(methodLabel) as CollectMethod[]).map((value) => ({ value, label: methodLabel[value] }))
const coverageOptions = [
  { value: 'limited', label: '제한됨' },
  ...(Object.keys(coverageLabel) as Coverage[]).map((value) => ({ value, label: coverageLabel[value] })),
]
const groupOptions = computed(() => groups.value.map((g) => ({ value: g.name, label: `${g.name} (${g.assetCount})` })))
</script>

<template>
  <div>
    <PageHeader title="자산" />

    <FilterBar :count="total" unit="개">
      <SearchInput v-model="q" placeholder="이름, 주소, 이미지, OS, 태그" />
      <SelectFilter v-model="filters.kind" label="종류" :options="kindOptions" />
      <SelectFilter v-model="filters.group" label="그룹" :options="groupOptions" />
      <SelectFilter v-model="filters.method" label="수집 방식" :options="methodOptions" />
      <SelectFilter v-model="filters.coverage" label="수집 범위" :options="coverageOptions" />
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
        :row-key="(a) => a.id"
        :row-to="(a) => `/assets/${a.id}`"
        :loading="pending"
      >
        <template #cell-name="{ row }">
          <NuxtLink :to="`/assets/${row.id}`" class="font-medium hover:underline">{{ row.name }}</NuxtLink>
          <div v-if="assetLocation(row) || row.containerCount" class="text-xs text-ink-3">
            <span class="mono">{{ assetLocation(row) }}</span>
            <template v-if="row.containerCount"> · 컨테이너 {{ row.containerCount }}</template>
          </div>
        </template>
        <template #cell-kind="{ row }">{{ assetKindLabel[row.kind] }}</template>
        <template #cell-os="{ row }">
          <template v-if="row.os">{{ osLabel(row.os) }}</template>
          <span v-else class="text-ink-3">—</span>
        </template>
        <template #cell-group="{ row }">
          <span :class="row.group ? '' : 'text-ink-3'">{{ row.group || '—' }}</span>
        </template>
        <template #cell-method="{ row }">
          {{ methodLabel[row.method] }}
          <span v-if="row.privilege === 'non_root'" class="text-xs text-ink-3">· non-root</span>
        </template>
        <template #cell-coverage="{ row }">
          <CoverageBadge :coverage="row.coverage" :reason="row.coverageReason" />
        </template>
        <template #cell-lastSeen="{ row }">
          <TimeAgo :at="row.lastSeen" class="text-ink-2" />
        </template>
      </DataTable>
    </Panel>
  </div>
</template>
