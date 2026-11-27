<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { ContainerImage } from '~/types'
import type { TableColumn } from '~/types/table'
import type { TriState } from '~/composables/useServerList'
import { listImages, type QueryOf } from '~/api'

useHead({ title: '이미지 · bomcensus' })

const { items, total, pending, error, refresh, q, filters, sort, page, size } = useServerList(
  'images',
  (p) => listImages(p as QueryOf<typeof listImages>),
  { filters: { inUse: false, contentKnown: '' as TriState }, sort: 'tag', url: true },
)

const columns: TableColumn<ContainerImage>[] = [
  { key: 'tag', label: 'tag', sort: 'tag' },
  { key: 'digest', label: 'digest', sort: 'digest', hideBelow: 'sm' },
  { key: 'os', label: 'OS', sort: 'os', hideBelow: 'lg' },
  { key: 'arch', label: '아키텍처', sort: 'arch', hideBelow: 'lg' },
  { key: 'size', label: '크기', align: 'right', sort: 'size', sortDesc: true, hideBelow: 'md' },
  { key: 'usage', label: '사용 대상', sort: 'instances', sortDesc: true },
  { key: 'firstSeen', label: '최초 발견', align: 'right', sort: 'firstSeen', sortDesc: true, hideBelow: 'md' },
]
</script>

<template>
  <div>
    <PageHeader title="이미지" />

    <FilterBar :count="total" unit="개">
      <SearchInput v-model="q" placeholder="tag, digest" />
      <label class="inline-flex items-center gap-1.5 text-sm">
        <input v-model="filters.inUse" type="checkbox" class="accent-(--accent)" /> 사용 중인 것만
      </label>
      <SelectFilter v-model="filters.contentKnown" label="내용" :options="triStateOptions('확인됨', '확인 안 됨')" />
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
        :row-key="(i) => i.digest"
        :row-to="(i) => `/images/${encodeURIComponent(i.digest)}`"
        :loading="pending"
      >
        <template #cell-tag="{ row }">
          <template v-if="row.currentTags.length">
            <NuxtLink :to="`/images/${encodeURIComponent(row.digest)}`" class="mono font-medium hover:underline">
              {{ row.currentTags[0] }}
            </NuxtLink>
            <span v-if="row.currentTags.length > 1" class="whitespace-nowrap text-xs text-ink-3" :title="row.currentTags.join('\n')"> 외 {{ row.currentTags.length - 1 }}</span>
            <span v-if="row.previousTags.length" class="whitespace-nowrap text-xs text-ink-3" :title="row.previousTags.map((t) => t.tag).join('\n')"> · 이전 {{ row.previousTags.length }}</span>
          </template>
          <template v-else-if="row.previousTags.length">
            <NuxtLink :to="`/images/${encodeURIComponent(row.digest)}`" class="mono text-ink-3 hover:underline">
              {{ row.previousTags[0]?.tag }}
            </NuxtLink>
            <span class="whitespace-nowrap text-xs text-ink-3" :title="row.previousTags.map((t) => t.tag).join('\n')"> 이전<template v-if="row.previousTags.length > 1"> 외 {{ row.previousTags.length - 1 }}</template></span>
          </template>
          <NuxtLink v-else :to="`/images/${encodeURIComponent(row.digest)}`" class="mono font-medium hover:underline">tag 없음</NuxtLink>
        </template>
        <template #cell-digest="{ row }"><span class="mono whitespace-nowrap" :title="row.digest">{{ shortHash(row.digest) }}</span></template>
        <template #cell-os="{ row }">{{ row.os ?? '—' }}</template>
        <template #cell-arch="{ row }"><span class="mono whitespace-nowrap">{{ row.arch ?? '—' }}</span></template>
        <template #cell-size="{ row }"><span class="mono whitespace-nowrap">{{ formatBytes(row.sizeBytes) }}</span></template>
        <template #cell-usage="{ row }">
          <span v-if="row.usage.containers" class="whitespace-nowrap text-ink-2">
            자산 {{ row.usage.assets }} · 인스턴스 {{ row.usage.instances }}
          </span>
          <span v-else class="text-ink-3">미사용</span>
        </template>
        <template #cell-firstSeen="{ row }"><TimeAgo :at="row.firstSeen" class="whitespace-nowrap text-ink-2" /></template>
      </DataTable>
    </Panel>
  </div>
</template>
