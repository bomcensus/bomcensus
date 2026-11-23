<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { ContainerImage } from '~/types'
import type { TableColumn } from '~/types/table'
import { fetchAll, listImages } from '~/api'

useHead({ title: '이미지 · bomcensus' })

const { data: images, pending, error, refresh } = useLoad('images', () => fetchAll((page) => listImages(page)), () => [])

const q = ref('')
const inUseOnly = ref(false)

const rows = computed(() => {
  const needle = q.value.trim().toLowerCase()
  return images.value.filter((i) => {
    if (inUseOnly.value && i.usage.containers === 0) return false
    if (!needle) return true
    return [i.digest, ...i.currentTags, ...i.previousTags.map((t) => t.tag)].some((v) => v.toLowerCase().includes(needle))
  })
})

const columns: TableColumn<ContainerImage>[] = [
  { key: 'tag', label: 'tag', sortValue: (i) => i.currentTags[0] ?? i.previousTags[0]?.tag ?? '' },
  { key: 'digest', label: 'digest', sortValue: (i) => i.digest, hideBelow: 'sm' },
  { key: 'os', label: 'OS', sortValue: (i) => i.os ?? '', hideBelow: 'lg' },
  { key: 'arch', label: '아키텍처', sortValue: (i) => i.arch, hideBelow: 'lg' },
  { key: 'size', label: '크기', align: 'right', sortValue: (i) => i.sizeBytes, hideBelow: 'md' },
  { key: 'usage', label: '사용 대상', sortValue: (i) => i.usage.instances },
  { key: 'firstSeen', label: '최초 발견', align: 'right', sortValue: (i) => i.firstSeen, hideBelow: 'md' },
]
</script>

<template>
  <div>
    <PageHeader title="이미지" />

    <FilterBar :count="rows.length" :total="images.length" unit="개">
      <SearchInput v-model="q" placeholder="tag, digest" />
      <label class="inline-flex items-center gap-1.5 text-sm">
        <input v-model="inUseOnly" type="checkbox" class="accent-(--accent)" /> 사용 중인 것만
      </label>
    </FilterBar>

    <Panel flush>
      <LoadError v-if="error" :error="error" @retry="refresh" />
      <DataTable
        v-else
        :columns="columns"
        :rows="rows"
        :row-key="(i) => i.digest"
        :row-to="(i) => `/images/${encodeURIComponent(i.digest)}`"
        :page-size="25"
        :loading="pending"
      >
        <template #cell-tag="{ row }">
          <template v-if="row.currentTags.length">
            <NuxtLink :to="`/images/${encodeURIComponent(row.digest)}`" class="mono font-medium hover:underline">
              {{ row.currentTags[0] }}
            </NuxtLink>
            <span v-if="row.currentTags.length > 1" class="whitespace-nowrap text-xs text-ink-3"> 외 {{ row.currentTags.length - 1 }}</span>
            <span v-if="row.previousTags.length" class="whitespace-nowrap text-xs text-ink-3"> · 이전 {{ row.previousTags.length }}</span>
          </template>
          <template v-else-if="row.previousTags.length">
            <NuxtLink :to="`/images/${encodeURIComponent(row.digest)}`" class="mono text-ink-3 hover:underline">
              {{ row.previousTags[0]?.tag }}
            </NuxtLink>
            <span class="whitespace-nowrap text-xs text-ink-3"> 이전<template v-if="row.previousTags.length > 1"> 외 {{ row.previousTags.length - 1 }}</template></span>
          </template>
          <NuxtLink v-else :to="`/images/${encodeURIComponent(row.digest)}`" class="mono font-medium hover:underline">tag 없음</NuxtLink>
        </template>
        <template #cell-digest="{ row }"><span class="mono whitespace-nowrap">{{ shortHash(row.digest) }}</span></template>
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
