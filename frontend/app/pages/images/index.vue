<script setup lang="ts">
import type { ContainerImage } from '~/types'
import type { TableColumn } from '~/types/table'
import { imageContentKnown, imageUsage, images, severityCountsOfImage, totalOf } from '~/mock'

useHead({ title: '이미지 · bomcensus' })

const q = ref('')
const inUseOnly = ref(false)

const usage = (i: ContainerImage) => imageUsage(i.digest)
const counts = (i: ContainerImage) => severityCountsOfImage(i.digest)

const rows = computed(() => {
  const needle = q.value.trim().toLowerCase()
  return images.filter((i) => {
    if (inUseOnly.value && usage(i).containers === 0) return false
    if (!needle) return true
    return [i.digest, ...i.repoTags].some((v) => v.toLowerCase().includes(needle))
  })
})

const columns: TableColumn<ContainerImage>[] = [
  { key: 'tag', label: 'tag', sortValue: (i) => i.repoTags[0] ?? '' },
  { key: 'digest', label: 'digest', sortValue: (i) => i.digest, hideBelow: 'sm' },
  { key: 'os', label: 'OS', sortValue: (i) => i.os ?? '', hideBelow: 'lg' },
  { key: 'arch', label: '아키텍처', sortValue: (i) => i.arch, hideBelow: 'lg' },
  { key: 'size', label: '크기', align: 'right', sortValue: (i) => i.sizeBytes, hideBelow: 'md' },
  { key: 'usage', label: '사용 대상', sortValue: (i) => usage(i).instances },
  { key: 'vulns', label: '취약점', sortValue: (i) => -(counts(i).critical * 1e6 + counts(i).high * 1e3 + totalOf(counts(i))) },
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
      <DataTable
        :columns="columns"
        :rows="rows"
        :row-key="(i) => i.digest"
        :row-to="(i) => `/images/${encodeURIComponent(i.digest)}`"
        :page-size="25"
        :initial-sort="{ key: 'vulns', dir: 'asc' }"
      >
        <template #cell-tag="{ row }">
          <NuxtLink :to="`/images/${encodeURIComponent(row.digest)}`" class="mono font-medium hover:underline">
            {{ row.repoTags[0] ?? 'tag 없음' }}
          </NuxtLink>
          <span v-if="row.repoTags.length > 1" class="whitespace-nowrap text-xs text-ink-3"> 외 {{ row.repoTags.length - 1 }}</span>
        </template>
        <template #cell-digest="{ row }"><span class="mono whitespace-nowrap">{{ shortHash(row.digest) }}</span></template>
        <template #cell-os="{ row }">{{ row.os ?? '—' }}</template>
        <template #cell-arch="{ row }"><span class="mono whitespace-nowrap">{{ row.arch }}</span></template>
        <template #cell-size="{ row }"><span class="mono whitespace-nowrap">{{ formatBytes(row.sizeBytes) }}</span></template>
        <template #cell-usage="{ row }">
          <span v-if="usage(row).containers" class="whitespace-nowrap text-ink-2">
            자산 {{ usage(row).assets }} · 인스턴스 {{ usage(row).instances }}
          </span>
          <span v-else class="text-ink-3">미사용</span>
        </template>
        <template #cell-vulns="{ row }">
          <SeverityCounts v-if="imageContentKnown(row.digest)" :counts="counts(row)" />
          <span v-else class="whitespace-nowrap text-xs text-ink-3">확인 불가</span>
        </template>
        <template #cell-firstSeen="{ row }"><TimeAgo :at="row.firstSeen" class="whitespace-nowrap text-ink-2" /></template>
      </DataTable>
    </Panel>
  </div>
</template>
