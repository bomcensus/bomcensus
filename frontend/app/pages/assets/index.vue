<script setup lang="ts">
import type { Asset, AssetKind, CollectMethod, Coverage } from '~/types'
import type { TableColumn } from '~/types/table'
import { assetGroups, assetLocation, assets, severityCountsOfAsset, totalOf } from '~/mock'

useHead({ title: '자산 · bomcensus' })

const q = ref('')
const kind = ref('')
const group = ref('')
const method = ref('')
const coverage = ref('')

const rows = computed(() => {
  const needle = q.value.trim().toLowerCase()
  return assets.filter((a) => {
    if (kind.value && a.kind !== kind.value) return false
    if (group.value && a.group !== group.value) return false
    if (method.value && a.method !== method.value) return false
    if (coverage.value === 'limited' ? a.coverage === 'full' : coverage.value && a.coverage !== coverage.value) return false
    if (!needle) return true
    return [a.name, assetLocation(a), a.os?.name, a.os?.version, ...a.tags, ...a.containers.map((c) => c.imageRef)].some((v) => v?.toLowerCase().includes(needle))
  })
})

const counts = (a: Asset) => severityCountsOfAsset(a.id)

const columns: TableColumn<Asset>[] = [
  { key: 'name', label: '이름', sortValue: (a) => a.name },
  { key: 'kind', label: '종류', sortValue: (a) => a.kind, hideBelow: 'sm' },
  { key: 'os', label: 'OS', sortValue: (a) => a.os?.name ?? '', hideBelow: 'md' },
  { key: 'group', label: '그룹', sortValue: (a) => a.group, hideBelow: 'lg' },
  { key: 'method', label: '수집 방식', sortValue: (a) => a.method, hideBelow: 'md' },
  { key: 'coverage', label: '수집 범위', sortValue: (a) => a.coverage },
  { key: 'vulns', label: '취약점', sortValue: (a) => -(counts(a).critical * 1e6 + counts(a).high * 1e3 + totalOf(counts(a))) },
  { key: 'lastSeen', label: '최근 수집', align: 'right', sortValue: (a) => a.lastSeen, hideBelow: 'sm' },
]

const kindOptions = (Object.keys(assetKindLabel) as AssetKind[]).map((value) => ({ value, label: assetKindLabel[value] }))
const methodOptions = (Object.keys(methodLabel) as CollectMethod[]).map((value) => ({ value, label: methodLabel[value] }))
const coverageOptions = [
  { value: 'limited', label: '제한됨' },
  ...(Object.keys(coverageLabel) as Coverage[]).map((value) => ({ value, label: coverageLabel[value] })),
]
const groupOptions = assetGroups().map((value) => ({ value, label: value }))
</script>

<template>
  <div>
    <PageHeader title="자산" />

    <FilterBar :count="rows.length" :total="assets.length" unit="개">
      <SearchInput v-model="q" placeholder="이름, 주소, OS, 태그, 이미지" />
      <SelectFilter v-model="kind" label="종류" :options="kindOptions" />
      <SelectFilter v-model="group" label="그룹" :options="groupOptions" />
      <SelectFilter v-model="method" label="수집 방식" :options="methodOptions" />
      <SelectFilter v-model="coverage" label="수집 범위" :options="coverageOptions" />
    </FilterBar>

    <Panel flush>
      <DataTable
        :columns="columns"
        :rows="rows"
        :row-key="(a) => a.id"
        :row-to="(a) => `/assets/${a.id}`"
        :page-size="25"
        :initial-sort="{ key: 'vulns', dir: 'asc' }"
      >
        <template #cell-name="{ row }">
          <NuxtLink :to="`/assets/${row.id}`" class="font-medium hover:underline">{{ row.name }}</NuxtLink>
          <div v-if="assetLocation(row) || row.containers.length" class="text-xs text-ink-3">
            <span class="mono">{{ assetLocation(row) }}</span>
            <template v-if="row.containers.length"> · 컨테이너 {{ row.containers.length }}</template>
          </div>
        </template>
        <template #cell-kind="{ row }">{{ assetKindLabel[row.kind] }}</template>
        <template #cell-os="{ row }">
          <template v-if="row.os">{{ row.os.name }} <span class="mono whitespace-nowrap text-ink-2">{{ row.os.version }}</span></template>
          <span v-else class="text-ink-3">—</span>
        </template>
        <template #cell-method="{ row }">
          {{ methodLabel[row.method] }}
          <span v-if="row.privilege === 'non_root'" class="text-xs text-ink-3">· non-root</span>
        </template>
        <template #cell-coverage="{ row }">
          <CoverageBadge :coverage="row.coverage" :reason="row.coverageReason" />
        </template>
        <template #cell-vulns="{ row }">
          <SeverityCounts v-if="row.coverage !== 'unsupported' && row.coverage !== 'failed'" :counts="counts(row)" />
          <span v-else class="text-xs text-ink-3">확인 불가</span>
        </template>
        <template #cell-lastSeen="{ row }">
          <TimeAgo :at="row.lastSeen" class="text-ink-2" />
        </template>
      </DataTable>
    </Panel>
  </div>
</template>
