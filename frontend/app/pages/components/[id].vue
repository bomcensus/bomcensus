<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { ComponentAssetRow } from '~/types'
import type { TableColumn } from '~/types/table'
import { fetchAll, getComponent, listComponentAssets } from '~/api'

const route = useRoute()
// When only the id changes on the same page, NuxtPage recreates it, so the value at setup time is enough
const id = String(route.params.id)

const { data: component, error, refresh } = useLoad(`component:${id}`, () => getComponent(id))
const {
  data: installed,
  pending: installedPending,
  error: installedError,
  refresh: refreshInstalled,
} = useLoad(`component:${id}:assets`, () => fetchAll((page) => listComponentAssets(id, page)), () => [])

useHead({ title: computed(() => `${component.value?.name ?? '컴포넌트'} · bomcensus`) })

const assetColumns: TableColumn<ComponentAssetRow>[] = [
  { key: 'asset', label: '자산', sortValue: (r) => r.asset.name },
  { key: 'locations', label: '위치', hideBelow: 'md' },
  { key: 'method', label: '탐지 방법', sortValue: (r) => r.method, hideBelow: 'sm' },
  { key: 'inUse', label: '실행 중', sortValue: (r) => (r.inUse ? 0 : 1) },
  { key: 'firstSeen', label: '최초 발견', align: 'right', sortValue: (r) => r.firstSeen, hideBelow: 'sm' },
  { key: 'raw', label: '출력', align: 'right' },
]

const rawRow = ref<ComponentAssetRow>()
const rawOpen = ref(false)
function showRaw(row: ComponentAssetRow) {
  rawRow.value = row
  rawOpen.value = true
}
</script>

<template>
  <div>
    <template v-if="!component">
      <PageHeader title="컴포넌트" :back="{ to: '/components', label: '컴포넌트' }" />
      <Panel>
        <LoadError v-if="error" :error="error" :back="{ to: '/components', label: '컴포넌트 목록' }" @retry="refresh" />
        <LoadingText v-else />
      </Panel>
    </template>

    <template v-else>
      <PageHeader
        :title="`${component.name} ${component.version}`"
        :subtitle="`${componentTypeLabel[component.type]} · ${originLabel[component.origin]}`"
        :back="{ to: '/components', label: '컴포넌트' }"
      />

      <Panel title="정보">
        <dl class="kv">
          <dt>purl</dt>
          <dd><CopyField :value="component.purl" /></dd>
          <dt>CPE</dt>
          <dd><span v-if="component.cpe" class="mono break-all">{{ component.cpe }}</span><span v-else class="text-ink-3">—</span></dd>
          <dt>종류</dt>
          <dd>{{ componentTypeLabel[component.type] }}</dd>
          <dt>출처</dt>
          <dd>{{ originLabel[component.origin] }}</dd>
          <dt>소스 패키지</dt>
          <dd>
            <template v-if="component.sourceName">
              {{ component.sourceName }}
              <span v-if="component.sourceVersion" class="mono whitespace-nowrap text-ink-2">{{ component.sourceVersion }}</span>
            </template>
            <span v-else class="text-ink-3">—</span>
          </dd>
          <dt>배포판</dt>
          <dd>{{ component.distro ?? '—' }}</dd>
          <dt>아키텍처</dt>
          <dd><span class="mono">{{ component.arch ?? '—' }}</span></dd>
          <dt>벤더</dt>
          <dd>{{ component.vendor ?? '—' }}</dd>
        </dl>
      </Panel>

      <div class="mt-4">
        <Panel title="설치 자산" flush>
          <LoadError v-if="installedError" :error="installedError" @retry="refreshInstalled" />
          <DataTable
            v-else
            :columns="assetColumns"
            :rows="installed"
            :row-key="(r) => `${r.assetId}/${r.container ?? ''}`"
            :row-to="(r) => `/assets/${r.assetId}`"
            :page-size="25"
            :loading="installedPending"
          >
            <template #cell-asset="{ row }">
              <NuxtLink :to="`/assets/${row.assetId}`" class="font-medium hover:underline">{{ row.asset.name }}</NuxtLink>
              <div v-if="row.container" class="mono whitespace-nowrap text-xs text-ink-3">
                {{ row.container }}<template v-if="row.layer"> · {{ layerLabel[row.layer] }}</template>
              </div>
            </template>
            <template #cell-locations="{ row }">
              <template v-if="row.locations.length">
                <span class="mono break-all text-xs">{{ row.locations[0] }}</span>
                <span v-if="row.locations.length > 1" class="text-xs text-ink-3"> 외 {{ row.locations.length - 1 }}</span>
              </template>
              <span v-else class="text-ink-3">—</span>
            </template>
            <template #cell-method="{ row }">{{ detectMethodLabel[row.method] }}</template>
            <template #cell-inUse="{ row }">
              <StatusBadge :tone="row.inUse ? 'warn' : 'neutral'" :label="row.inUse ? '실행 중' : '실행 안 함'" />
            </template>
            <template #cell-firstSeen="{ row }"><span class="whitespace-nowrap">{{ formatDate(row.firstSeen) }}</span></template>
            <template #cell-raw="{ row }">
              <AppButton v-if="row.versionRaw" size="sm" @click="showRaw(row)">출력 보기</AppButton>
            </template>
          </DataTable>
        </Panel>
      </div>

      <AppModal v-model:open="rawOpen" title="버전 출력" wide>
        <template v-if="rawRow">
          <p class="mb-2 text-sm text-ink-2">{{ rawRow.asset.name }}</p>
          <p v-if="rawRow.versionCommand" class="mono mb-2 break-all text-xs">{{ rawRow.versionCommand }}</p>
          <pre class="pre">{{ rawRow.versionRaw }}</pre>
        </template>
        <template #footer><AppButton @click="rawOpen = false">닫기</AppButton></template>
      </AppModal>
    </template>
  </div>
</template>
