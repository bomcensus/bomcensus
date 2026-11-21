<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { ImageComponent, ImageUse } from '~/types'
import type { TableColumn } from '~/types/table'
import { getImage } from '~/api'

const route = useRoute()
// When only the digest changes on the same page, NuxtPage recreates it, so the value at setup time is enough
const digest = decodeURIComponent(String(route.params.digest))

const { data: image, error, refresh } = useLoad(`image:${digest}`, () => getImage(digest))

useHead({ title: computed(() => `${image.value?.repoTags[0] ?? '이미지'} · bomcensus`) })

const uses = computed(() => image.value?.uses ?? [])

const useColumns: TableColumn<ImageUse>[] = [
  { key: 'asset', label: '자산', sortValue: (r) => r.asset.name },
  { key: 'kind', label: '종류', sortValue: (r) => r.asset.kind, hideBelow: 'sm' },
  { key: 'location', label: '위치', sortValue: (r) => assetLocation(r.asset) ?? '', hideBelow: 'md' },
  { key: 'name', label: '컨테이너', sortValue: (r) => r.container.name },
  { key: 'instances', label: '인스턴스', align: 'right', sortValue: (r) => r.container.instances },
  { key: 'coverage', label: '수집 범위' },
]

const components = computed(() => image.value?.components ?? [])

const componentColumns: TableColumn<ImageComponent>[] = [
  { key: 'name', label: '이름', sortValue: (r) => r.component.name },
  { key: 'version', label: '버전', sortValue: (r) => r.component.version },
  { key: 'type', label: '종류', sortValue: (r) => r.component.type, hideBelow: 'sm' },
]
</script>

<template>
  <div>
    <template v-if="image">
      <PageHeader
        :title="image.repoTags[0] ?? 'tag 없음'"
        :subtitle="shortHash(image.digest)"
        :back="{ to: '/images', label: '이미지' }"
      />

      <Panel title="이미지">
        <dl class="kv">
          <dt>tag</dt>
          <dd class="mono break-all">{{ image.repoTags.length ? image.repoTags.join(', ') : '—' }}</dd>
          <dt>digest</dt>
          <dd><CopyField :value="image.digest" /></dd>
          <dt>OS</dt>
          <dd>{{ image.os ?? '—' }}</dd>
          <dt>아키텍처</dt>
          <dd class="mono">{{ image.arch ?? '—' }}</dd>
          <dt>크기</dt>
          <dd class="mono">{{ formatBytes(image.sizeBytes) }}</dd>
          <dt>최초 발견</dt>
          <dd class="whitespace-nowrap">{{ formatDateTime(image.firstSeen) }}</dd>
        </dl>
      </Panel>

      <Panel title="이 이미지를 쓰는 컨테이너" class="mt-4" flush>
        <DataTable
          :columns="useColumns"
          :rows="uses"
          :row-key="(r) => `${r.asset.id}/${r.container.name}`"
        >
          <template #cell-asset="{ row }">
            <NuxtLink :to="`/assets/${row.asset.id}?tab=containers`" class="font-medium hover:underline">{{ row.asset.name }}</NuxtLink>
          </template>
          <template #cell-kind="{ row }">{{ assetKindLabel[row.asset.kind] }}</template>
          <template #cell-location="{ row }">
            <span class="mono text-xs">{{ assetLocation(row.asset) ?? '—' }}</span>
          </template>
          <template #cell-name="{ row }"><span class="mono whitespace-nowrap">{{ row.container.name }}</span></template>
          <template #cell-instances="{ row }"><span class="mono whitespace-nowrap">{{ row.container.instances }}</span></template>
          <template #cell-coverage="{ row }">
            <CoverageBadge :coverage="row.container.coverage" :reason="row.container.coverageReason" />
          </template>
        </DataTable>
      </Panel>

      <Panel title="컴포넌트" class="mt-4" flush>
        <p v-if="!image.contentKnown" class="note note-warn m-3">이미지 내용을 수집한 컨테이너가 없어 컴포넌트를 알 수 없습니다.</p>
        <DataTable
          v-else
          :columns="componentColumns"
          :rows="components"
          :row-key="(r) => r.component.id"
          :row-to="(r) => `/components/${r.component.id}`"
          :initial-sort="{ key: 'name', dir: 'asc' }"
        >
          <template #cell-name="{ row }">
            <NuxtLink :to="`/components/${row.component.id}`" class="font-medium hover:underline">{{ row.component.name }}</NuxtLink>
          </template>
          <template #cell-version="{ row }"><span class="mono whitespace-nowrap">{{ row.component.version }}</span></template>
          <template #cell-type="{ row }">{{ componentTypeLabel[row.component.type] }}</template>
        </DataTable>
      </Panel>
    </template>

    <template v-else>
      <PageHeader title="이미지" :back="{ to: '/images', label: '이미지' }" />
      <Panel>
        <LoadError v-if="error" :error="error" :back="{ to: '/images', label: '이미지 목록' }" @retry="refresh" />
        <LoadingText v-else />
      </Panel>
    </template>
  </div>
</template>
