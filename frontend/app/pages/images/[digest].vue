<script setup lang="ts">
import type { Severity } from '~/types'
import type { TableColumn } from '~/types/table'
import type { FindingRow, ImageUseRow } from '~/mock'
import { assetLocation, compareSeverity, containersOfImage, findingsOfImage, getImage, imageContentKnown, isActive } from '~/mock'

const route = useRoute()
const digest = computed(() => decodeURIComponent(String(route.params.digest)))
const image = computed(() => getImage(digest.value))

useHead({ title: computed(() => `${image.value?.repoTags[0] ?? '이미지'} · bomcensus`) })

const uses = computed(() => containersOfImage(digest.value))

const useColumns: TableColumn<ImageUseRow>[] = [
  { key: 'asset', label: '자산', sortValue: (r) => r.asset.name },
  { key: 'kind', label: '종류', sortValue: (r) => r.asset.kind, hideBelow: 'sm' },
  { key: 'location', label: '위치', sortValue: (r) => assetLocation(r.asset) ?? '', hideBelow: 'md' },
  { key: 'name', label: '컨테이너', sortValue: (r) => r.container.name },
  { key: 'instances', label: '인스턴스', align: 'right', sortValue: (r) => r.container.instances },
  { key: 'coverage', label: '수집 범위' },
]

// 조치가 필요한 finding을 취약점별로 묶는다. 같은 컴포넌트는 한 줄로 합친다.
interface VulnGroup {
  key: string
  row: FindingRow
  severity: Severity
  assets: number
}

const findings = computed(() => findingsOfImage(digest.value).filter(isActive))
const groups = computed<VulnGroup[]>(() => {
  const map = new Map<string, { row: FindingRow; assets: Set<string> }>()
  for (const f of findings.value) {
    const key = `${f.vulnId}|${f.componentId}`
    const g = map.get(key) ?? { row: f, assets: new Set<string>() }
    g.assets.add(f.assetId)
    map.set(key, g)
  }
  return [...map.entries()]
    .map(([key, g]) => ({ key, row: g.row, severity: g.row.vuln.severity, assets: g.assets.size }))
    .sort((a, b) => compareSeverity(a.severity, b.severity))
})

const vulnColumns: TableColumn<VulnGroup>[] = [
  { key: 'id', label: 'ID', sortValue: (g) => g.row.vulnId },
  { key: 'severity', label: '심각도', sortValue: (g) => g.severity === 'critical' ? 0 : g.severity === 'high' ? 1 : g.severity === 'medium' ? 2 : 3 },
  { key: 'component', label: '컴포넌트', sortValue: (g) => g.row.component.name },
  { key: 'fix', label: '수정 버전' },
  { key: 'assets', label: '영향 자산', align: 'right', sortValue: (g) => g.assets },
]

// 내용을 수집한 컨테이너가 하나도 없으면 취약점을 알 수 없다
const contentKnown = computed(() => imageContentKnown(digest.value))
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
          <dd class="mono">{{ image.arch }}</dd>
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

      <Panel title="이미지 취약점" class="mt-4" flush>
        <p v-if="!contentKnown" class="note note-warn m-3">
          내용을 수집한 컨테이너가 없어 이 이미지의 취약점을 알 수 없습니다. 취약점이 없다는 뜻이 아닙니다.
        </p>
        <template v-else>
          <DataTable
            :columns="vulnColumns"
            :rows="groups"
            :row-key="(g) => g.key"
            :initial-sort="{ key: 'severity', dir: 'asc' }"
          >
            <template #cell-id="{ row }">
              <NuxtLink :to="`/vulnerabilities/${row.row.vulnId}`" class="link mono whitespace-nowrap">{{ row.row.vulnId }}</NuxtLink>
            </template>
            <template #cell-severity="{ row }"><SeverityBadge :severity="row.severity" /></template>
            <template #cell-component="{ row }">
              {{ row.row.component.name }} <span class="mono whitespace-nowrap text-ink-2">{{ row.row.component.version }}</span>
            </template>
            <template #cell-fix="{ row }">
              <span v-if="row.row.match?.fixedVersion" class="mono whitespace-nowrap">{{ row.row.match.fixedVersion }}</span>
              <span v-else class="text-ink-3">{{ row.row.match ? fixStateLabel[row.row.match.fixState] : '—' }}</span>
            </template>
            <template #cell-assets="{ row }"><span class="mono whitespace-nowrap">{{ row.assets }}</span></template>
          </DataTable>
        </template>
      </Panel>
    </template>

    <template v-else>
      <PageHeader title="이미지" :back="{ to: '/images', label: '이미지' }" />
      <EmptyState title="찾을 수 없음">
        <AppButton to="/images">이미지 목록</AppButton>
      </EmptyState>
    </template>
  </div>
</template>
