<script setup lang="ts">
import type { ComponentAssetRow, ComponentVulnRow } from '~/mock'
import type { TableColumn } from '~/types/table'
import { assetsOfComponent, getComponent, vulnsOfComponent } from '~/mock'

const route = useRoute()
const id = computed(() => String(route.params.id ?? ''))
const component = computed(() => getComponent(id.value))

useHead({ title: computed(() => `${component.value?.name ?? '컴포넌트'} · bomcensus`) })

const tab = ref('assets')
const installed = computed(() => assetsOfComponent(id.value))
const vulns = computed(() => vulnsOfComponent(id.value))
const tabs = computed(() => [
  { key: 'assets', label: '설치 자산', count: installed.value.length },
  { key: 'vulns', label: '취약점', count: vulns.value.length },
])

const assetColumns: TableColumn<ComponentAssetRow>[] = [
  { key: 'asset', label: '자산', sortValue: (r) => r.asset.name },
  { key: 'locations', label: '위치', hideBelow: 'md' },
  { key: 'method', label: '탐지 방법', sortValue: (r) => r.method, hideBelow: 'sm' },
  { key: 'inUse', label: '실행 중', sortValue: (r) => (r.inUse ? 0 : 1) },
  { key: 'firstSeen', label: '최초 발견', align: 'right', sortValue: (r) => r.firstSeen, hideBelow: 'sm' },
  { key: 'raw', label: '출력', align: 'right' },
]

const vulnColumns: TableColumn<ComponentVulnRow>[] = [
  { key: 'id', label: 'ID', sortValue: (r) => r.vulnId },
  { key: 'severity', label: '심각도' },
  { key: 'fix', label: '수정 상태' },
  { key: 'basis', label: '판정 근거', hideBelow: 'md' },
  { key: 'advisory', label: '권고 ID', hideBelow: 'lg' },
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
    <EmptyState v-if="!component" title="찾을 수 없음">
      <AppButton to="/components">목록으로</AppButton>
    </EmptyState>

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
        <AppTabs v-model="tab" :tabs="tabs" />
        <Panel flush class="mt-3">
          <DataTable
            v-if="tab === 'assets'"
            :columns="assetColumns"
            :rows="installed"
            :row-key="(r) => `${r.assetId}/${r.container ?? ''}`"
            :row-to="(r) => `/assets/${r.assetId}`"
            :page-size="25"
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

          <DataTable
            v-else
            :columns="vulnColumns"
            :rows="vulns"
            :row-key="(r) => r.vulnId"
            :row-to="(r) => `/vulnerabilities/${r.vulnId}`"
            :page-size="25"
          >
            <template #cell-id="{ row }">
              <NuxtLink :to="`/vulnerabilities/${row.vulnId}`" class="mono whitespace-nowrap hover:underline">{{ row.vulnId }}</NuxtLink>
              <div class="text-xs text-ink-3">{{ row.vuln.title }}</div>
            </template>
            <template #cell-severity="{ row }"><SeverityBadge :severity="row.vuln.severity" /></template>
            <template #cell-fix="{ row }">
              <template v-if="row.fixedVersion"><span class="mono whitespace-nowrap">{{ row.fixedVersion }}</span></template>
              <template v-else>{{ fixStateLabel[row.fixState] }}</template>
            </template>
            <template #cell-basis="{ row }">{{ matchBasisLabel[row.basis] }}</template>
            <template #cell-advisory="{ row }"><span class="mono whitespace-nowrap text-xs">{{ row.advisoryId ?? '—' }}</span></template>
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
