<script setup lang="ts">
import type { Coverage, Severity, Vulnerability } from '~/types'
import type { TableColumn } from '~/types/table'
import {
  SEVERITIES,
  affectedAssetCount,
  agents,
  assets,
  compareSeverity,
  countBySeverity,
  feeds,
  findings,
  getAsset,
  getComponent,
  getVuln,
  isActive,
  isSuspicious,
  needsRestart,
  processes,
  vulnerabilities,
} from '~/mock'

useHead({ title: '대시보드 · bomcensus' })

// ── 조치가 필요한 finding을 취약점별로 묶는다 ──
interface VulnGroup {
  vuln: Vulnerability
  assets: number
  running: number
  exposed: number
}

const groups = computed<VulnGroup[]>(() => {
  const byVuln = new Map<string, { all: Set<string>; running: Set<string>; exposed: Set<string> }>()
  for (const f of findings) {
    if (!isActive(f)) continue
    const g = byVuln.get(f.vulnId) ?? { all: new Set(), running: new Set(), exposed: new Set() }
    g.all.add(f.assetId)
    if (f.inUse) g.running.add(f.assetId)
    if (f.exposed) g.exposed.add(f.assetId)
    byVuln.set(f.vulnId, g)
  }
  return [...byVuln.entries()].flatMap(([id, g]) => {
    const vuln = getVuln(id)
    return vuln ? [{ vuln, assets: g.all.size, running: g.running.size, exposed: g.exposed.size }] : []
  })
})

const topGroups = computed(() =>
  [...groups.value]
    .sort(
      (a, b) =>
        Number(b.vuln.kev) - Number(a.vuln.kev) ||
        compareSeverity(a.vuln.severity, b.vuln.severity) ||
        b.assets - a.assets,
    )
    .slice(0, 8),
)

const groupColumns: TableColumn<VulnGroup>[] = [
  { key: 'id', label: 'ID' },
  { key: 'title', label: '제목', hideBelow: 'md' },
  { key: 'severity', label: '심각도' },
  { key: 'kev', label: 'KEV' },
  { key: 'epss', label: 'EPSS', align: 'right', hideBelow: 'sm' },
  { key: 'assets', label: '영향 자산', align: 'right' },
  { key: 'live', label: '실행 중·노출', align: 'right', hideBelow: 'sm' },
]

// ── 숫자 줄 ──
const stats = computed(() => ({
  assets: assets.length,
  highSeverity: groups.value.filter((g) => g.vuln.severity === 'critical' || g.vuln.severity === 'high').length,
  kev: groups.value.filter((g) => g.vuln.kev).length,
  restart: processes.filter(needsRestart).length,
  suspicious: processes.filter(isSuspicious).length,
  limited: assets.filter((a) => a.coverage !== 'full').length,
}))

// ── 오른쪽 패널 ──
const severityCounts = computed(() => countBySeverity(findings))
const severityMax = computed(() => Math.max(1, ...SEVERITIES.map((s) => severityCounts.value[s])))
const barColor: Record<Severity, string> = { critical: 'bg-critical', high: 'bg-high', medium: 'bg-medium', low: 'bg-low' }

const coverageCounts = computed(() => {
  const map = new Map<Coverage, number>()
  for (const a of assets) map.set(a.coverage, (map.get(a.coverage) ?? 0) + 1)
  return (Object.keys(coverageLabel) as Coverage[]).map((c) => ({ coverage: c, count: map.get(c) ?? 0 }))
})
const coverageMax = computed(() => Math.max(1, ...coverageCounts.value.map((c) => c.count)))

const badFeeds = computed(() => feeds.filter((f) => f.status !== 'ok'))
const feedStatusLabel = { ok: '정상', stale: '지연', error: '오류' } as const

const agentStats = computed(() => ({
  online: agents.filter((a) => a.status === 'online').length,
  offline: agents.filter((a) => a.status === 'offline').length,
  pending: agents.filter((a) => a.status === 'pending_approval').length,
  revoked: agents.filter((a) => a.status === 'revoked').length,
  notPinned: agents.filter((a) => a.tlsMode !== 'pinned').length,
}))

// ── 최근 탐지 ──
const recent = computed(() =>
  findings
    .flatMap((f) => {
      const asset = getAsset(f.assetId)
      const component = getComponent(f.componentId)
      const vuln = getVuln(f.vulnId)
      return asset && component && vuln ? [{ ...f, asset, component, vuln }] : []
    })
    .sort((a, b) => b.firstDetected.localeCompare(a.firstDetected))
    .slice(0, 8),
)
type RecentRow = (typeof recent.value)[number]
const recentColumns: TableColumn<RecentRow>[] = [
  { key: 'asset', label: '자산' },
  { key: 'component', label: '컴포넌트', hideBelow: 'sm' },
  { key: 'vuln', label: '취약점' },
  { key: 'at', label: '탐지', align: 'right' },
]

const vulnTotal = computed(() => vulnerabilities.length)
</script>

<template>
  <div>
    <PageHeader title="대시보드" />

    <div class="grid grid-cols-2 gap-3 lg:grid-cols-6">
      <StatTile label="자산" :value="stats.assets" to="/assets" />
      <StatTile label="심각·높음 취약점" :value="stats.highSeverity" :hint="`전체 ${vulnTotal}건 중`" :tone="stats.highSeverity ? 'danger' : 'neutral'" to="/vulnerabilities" />
      <StatTile label="KEV 해당 취약점" :value="stats.kev" :tone="stats.kev ? 'danger' : 'neutral'" />
      <StatTile label="재시작 필요 프로세스" :value="stats.restart" :tone="stats.restart ? 'warn' : 'neutral'" to="/processes?view=restart" />
      <StatTile label="의심 프로세스" :value="stats.suspicious" :tone="stats.suspicious ? 'danger' : 'neutral'" to="/processes?view=suspicious" />
      <StatTile label="수집 범위 제한 자산" :value="stats.limited" :tone="stats.limited ? 'warn' : 'neutral'" to="/assets" />
    </div>

    <div class="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
      <Panel title="우선 조치 대상" flush class="xl:col-span-2">
        <DataTable
          :columns="groupColumns"
          :rows="topGroups"
          :row-key="(g) => g.vuln.id"
          :row-to="(g) => `/vulnerabilities/${g.vuln.id}`"
        >
          <template #cell-id="{ row }">
            <NuxtLink :to="`/vulnerabilities/${row.vuln.id}`" class="link mono whitespace-nowrap">{{ row.vuln.id }}</NuxtLink>
          </template>
          <template #cell-title="{ row }">
            <span class="line-clamp-1">{{ row.vuln.title }}</span>
          </template>
          <template #cell-severity="{ row }"><SeverityBadge :severity="row.vuln.severity" /></template>
          <template #cell-kev="{ row }">
            <StatusBadge v-if="row.vuln.kev" tone="danger" label="KEV" />
            <span v-else class="text-ink-3">—</span>
          </template>
          <template #cell-epss="{ row }"><span class="mono whitespace-nowrap">{{ formatEpss(row.vuln.epss) }}</span></template>
          <template #cell-assets="{ row }"><span class="mono whitespace-nowrap">{{ row.assets }}</span></template>
          <template #cell-live="{ row }">
            <span class="mono whitespace-nowrap">{{ row.running }} · {{ row.exposed }}</span>
          </template>
        </DataTable>
      </Panel>

      <div class="grid min-w-0 grid-cols-1 gap-4">
        <Panel title="심각도별 미해결">
          <ul class="grid gap-2">
            <li v-for="s in SEVERITIES" :key="s" class="grid grid-cols-[3rem_1fr_2.5rem] items-center gap-2 text-sm">
              <span>{{ severityLabel[s] }}</span>
              <div class="h-2 rounded-sm bg-surface-2">
                <div class="h-2 rounded-sm" :class="barColor[s]" :style="{ width: `${(severityCounts[s] / severityMax) * 100}%` }" />
              </div>
              <span class="mono text-right">{{ severityCounts[s] }}</span>
            </li>
          </ul>
        </Panel>

        <Panel title="수집 범위">
          <ul class="grid gap-2">
            <li v-for="c in coverageCounts" :key="c.coverage" class="grid grid-cols-[6rem_1fr_2.5rem] items-center gap-2 text-sm">
              <span class="truncate">{{ coverageLabel[c.coverage] }}</span>
              <div class="h-2 rounded-sm bg-surface-2">
                <div class="h-2 rounded-sm" :class="c.coverage === 'full' ? 'bg-ok' : 'bg-accent'" :style="{ width: `${(c.count / coverageMax) * 100}%` }" />
              </div>
              <span class="mono text-right">{{ c.count }}</span>
            </li>
          </ul>
        </Panel>

        <Panel title="취약점 피드">
          <p v-if="!badFeeds.length" class="text-sm text-ink-2">모든 피드가 정상입니다.</p>
          <ul v-else class="grid gap-2">
            <li v-for="f in badFeeds" :key="f.id" class="flex items-center justify-between gap-2 text-sm">
              <span class="min-w-0 truncate">{{ f.name }}</span>
              <StatusBadge :tone="f.status === 'error' ? 'danger' : 'warn'" :label="feedStatusLabel[f.status]" dot />
            </li>
          </ul>
        </Panel>

        <Panel title="에이전트">
          <dl class="kv">
            <dt>{{ agentStatusLabel.online }}</dt>
            <dd class="mono">{{ agentStats.online }}</dd>
            <dt>{{ agentStatusLabel.offline }}</dt>
            <dd class="mono">{{ agentStats.offline }}</dd>
            <dt>{{ agentStatusLabel.pending_approval }}</dt>
            <dd class="mono">{{ agentStats.pending }}</dd>
            <dt>{{ agentStatusLabel.revoked }}</dt>
            <dd class="mono">{{ agentStats.revoked }}</dd>
            <dt>TLS가 pinned 아님</dt>
            <dd class="mono">{{ agentStats.notPinned }}</dd>
          </dl>
        </Panel>
      </div>
    </div>

    <Panel title="최근 탐지" flush class="mt-4">
      <DataTable
        :columns="recentColumns"
        :rows="recent"
        :row-key="(r) => r.id"
      >
        <template #cell-asset="{ row }">
          <NuxtLink :to="`/assets/${row.asset.id}`" class="link">{{ row.asset.name }}</NuxtLink>
        </template>
        <template #cell-component="{ row }">
          {{ row.component.name }} <span class="mono whitespace-nowrap text-ink-2">{{ row.component.version }}</span>
        </template>
        <template #cell-vuln="{ row }">
          <NuxtLink :to="`/vulnerabilities/${row.vuln.id}`" class="link mono whitespace-nowrap">{{ row.vuln.id }}</NuxtLink>
        </template>
        <template #cell-at="{ row }"><TimeAgo :at="row.firstDetected" class="text-ink-2" /></template>
      </DataTable>
    </Panel>
  </div>
</template>
