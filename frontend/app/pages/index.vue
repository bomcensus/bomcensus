<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import { getDashboard, getVulnerabilitySummary, listProcesses } from '~/api'

useHead({ title: '대시보드 · bomcensus' })

const { data: dashboard, error, refresh } = useLoad('dashboard', getDashboard)
const { data: vulns, error: vulnsError, refresh: refreshVulns } = useLoad('dashboard:vulns', getVulnerabilitySummary)
// The dashboard shows at most 10 suspicious processes; the rest are on the processes page.
const suspiciousLimit = 10
const { data: suspicious } = useLoad('dashboard:suspicious', () => listProcesses({ view: 'suspicious', limit: suspiciousLimit }))

const exposures = ['listening', 'running', 'installed', 'unknown'] as const

const coverageMax = computed(() => Math.max(1, ...(dashboard.value?.coverage.map((c) => c.count) ?? [])))
</script>

<template>
  <div>
    <PageHeader title="대시보드" />

    <Panel v-if="error">
      <LoadError :error="error" @retry="refresh" />
    </Panel>
    <Panel v-else-if="!dashboard">
      <LoadingText />
    </Panel>

    <template v-else>
      <div class="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile
          label="자산"
          :value="dashboard.assets.total"
          :hint="`호스트 ${dashboard.assets.hosts} · 워크로드 ${dashboard.assets.workloads}`"
          to="/assets"
        />
        <StatTile
          label="재시작 필요 프로세스"
          :value="dashboard.processes.restartRequired"
          :tone="dashboard.processes.restartRequired ? 'warn' : 'neutral'"
          to="/processes?view=restart"
        />
        <StatTile
          label="의심 프로세스"
          :value="dashboard.processes.suspicious"
          :tone="dashboard.processes.suspicious ? 'danger' : 'neutral'"
          to="/processes?view=suspicious"
        />
        <StatTile
          label="수집 범위 제한 자산"
          :value="dashboard.assets.limited"
          :tone="dashboard.assets.limited ? 'warn' : 'neutral'"
          to="/assets"
        />
      </div>

      <template v-if="vulns">
        <div class="mt-3 grid grid-cols-2 gap-3 lg:grid-cols-4">
          <StatTile
            label="긴급 업데이트 필요"
            :value="vulns.urgent.components"
            :tone="vulns.urgent.components ? 'danger' : 'neutral'"
            :hint="`치명·높음 × listen ports·실행 · CVE ${vulns.urgent.cves}`"
            to="/vulnerabilities?view=component"
          />
          <StatTile
            label="취약점"
            :value="vulns.totals.cves"
            :hint="`컴포넌트 ${vulns.totals.components} · KEV ${vulns.totals.kev}${vulns.deferred ? ` · 유예 ${vulns.deferred}` : ''}`"
            to="/vulnerabilities"
          />
          <StatTile label="취약점이 있는 자산" :value="vulns.totals.assets" to="/assets" />
          <StatTile
            label="확인 범위 제한"
            :value="vulns.unsupported"
            :tone="vulns.unsupported ? 'warn' : 'neutral'"
            hint="feed 서버에 데이터가 없는 컴포넌트"
          />
        </div>

        <Panel
          class="mt-4"
          title="취약점 · 조치 단위"
          :description="vulns.revision !== undefined ? `취약점 데이터 rev ${vulns.revision} · ${formatDateTime(vulns.checkedAt)}` : 'feed 서버에 아직 연결하지 않았습니다'"
          flush
        >
          <template #actions>
            <span class="hidden flex-wrap gap-3 sm:flex">
              <ExposureMeter v-for="e in exposures" :key="e" :exposure="e" />
            </span>
          </template>
          <p v-if="!vulns.actions.length" class="px-3.5 py-3 text-sm text-ink-2">열린 취약점이 없습니다.</p>
          <VulnActionTable v-else :items="vulns.actions" :more="vulns.actionsTotal - vulns.actions.length" />
        </Panel>
      </template>
      <Panel v-else-if="vulnsError" class="mt-4">
        <LoadError :error="vulnsError" @retry="refreshVulns" />
      </Panel>

      <Panel v-if="suspicious?.items.length" class="mt-4" title="의심 프로세스" description="교체·삭제된 실행 파일, fileless 실행" flush>
        <div class="overflow-x-auto">
          <table class="w-full min-w-[640px] border-collapse text-sm">
            <thead>
              <tr class="border-b border-line text-left text-xs text-ink-3">
                <th class="py-2 pl-3.5 font-normal">프로세스</th>
                <th class="px-3 py-2 font-normal">자산</th>
                <th class="px-3 py-2 font-normal">경로</th>
                <th class="px-3 py-2 font-normal">listen ports</th>
                <th class="py-2 pl-3 pr-3.5 text-right font-normal">시작</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="p in suspicious.items" :key="p.id" class="border-b border-line align-top">
                <td class="py-2 pl-3.5">
                  <StatusBadge :tone="exeStateTone[p.exeState]" :label="exeStateLabel[p.exeState]" />
                  <span class="mono ml-1.5">{{ p.exePath.split('/').pop() }}</span>
                  <span class="mono ml-1 text-xs text-ink-3">{{ p.pid }} · {{ p.user }}</span>
                </td>
                <td class="px-3 py-2">
                  <NuxtLink :to="`/assets/${p.assetId}?tab=processes`" class="hover:underline">{{ p.assetName }}</NuxtLink>
                  <span v-if="p.container" class="mono ml-1 text-xs text-ink-3">{{ p.container }}</span>
                </td>
                <td class="mono px-3 py-2 text-xs break-all text-ink-2">{{ p.exePath }}</td>
                <td class="mono px-3 py-2 text-xs">{{ p.listen.length ? p.listen.map((l) => `${l.proto}/${l.port}`).join(', ') : '—' }}</td>
                <td class="py-2 pl-3 pr-3.5 text-right text-xs whitespace-nowrap"><TimeAgo :at="p.startedAt" /></td>
              </tr>
              <tr v-if="suspicious.total > suspicious.items.length">
                <td colspan="5" class="px-3.5 py-2.5 text-sm">
                  <NuxtLink to="/processes?view=suspicious" class="link">+ {{ suspicious.total - suspicious.items.length }}개 자세히 보기</NuxtLink>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </Panel>

      <div class="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2">
        <Panel title="수집 범위" class="min-w-0">
          <ul class="grid gap-2">
            <li v-for="c in dashboard.coverage" :key="c.coverage" class="grid grid-cols-[6rem_1fr_2.5rem] items-center gap-2 text-sm">
              <span class="truncate">{{ coverageLabel[c.coverage] }}</span>
              <div class="h-2 rounded-sm bg-surface-2">
                <div class="h-2 rounded-sm" :class="c.coverage === 'full' ? 'bg-ok' : 'bg-accent'" :style="{ width: `${(c.count / coverageMax) * 100}%` }" />
              </div>
              <span class="mono text-right">{{ c.count }}</span>
            </li>
          </ul>
        </Panel>

        <Panel title="에이전트" class="min-w-0">
          <dl class="kv">
            <dt>{{ agentStatusLabel.online }}</dt>
            <dd class="mono">{{ dashboard.agents.online }}</dd>
            <dt>{{ agentStatusLabel.offline }}</dt>
            <dd class="mono">{{ dashboard.agents.offline }}</dd>
            <dt>{{ agentStatusLabel.pending_approval }}</dt>
            <dd class="mono">{{ dashboard.agents.pendingApproval }}</dd>
            <dt>{{ agentStatusLabel.revoked }}</dt>
            <dd class="mono">{{ dashboard.agents.revoked }}</dd>
            <dt>TLS가 pinned 아님</dt>
            <dd class="mono">{{ dashboard.agents.notPinned }}</dd>
            <dt>TLS 중간에서 풀림</dt>
            <dd class="mono" :class="dashboard.agents.tlsIntercepted ? 'font-semibold text-critical' : ''">{{ dashboard.agents.tlsIntercepted }}</dd>
          </dl>
        </Panel>
      </div>
    </template>
  </div>
</template>
