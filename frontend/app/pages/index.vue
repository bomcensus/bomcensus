<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import { getDashboard } from '~/api'

useHead({ title: '대시보드 · bomcensus' })

const { data: dashboard, error, refresh } = useLoad('dashboard', getDashboard)

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
