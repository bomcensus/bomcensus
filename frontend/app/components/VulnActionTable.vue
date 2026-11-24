<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { Exposure, ExposureCounts, VulnComponent, VulnCve } from '~/types'
import { getVulnerableComponent, toApiError } from '~/api'

// Update actions (one per vulnerable component). A row expands to its CVEs,
// at most `cveLimit` of them; the rest are behind a link.
const props = withDefaults(defineProps<{ items: VulnComponent[]; more?: number; cveLimit?: number }>(), { more: 0, cveLimit: 10 })

const open = ref(new Set<string>())
const cves = ref<Record<string, VulnCve[]>>({})
const errors = ref<Record<string, string>>({})

async function toggle(c: VulnComponent) {
  const next = new Set(open.value)
  if (next.has(c.componentId)) {
    next.delete(c.componentId)
  } else {
    next.add(c.componentId)
    if (!cves.value[c.componentId]) {
      try {
        const d = await getVulnerableComponent(c.componentId)
        cves.value = { ...cves.value, [c.componentId]: d.cves }
      } catch (e) {
        errors.value = { ...errors.value, [c.componentId]: toApiError(e).message }
      }
    }
  }
  open.value = next
}

const severityText: Record<string, string> = {
  critical: 'text-critical',
  high: 'text-high',
  medium: 'text-medium',
  low: 'text-low',
  none: 'text-ink-3',
}

function mix(c: ExposureCounts): string {
  const parts: [Exposure, number][] = [
    ['listening', c.listening],
    ['running', c.running],
    ['installed', c.installed],
    ['unknown', c.unknown],
  ]
  return parts
    .filter(([, n]) => n > 0)
    .map(([e, n]) => `${exposureLabel[e]} ${n}`)
    .join(' · ')
}

function processNote(v: VulnCve): string {
  const p = v.processes?.[0]
  if (!p) return ''
  const exe = p.exe.split('/').pop() ?? p.exe
  return p.ports.length ? `${exe} · ${p.ports.join(', ')}` : exe
}

const sevCounts = (c: VulnComponent) =>
  (['critical', 'high', 'medium', 'low'] as const).map((k) => ({ k, n: c.severityCounts[k] })).filter((x) => x.n > 0)
</script>

<template>
  <div class="overflow-x-auto">
    <table class="w-full min-w-[760px] border-collapse text-sm">
      <thead>
        <tr class="border-b border-line text-left text-xs text-ink-3">
          <th class="w-24 py-2 pl-3.5 font-normal">최고 CVSS</th>
          <th class="px-3 py-2 font-normal">컴포넌트 · 업데이트</th>
          <th class="w-36 px-3 py-2 font-normal">CVE</th>
          <th class="w-44 px-3 py-2 font-normal">영향도</th>
          <th class="hidden px-3 py-2 font-normal lg:table-cell">프로세스</th>
          <th class="w-16 py-2 pl-3 pr-3.5 text-right font-normal">자산</th>
        </tr>
      </thead>
      <tbody>
        <template v-for="c in props.items" :key="c.componentId">
          <tr
            class="cursor-pointer border-b border-line align-top hover:bg-surface-2"
            :aria-expanded="open.has(c.componentId)"
            @click="toggle(c)"
          >
            <td class="py-2.5 pl-3.5">
              <span class="inline-flex items-center gap-1.5 whitespace-nowrap">
                <span class="w-2 text-xs text-ink-3">{{ open.has(c.componentId) ? '▾' : '▸' }}</span>
                <span v-if="c.severity" class="text-[11px]" :class="severityText[c.severity]">■</span>
                <span class="mono">{{ c.score !== undefined ? c.score.toFixed(1) : '—' }}</span>
              </span>
            </td>
            <td class="min-w-0 px-3 py-2.5">
              <NuxtLink :to="`/vulnerabilities?view=component&id=${c.componentId}`" class="font-medium hover:underline" @click.stop>{{ c.name }}</NuxtLink>
              <span class="mono ml-1.5 text-xs whitespace-nowrap text-ink-2">{{ c.version }}</span>
              <span v-if="c.fixedVersion" class="mono ml-1.5 whitespace-nowrap text-xs">→ {{ c.fixedVersion }}</span>
              <span v-else class="ml-1.5 text-xs text-ink-3">수정 버전 없음</span>
            </td>
            <td class="px-3 py-2.5">
              <span class="mono">{{ c.cves }}</span>
              <StatusBadge v-if="c.kev" class="ml-1" tone="danger" :label="`KEV ${c.kev}`" />
              <span class="ml-1.5 inline-flex gap-1">
                <span v-for="s in sevCounts(c)" :key="s.k" class="mono text-[10px]" :class="severityText[s.k]">■{{ s.n }}</span>
              </span>
            </td>
            <td class="px-3 py-2.5">
              <ExposureMeter :exposure="c.exposure" />
              <div class="text-xs text-ink-3">{{ mix(c.exposureCounts) }}</div>
            </td>
            <td class="hidden px-3 py-2.5 lg:table-cell">
              <span v-if="!c.processes.length" class="text-ink-3">—</span>
              <span v-else class="flex flex-wrap gap-1">
                <span v-for="p in c.processes.slice(0, 3)" :key="p.exe" class="mono rounded-sm bg-surface-2 px-1.5 text-xs">
                  {{ p.exe.split('/').pop() }} ×{{ p.count }}
                </span>
              </span>
            </td>
            <td class="mono py-2.5 pl-3 pr-3.5 text-right">{{ c.assets }}</td>
          </tr>
          <template v-if="open.has(c.componentId)">
            <tr v-if="errors[c.componentId]" class="border-b border-line bg-surface-2">
              <td colspan="6" class="px-3.5 py-2 text-sm text-critical">{{ errors[c.componentId] }}</td>
            </tr>
            <tr v-else-if="!cves[c.componentId]" class="border-b border-line bg-surface-2">
              <td colspan="6" class="px-3.5 py-2"><LoadingText /></td>
            </tr>
            <template v-else>
              <tr v-for="v in cves[c.componentId]!.slice(0, cveLimit)" :key="v.vulnId" class="border-b border-line bg-surface-2 align-top text-xs">
                <td class="py-2 pl-8">
                  <span class="inline-flex items-center gap-1.5 whitespace-nowrap">
                    <span v-if="v.severity" class="text-[11px]" :class="severityText[v.severity]">■</span>
                    <span class="mono">{{ v.score !== undefined ? v.score.toFixed(1) : '—' }}</span>
                  </span>
                </td>
                <td class="px-3 py-2">
                  <NuxtLink :to="`/vulnerabilities?view=cve&id=${encodeURIComponent(v.vulnId)}`" class="mono font-medium hover:underline">{{ v.vulnId }}</NuxtLink>
                  <StatusBadge v-if="v.kev" class="ml-1" tone="danger" label="KEV" />
                  <span v-if="v.summary" class="ml-1.5 text-ink-2">{{ v.summary }}</span>
                </td>
                <td class="mono px-3 py-2">
                  <template v-if="v.fixedVersion">→ {{ v.fixedVersion }}</template>
                  <span v-else-if="v.fixState" class="text-ink-3">{{ fixStateLabel[v.fixState] }}</span>
                </td>
                <td class="px-3 py-2"><ExposureMeter :exposure="v.exposure" /></td>
                <td class="mono hidden px-3 py-2 text-ink-2 lg:table-cell">{{ processNote(v) }}</td>
                <td class="mono py-2 pl-3 pr-3.5 text-right">{{ v.assets }}</td>
              </tr>
              <tr v-if="cves[c.componentId]!.length > cveLimit" class="border-b border-line bg-surface-2 text-xs">
                <td colspan="6" class="py-2 pl-8">
                  <NuxtLink :to="`/vulnerabilities?view=component&id=${c.componentId}`" class="link">
                    + {{ cves[c.componentId]!.length - cveLimit }}개 자세히 보기
                  </NuxtLink>
                </td>
              </tr>
            </template>
          </template>
        </template>
        <tr v-if="more > 0">
          <td colspan="6" class="px-3.5 py-2.5 text-sm">
            <NuxtLink to="/vulnerabilities?view=component" class="link">+ {{ more }}개 자세히 보기</NuxtLink>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
