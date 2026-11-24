<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import { getVulnerableProcess, listVulnerableProcesses } from '~/api'

// Vulnerabilities by the executable of the processes that load vulnerable components.
const props = defineProps<{ selected: string }>()
const emit = defineEmits<{ select: [exe: string] }>()

const q = ref('')
const { data: list, pending, error, refresh } = useLoad('vulns:processes', () => listVulnerableProcesses({ limit: 1000 }))
const items = computed(() => {
  const needle = q.value.trim().toLowerCase()
  return (list.value?.items ?? []).filter((p) => !needle || p.exe.toLowerCase().includes(needle))
})
const current = computed(() => props.selected || items.value[0]?.exe || '')
const { data: detail, error: detailError, refresh: refreshDetail } = useLoad(
  () => `vulns:process:${current.value}`,
  () => (current.value ? getVulnerableProcess(current.value) : Promise.resolve(undefined)),
)
const base = (exe: string) => exe.split('/').pop() ?? exe
</script>

<template>
  <div>
    <FilterBar :count="items.length" :total="list?.total" unit="개">
      <SearchInput v-model="q" placeholder="실행 파일 경로" />
    </FilterBar>
    <div class="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,22rem)_minmax(0,1fr)]">
      <Panel flush class="min-w-0 self-start">
        <LoadError v-if="error" :error="error" @retry="refresh" />
        <LoadingText v-else-if="pending && !list" class="p-3.5" />
        <p v-else-if="!items.length" class="px-3.5 py-3 text-sm text-ink-2">취약한 컴포넌트를 로드한 프로세스가 없습니다.</p>
        <ul v-else class="max-h-[70vh] overflow-y-auto">
          <li v-for="p in items" :key="p.exe">
            <button
              type="button"
              class="block w-full border-b border-line px-3.5 py-2.5 text-left hover:bg-surface-2"
              :class="p.exe === current ? 'bg-accent-soft' : ''"
              :aria-current="p.exe === current ? 'true' : undefined"
              @click="emit('select', p.exe)"
            >
              <span class="flex items-center gap-1.5">
                <span v-if="p.severity" class="text-[11px]" :class="severityText[p.severity]">■</span>
                <span class="mono text-sm font-medium">{{ base(p.exe) }}</span>
                <StatusBadge v-if="p.kev" tone="danger" label="KEV" />
                <span class="mono ml-auto text-xs text-ink-2">{{ p.score !== undefined ? p.score.toFixed(1) : '—' }}</span>
              </span>
              <span class="mono mt-0.5 block truncate text-xs text-ink-3">{{ p.exe }}</span>
              <span class="mt-1 block text-xs text-ink-3">
                자산 {{ p.assets }} · listen ports {{ p.listening }} · CVE {{ p.cves }}
              </span>
            </button>
          </li>
        </ul>
      </Panel>

      <div class="min-w-0">
        <Panel v-if="detailError"><LoadError :error="detailError" @retry="refreshDetail" /></Panel>
        <Panel v-else-if="!current"><p class="text-sm text-ink-2">왼쪽에서 프로세스를 고르세요.</p></Panel>
        <Panel v-else-if="!detail || detail.process.exe !== current"><LoadingText /></Panel>
        <div v-else class="grid grid-cols-1 gap-4">
          <Panel>
            <h2 class="mono text-lg font-semibold">{{ base(detail.process.exe) }}</h2>
            <p class="mono text-xs break-all text-ink-2">{{ detail.process.exe }}</p>
            <dl class="kv mt-3">
              <dt>자산</dt>
              <dd class="mono">{{ detail.process.assets }}</dd>
              <dt>프로세스</dt>
              <dd class="mono">{{ detail.process.processes }}</dd>
              <dt>listen ports</dt>
              <dd class="mono">{{ detail.process.listening }}</dd>
              <dt>CVE</dt>
              <dd>
                <span class="mono">{{ detail.process.cves }}</span>
                <StatusBadge v-if="detail.process.kev" class="ml-1" tone="danger" :label="`KEV ${detail.process.kev}`" />
              </dd>
            </dl>
          </Panel>
          <Panel title="로드한 컴포넌트" flush>
            <VulnActionTable :items="detail.components" />
          </Panel>
          <Panel title="위치" flush>
            <VulnLocations :items="detail.locations" :where="locationWhere" :process-text="locationProcess" />
          </Panel>
        </div>
      </div>
    </div>
  </div>
</template>
