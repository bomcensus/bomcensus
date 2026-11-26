<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import { getVulnerableImage, listVulnerableImages } from '~/api'

// Vulnerabilities of image contents, running or not. Only component-scoped judgments apply to images.
const props = defineProps<{ selected: string }>()
const emit = defineEmits<{ select: [digest: string] }>()

const q = ref('')
const { data: list, pending, error, refresh } = useLoad('vulns:images', () => listVulnerableImages({ limit: 1000 }))
const items = computed(() => {
  const needle = q.value.trim().toLowerCase()
  return (list.value?.items ?? []).filter(
    (i) => !needle || i.digest.includes(needle) || i.tags.some((t) => t.toLowerCase().includes(needle)),
  )
})
const current = computed(() => props.selected || items.value[0]?.digest || '')
const { data: detail, error: detailError, refresh: refreshDetail } = useLoad(
  () => `vulns:image:${current.value}`,
  () => (current.value ? getVulnerableImage(current.value) : Promise.resolve(undefined)),
)
const title = (tags: string[], digest: string) => tags[0] ?? shortHash(digest)
</script>

<template>
  <div>
    <FilterBar :count="items.length" :total="list?.total" unit="개">
      <SearchInput v-model="q" placeholder="태그, digest" />
    </FilterBar>
    <div class="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,22rem)_minmax(0,1fr)]">
      <Panel flush class="min-w-0 self-start">
        <LoadError v-if="error" :error="error" @retry="refresh" />
        <LoadingText v-else-if="pending && !list" class="p-3.5" />
        <p v-else-if="!items.length" class="px-3.5 py-3 text-sm text-ink-2">취약점이 있는 이미지가 없습니다.</p>
        <ul v-else class="max-h-[70vh] overflow-y-auto">
          <li v-for="i in items" :key="i.digest">
            <button
              type="button"
              class="block w-full border-b border-line px-3.5 py-2.5 text-left hover:bg-surface-2"
              :class="i.digest === current ? 'bg-accent-soft' : ''"
              :aria-current="i.digest === current ? 'true' : undefined"
              @click="emit('select', i.digest)"
            >
              <span class="flex items-center gap-1.5">
                <span v-if="i.severity" class="text-[11px]" :class="severityText[i.severity]">■</span>
                <span class="mono truncate text-sm font-medium" :title="i.tags.length ? i.tags.join('\n') : i.digest">{{ title(i.tags, i.digest) }}</span>
                <StatusBadge v-if="i.kev" tone="danger" label="KEV" />
                <span class="mono ml-auto text-xs text-ink-2">{{ i.score !== undefined ? i.score.toFixed(1) : '—' }}</span>
              </span>
              <span class="mono mt-0.5 block truncate text-xs text-ink-3" :title="i.digest">{{ shortHash(i.digest) }}</span>
              <span class="mt-1 block text-xs text-ink-3">
                CVE {{ i.cves }} · 컴포넌트 {{ i.components }} ·
                {{ i.containers ? `실행 중 컨테이너 ${i.containers}` : '실행 안 함' }}
              </span>
            </button>
          </li>
        </ul>
      </Panel>

      <div class="min-w-0">
        <Panel v-if="detailError"><LoadError :error="detailError" @retry="refreshDetail" /></Panel>
        <Panel v-else-if="!current"><p class="text-sm text-ink-2">왼쪽에서 이미지를 고르세요.</p></Panel>
        <Panel v-else-if="!detail || detail.image.digest !== current"><LoadingText /></Panel>
        <div v-else class="grid grid-cols-1 gap-4">
          <Panel>
            <h2 class="mono text-lg font-semibold break-all">{{ title(detail.image.tags, detail.image.digest) }}</h2>
            <dl class="kv mt-3">
              <dt>digest</dt>
              <dd>
                <NuxtLink :to="`/images/${encodeURIComponent(detail.image.digest)}`" class="link mono text-xs break-all">{{ detail.image.digest }}</NuxtLink>
              </dd>
              <template v-if="detail.image.tags.length > 1">
                <dt>태그</dt>
                <dd class="mono text-xs">{{ detail.image.tags.join(', ') }}</dd>
              </template>
              <dt>CVE</dt>
              <dd>
                <span class="mono">{{ detail.image.cves }}</span>
                <StatusBadge v-if="detail.image.kev" class="ml-1" tone="danger" :label="`KEV ${detail.image.kev}`" />
              </dd>
              <dt>실행</dt>
              <dd>{{ detail.image.containers ? `컨테이너 ${detail.image.containers} · 자산 ${detail.image.assets}` : '실행 중인 컨테이너 없음' }}</dd>
            </dl>
            <p class="mt-3 text-xs text-ink-3">이미지 안의 파일이 어느 레이어(베이스·앱)에서 왔는지는 수집하지 않아 나누어 보이지 않습니다.</p>
          </Panel>
          <Panel title="취약한 컴포넌트" flush>
            <div class="overflow-x-auto">
              <table class="w-full min-w-[640px] border-collapse text-sm">
                <thead>
                  <tr class="border-b border-line text-left text-xs text-ink-3">
                    <th class="py-2 pl-3.5 font-normal">컴포넌트 · 업데이트</th>
                    <th class="px-3 py-2 font-normal">CVE</th>
                    <th class="py-2 pl-3 pr-3.5 font-normal">수정</th>
                  </tr>
                </thead>
                <tbody>
                  <template v-for="c in detail.components" :key="c.componentId">
                    <tr v-for="(v, i) in c.cves" :key="v.vulnId" class="border-b border-line align-top" :class="v.deferred ? 'text-ink-3' : ''">
                      <td class="py-2 pl-3.5">
                        <template v-if="i === 0">
                          <NuxtLink :to="`/components/${c.componentId}`" class="font-medium hover:underline">{{ c.name }}</NuxtLink>
                          <span class="mono ml-1 text-xs text-ink-2">{{ versionText(c.version, c.build) }}</span>
                          <span v-if="fixTarget(c)" class="mono ml-1 text-xs" :title="lastAffectedHint(c)">→ {{ fixTarget(c) }}</span>
                        </template>
                      </td>
                      <td class="px-3 py-2">
                        <span class="inline-flex items-center gap-1.5">
                          <span v-if="v.severity" class="text-[11px]" :class="severityText[v.severity]">■</span>
                          <NuxtLink :to="`/vulnerabilities?view=cve&id=${encodeURIComponent(v.vulnId)}`" class="mono hover:underline">{{ v.vulnId }}</NuxtLink>
                          <span class="mono text-xs text-ink-2">{{ v.score !== undefined ? v.score.toFixed(1) : '' }}</span>
                          <StatusBadge v-if="v.kev" tone="danger" label="KEV" />
                          <StatusBadge v-if="v.deferred" label="유예" />
                        </span>
                      </td>
                      <td class="py-2 pl-3 pr-3.5">
                        <span v-if="fixTarget(v)" class="mono text-xs whitespace-nowrap" :title="lastAffectedHint(v)">→ {{ fixTarget(v) }}</span>
                        <span v-else class="text-xs text-ink-3">{{ fixStateLabel[v.fixState] }}</span>
                      </td>
                    </tr>
                  </template>
                </tbody>
              </table>
            </div>
          </Panel>
        </div>
      </div>
    </div>
  </div>
</template>
