<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import { listTriageRules } from '~/api'

// The triage rules, newest first, with the open findings each decides now.
const emit = defineEmits<{ changed: [] }>()
const includeRevoked = ref(false)
const { data: list, pending, error, refresh } = useLoad(
  () => `vulns:rules:${includeRevoked.value}`,
  () => listTriageRules({ includeRevoked: includeRevoked.value || undefined }),
)
async function changed() {
  await refresh()
  emit('changed')
}
</script>

<template>
  <div>
    <FilterBar :count="list?.total" unit="개">
      <label class="inline-flex items-center gap-1.5 text-sm">
        <input v-model="includeRevoked" type="checkbox" class="size-[15px] accent-(--accent)" /> 취소한 판정도 보기
      </label>
    </FilterBar>
    <Panel flush>
      <LoadError v-if="error" :error="error" @retry="refresh" />
      <LoadingText v-else-if="pending && !list" class="p-3.5" />
      <p v-else-if="!list?.items.length" class="px-3.5 py-3 text-sm text-ink-2">판정이 없습니다. 취약점 상세에서 "판정…"으로 추가합니다.</p>
      <div v-else class="overflow-x-auto">
        <table class="w-full min-w-[720px] border-collapse text-sm">
          <thead>
            <tr class="border-b border-line text-left text-xs text-ink-3">
              <th class="py-2 pl-3.5 font-normal">취약점</th>
              <th class="px-3 py-2 font-normal">판정</th>
              <th class="py-2 pl-3 pr-3.5 text-right font-normal">유예 중</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in list.items" :key="r.id" class="border-b border-line align-top last:border-b-0" :class="r.revokedAt ? 'text-ink-3' : ''">
              <td class="py-2.5 pl-3.5">
                <NuxtLink :to="`/vulnerabilities?view=cve&id=${encodeURIComponent(r.vulnId)}`" class="mono font-medium hover:underline">{{ r.vulnId }}</NuxtLink>
              </td>
              <td class="px-3 py-2.5">
                <TriageRuleBadge :rule="r" @changed="changed" />
                <div v-if="r.revokedAt" class="mt-0.5 text-xs">{{ r.revokedBy }}이(가) {{ formatDateTime(r.revokedAt) }}에 취소</div>
              </td>
              <td class="mono py-2.5 pl-3 pr-3.5 text-right whitespace-nowrap">
                <template v-if="r.active">{{ r.findings ?? 0 }}곳 · 자산 {{ r.assets ?? 0 }}</template>
                <span v-else class="text-ink-3">—</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </Panel>
  </div>
</template>
