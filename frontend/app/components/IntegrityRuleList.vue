<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { IntegrityAllowRule } from '~/types'
import { listIntegrityAllowRules, revokeIntegrityAllowRule, toApiError } from '~/api'

// The file integrity allow rules, newest first, with the findings each hides now.
const emit = defineEmits<{ changed: [] }>()
const includeRevoked = ref(false)
const { data: list, pending, error, refresh } = useLoad(
  () => `integrity:rules:${includeRevoked.value}`,
  () => listIntegrityAllowRules({ includeRevoked: includeRevoked.value || undefined, limit: 500 }),
)

// Revoking asks inline: the row shows what comes back.
const confirming = ref('')
const busy = ref(false)
const revokeError = ref('')

async function revoke(r: IntegrityAllowRule) {
  if (busy.value) return
  busy.value = true
  revokeError.value = ''
  try {
    await revokeIntegrityAllowRule(r.id)
    confirming.value = ''
    await refresh()
    emit('changed')
  } catch (e) {
    revokeError.value = toApiError(e).message
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div>
    <FilterBar :count="list?.total" unit="개">
      <label class="inline-flex items-center gap-1.5 text-sm">
        <input v-model="includeRevoked" type="checkbox" class="size-[15px] accent-(--accent)" /> 해제한 규칙도 보기
      </label>
    </FilterBar>
    <p v-if="revokeError" class="note note-danger mb-3" role="alert">{{ revokeError }}</p>
    <Panel flush>
      <LoadError v-if="error" :error="error" @retry="refresh" />
      <LoadingText v-else-if="pending && !list" class="p-3.5" />
      <p v-else-if="!list?.items.length" class="px-3.5 py-3 text-sm text-ink-2">허용 규칙이 없습니다. 검사 결과에서 "허용…"으로 추가합니다.</p>
      <div v-else class="overflow-x-auto">
        <table class="w-full min-w-[820px] border-collapse text-sm">
          <thead>
            <tr class="border-b border-line text-left text-xs text-ink-3">
              <th class="py-2 pl-3.5 font-normal">범위</th>
              <th class="px-3 py-2 font-normal">경로 / 실제 SHA-256</th>
              <th class="px-3 py-2 text-right font-normal">숨긴 노드</th>
              <th class="px-3 py-2 font-normal">사유</th>
              <th class="px-3 py-2 font-normal">만든 사람</th>
              <th class="py-2 pl-3 pr-3.5 font-normal" />
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in list.items" :key="r.id" class="border-b border-line align-top last:border-b-0" :class="r.revokedAt ? 'text-ink-3' : ''">
              <td class="py-2.5 pl-3.5">
                <StatusBadge tone="info" :label="r.scope === 'fleet' ? '같은 해시 전체' : '노드'" />
                <NuxtLink v-if="r.assetId" :to="`/assets/${r.assetId}?tab=integrity`" class="mono mt-1 block text-xs hover:underline">
                  {{ r.assetName || r.assetId }}
                </NuxtLink>
              </td>
              <td class="px-3 py-2.5">
                <div class="mono break-all text-xs">{{ r.path }}</div>
                <div class="mono text-xs text-ink-3" :title="r.actualSha256 || undefined">{{ r.actualSha256 ? `${r.actualSha256.slice(0, 16)}…` : '누락' }}</div>
              </td>
              <td class="mono px-3 py-2.5 text-right">{{ r.revokedAt ? '—' : r.hidden }}</td>
              <td class="px-3 py-2.5 text-xs">{{ r.note }}</td>
              <td class="px-3 py-2.5 text-xs">
                <div>{{ r.createdBy }}</div>
                <div class="text-ink-3">{{ formatDateTime(r.createdAt) }}</div>
                <div v-if="r.revokedAt" class="mt-0.5">{{ r.revokedBy }}이(가) {{ formatDateTime(r.revokedAt) }}에 해제</div>
              </td>
              <td class="py-2.5 pl-3 pr-3.5 text-right whitespace-nowrap">
                <template v-if="!r.revokedAt">
                  <span v-if="confirming === r.id" class="inline-flex items-center gap-1.5 text-xs text-ink-2">
                    {{ r.hidden }}개 노드에서 다시 보입니다.
                    <AppButton size="sm" variant="danger" :disabled="busy" @click="revoke(r)">해제</AppButton>
                    <AppButton size="sm" @click="confirming = ''">취소</AppButton>
                  </span>
                  <AppButton v-else size="sm" variant="danger" @click="confirming = r.id">해제</AppButton>
                </template>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </Panel>
  </div>
</template>
