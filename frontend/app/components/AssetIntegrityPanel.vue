<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { IntegrityFinding, IntegrityPass } from '~/types'
import { getAssetIntegrity } from '~/api'

// The file integrity of one asset: its passes and the files that differ.
const props = defineProps<{ assetId: string }>()

const showAllowed = ref(false)
const { data, pending, error, refresh } = useLoad(
  () => `asset:${props.assetId}:integrity:${showAllowed.value}`,
  () => getAssetIntegrity(props.assetId, { includeAllowed: showAllowed.value || undefined }),
)

const allowing = ref<IntegrityFinding>()
const allowOpen = computed({
  get: () => !!allowing.value,
  set: (v) => {
    if (!v) allowing.value = undefined
  },
})

function passText(p: IntegrityPass): string {
  const parts = [`검사 ${formatNumber(p.checked)}개`, `제외 ${formatNumber(p.excluded)}개`]
  if (p.unreadable) parts.push(`읽지 못함 ${formatNumber(p.unreadable)}개`)
  return parts.join(' · ')
}
</script>

<template>
  <div class="space-y-4">
    <Panel title="파일 무결성 검사">
      <LoadError v-if="error" :error="error" @retry="refresh" />
      <LoadingText v-else-if="!data" />
      <dl v-else class="kv">
        <dt>상태</dt>
        <dd>
          <StatusBadge :tone="data.enabled ? 'ok' : 'neutral'" :label="data.enabled ? '켜짐' : '검사 꺼짐'" dot />
          <span v-if="data.mode" class="ml-2 text-xs text-ink-2">{{ integrityModeLabel[data.mode] }}</span>
        </dd>
        <dt>마지막 완료</dt>
        <dd>
          <template v-if="data.lastCompletedPass">
            {{ formatDateTime(data.lastCompletedPass.completedAt) }}
            <StatusBadge class="ml-1" :tone="integrityCoverageTone[data.lastCompletedPass.coverage]" :label="integrityCoverageLabel[data.lastCompletedPass.coverage]" />
            <div class="text-xs text-ink-2">{{ passText(data.lastCompletedPass) }}</div>
            <Diagnostic v-if="data.lastCompletedPass.reason" :text="data.lastCompletedPass.reason" class="mt-1" />
          </template>
          <span v-else class="text-ink-3">아직 없음</span>
        </dd>
        <template v-if="data.lastPass && !data.lastPass.completedAt">
          <dt>진행 중</dt>
          <dd>
            {{ formatDateTime(data.lastPass.startedAt) }} 시작 · 마지막 조각 <TimeAgo :at="data.lastPass.lastChunkAt" />
            <div class="text-xs text-ink-2">{{ passText(data.lastPass) }}</div>
          </dd>
        </template>
      </dl>
    </Panel>

    <Panel title="변경된 파일" flush>
      <template #actions>
        <label class="inline-flex items-center gap-1.5 text-sm">
          <input v-model="showAllowed" type="checkbox" class="size-[15px] accent-(--accent)" /> 허용한 항목도 보기
        </label>
      </template>
      <LoadingText v-if="pending && !data" class="p-3.5" />
      <p v-else-if="!data?.findings.length" class="px-3.5 py-3 text-sm text-ink-2">패키지 DB와 다른 파일이 없습니다.</p>
      <div v-else class="overflow-x-auto">
        <table class="w-full min-w-[820px] border-collapse text-sm">
          <thead>
            <tr class="border-b border-line text-left text-xs text-ink-3">
              <th class="py-2 pl-3.5 font-normal">상태</th>
              <th class="px-3 py-2 font-normal">경로 · 패키지</th>
              <th class="px-3 py-2 font-normal">기대값 / 실제값</th>
              <th class="px-3 py-2 font-normal">mtime</th>
              <th class="py-2 pl-3 pr-3.5 font-normal" />
            </tr>
          </thead>
          <tbody>
            <tr v-for="f in data.findings" :key="f.id" class="border-b border-line align-top last:border-b-0" :class="f.allowedBy ? 'text-ink-3' : ''">
              <td class="py-2.5 pl-3.5">
                <StatusBadge :tone="integrityStatusTone[f.status]" :label="integrityStatusLabel[f.status]" />
                <StatusBadge v-if="f.allowedBy" class="ml-1" label="허용됨" />
              </td>
              <td class="px-3 py-2.5">
                <div class="mono break-all text-xs">{{ f.path }}</div>
                <div class="text-xs text-ink-3">{{ f.package }} {{ f.version }}</div>
              </td>
              <td class="mono px-3 py-2.5 text-xs">
                <!-- Labels in their own column so that the digests line up. -->
                <div class="grid grid-cols-[auto_minmax(0,1fr)] gap-x-2">
                  <span class="text-ink-3">{{ integrityAlgoLabel[f.algo] ?? f.algo }}</span>
                  <span class="break-all">{{ f.expected }}</span>
                  <span />
                  <span class="break-all" :class="f.allowedBy ? '' : 'text-critical'">{{ f.status === 'missing' ? '파일 없음' : f.actual }}</span>
                  <template v-if="f.actualSha256 && f.algo !== 'sha256'">
                    <span class="text-ink-3">SHA-256</span>
                    <span class="break-all text-ink-3">{{ f.actualSha256 }}</span>
                  </template>
                </div>
              </td>
              <td class="px-3 py-2.5 text-xs whitespace-nowrap">{{ f.mtime ? formatDateTime(f.mtime) : '—' }}</td>
              <td class="py-2.5 pl-3 pr-3.5 text-right">
                <AppButton v-if="!f.allowedBy" size="sm" @click="allowing = f">허용…</AppButton>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </Panel>

    <IntegrityAllowModal
      v-if="allowing"
      v-model:open="allowOpen"
      :path="allowing.path"
      :status="allowing.status"
      :sha256="allowing.actualSha256"
      :nodes="[{ assetId: allowing.assetId, assetName: allowing.assetName }]"
      scope="asset"
      :asset-ids="[allowing.assetId]"
      @saved="refresh"
    />
  </div>
</template>
