<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { TriageRule } from '~/types'
import { revokeTriageRule, toApiError } from '~/api'

// A triage rule in one line: verdict, reason, scope, deferral and who; active rules can be revoked.
const props = defineProps<{ rule: TriageRule }>()
const emit = defineEmits<{ changed: [] }>()

const busy = ref(false)
const error = ref('')

const scopeText = computed(() => {
  const s = props.rule.scope
  if (s.kind === 'asset') return `자산 ${props.rule.scopeName ?? s.value}`
  if (s.kind === 'group') return `그룹 ${s.value}`
  return s.value
})
const deferText = computed(() => {
  const r = props.rule
  if (!r.active && r.expiresAt) return `유예 종료 ${formatDate(r.expiresAt)}`
  return r.expiresAt ? `${formatDate(r.expiresAt)}까지` : '영구'
})

async function revoke() {
  if (busy.value) return
  busy.value = true
  error.value = ''
  try {
    await revokeTriageRule(props.rule.id)
    emit('changed')
  } catch (e) {
    error.value = toApiError(e).message
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <span class="inline-flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-xs">
    <StatusBadge v-if="rule.revokedAt" label="취소됨" />
    <StatusBadge v-else-if="rule.active" tone="ok" label="영향 없음" />
    <StatusBadge v-else tone="warn" label="유예 종료" />
    <span>{{ justificationLabel[rule.justification] }}</span>
    <span class="text-ink-3">
      <span class="mono break-all">{{ scopeText }}</span> · {{ deferText }} · {{ rule.createdBy }} · {{ formatDate(rule.createdAt) }}
    </span>
    <span v-if="rule.note" class="text-ink-2">"{{ rule.note }}"</span>
    <button v-if="!rule.revokedAt" type="button" class="link" :disabled="busy" @click="revoke">{{ rule.active ? '취소' : '닫기' }}</button>
    <span v-if="error" class="text-critical">{{ error }}</span>
  </span>
</template>
