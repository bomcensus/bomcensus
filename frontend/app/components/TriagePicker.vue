<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { TriageJustification, TriageRule } from '~/types'
import { createTriageRule, toApiError } from '~/api'

// Judge that a vulnerability does not affect a scope (CycloneDX VEX not_affected),
// for good or until a date. The scope is a component version, or the asset or its group when given.
const open = defineModel<boolean>('open', { required: true })
const props = defineProps<{ vulnId: string; purl: string; asset?: { id: string; name: string; group?: string } }>()
const emit = defineEmits<{ saved: [rule: TriageRule] }>()

const reasons = Object.keys(justificationLabel) as TriageJustification[]
const reason = ref<TriageJustification>()
const scope = ref<'purl' | 'asset' | 'group'>('purl')
const pattern = ref('')
const defer = ref<'until' | 'forever'>('until')
const date = ref('')
const note = ref('')
const busy = ref(false)
const error = ref('')

const dayString = (d: Date) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
const after = (days: number) => dayString(new Date(Date.now() + days * 86400_000))
const presets = [
  { days: 30, label: '30일' },
  { days: 90, label: '90일' },
  { days: 365, label: '1년' },
]

watch(open, (v) => {
  if (!v) return
  reason.value = undefined
  scope.value = 'purl'
  pattern.value = props.purl.split(/[?#]/)[0] ?? props.purl
  defer.value = 'until'
  date.value = after(30)
  note.value = ''
  error.value = ''
})

const scopeValue = computed(() => {
  if (scope.value === 'asset') return props.asset?.id ?? ''
  if (scope.value === 'group') return props.asset?.group ?? ''
  return pattern.value.trim()
})
// The deferral lasts to the end of the chosen day.
const expiresAt = computed(() => (defer.value === 'until' && date.value ? new Date(`${date.value}T23:59:59`).toISOString() : undefined))
const valid = computed(() => !!reason.value && !!scopeValue.value && (defer.value === 'forever' || !!date.value))

async function save() {
  if (!valid.value || busy.value) return
  busy.value = true
  error.value = ''
  try {
    const rule = await createTriageRule({
      vulnId: props.vulnId,
      scope: { kind: scope.value, value: scopeValue.value },
      justification: reason.value!,
      note: note.value.trim() || undefined,
      expiresAt: expiresAt.value,
    })
    open.value = false
    emit('saved', rule)
  } catch (e) {
    error.value = toApiError(e).message
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <AppModal v-model:open="open" :title="`영향 없음 판정 · ${vulnId}`" wide>
    <div class="grid grid-cols-1 gap-4 text-sm">
      <div role="group" aria-label="영향 없음 사유">
        <span class="mb-1.5 block text-xs text-ink-2">영향 없음 사유 (CycloneDX justification)</span>
        <div class="flex flex-wrap gap-1.5">
          <button
            v-for="r in reasons"
            :key="r"
            type="button"
            :aria-pressed="reason === r"
            class="h-7 rounded-[5px] border px-2.5 text-xs whitespace-nowrap"
            :class="reason === r ? 'border-accent bg-accent-soft font-semibold text-accent' : 'border-line-strong bg-surface text-ink-2'"
            @click="reason = r"
          >
            {{ justificationLabel[r] }}
          </button>
        </div>
      </div>

      <div class="flex flex-wrap gap-6">
        <fieldset class="min-w-0 flex-1">
          <legend class="mb-1.5 text-xs text-ink-2">범위</legend>
          <label class="flex items-center gap-1.5">
            <input v-model="scope" type="radio" value="purl" class="size-[15px] accent-(--accent)" /> 이 컴포넌트 버전 전체
          </label>
          <input
            v-if="scope === 'purl'"
            v-model="pattern"
            type="text"
            class="input mono mt-1 ml-5 w-[calc(100%-1.25rem)] text-xs"
            spellcheck="false"
            aria-label="purl"
          />
          <label v-if="asset" class="mt-1 flex items-center gap-1.5">
            <input v-model="scope" type="radio" value="asset" class="size-[15px] accent-(--accent)" /> 이 자산만
            <span class="mono text-xs text-ink-3">{{ asset.name }}</span>
          </label>
          <label v-if="asset?.group" class="mt-1 flex items-center gap-1.5">
            <input v-model="scope" type="radio" value="group" class="size-[15px] accent-(--accent)" /> 자산 그룹
            <span class="mono text-xs text-ink-3">{{ asset.group }}</span>
          </label>
        </fieldset>
        <fieldset class="min-w-0">
          <legend class="mb-1.5 text-xs text-ink-2">유예</legend>
          <label class="flex items-center gap-1.5">
            <input v-model="defer" type="radio" value="forever" class="size-[15px] accent-(--accent)" /> 영구
            <span class="text-xs text-ink-3">취소할 때까지</span>
          </label>
          <label class="mt-1 flex items-center gap-1.5">
            <input v-model="defer" type="radio" value="until" class="size-[15px] accent-(--accent)" /> 기간 지정
          </label>
          <div v-if="defer === 'until'" class="mt-1 ml-5 flex flex-wrap items-center gap-1.5">
            <button
              v-for="p in presets"
              :key="p.days"
              type="button"
              :aria-pressed="date === after(p.days)"
              class="h-7 rounded-[5px] border px-2.5 text-xs"
              :class="date === after(p.days) ? 'border-accent bg-accent-soft font-semibold text-accent' : 'border-line-strong bg-surface text-ink-2'"
              @click="date = after(p.days)"
            >
              {{ p.label }}
            </button>
            <input v-model="date" type="date" :min="after(1)" class="input mono h-7 text-xs" aria-label="유예 끝나는 날" />
          </div>
        </fieldset>
      </div>

      <FormField label="메모">
        <input v-model="note" type="text" class="input w-full" maxlength="2000" placeholder="근거 (예: JNDI lookup 비활성화 설정 확인)" />
      </FormField>
      <p class="text-xs text-ink-3">
        조건에 맞는 새 자산에도 적용됩니다. 기간이 끝나면 다시 목록에 나타나고 "유예 종료"로 표시됩니다. OpenVEX로 내보낼 수 있습니다.
      </p>
      <p v-if="error" class="note note-danger" role="alert">{{ error }}</p>
    </div>
    <template #footer>
      <AppButton @click="open = false">취소</AppButton>
      <AppButton variant="primary" :disabled="!valid || busy" @click="save">영향 없음으로 저장</AppButton>
    </template>
  </AppModal>
</template>
