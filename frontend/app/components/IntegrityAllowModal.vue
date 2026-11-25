<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { IntegrityAllowRuleScope, IntegrityStatus } from '~/types'
import { createIntegrityAllowRules, toApiError } from '~/api'

// Allows one changed file (path + status + actual SHA-256) on chosen assets or on every asset.
const open = defineModel<boolean>('open', { required: true })
const props = defineProps<{
  path: string
  status: IntegrityStatus
  sha256?: string
  nodes: { assetId: string; assetName: string }[]
  // Preselected scope and assets; the asset page starts with its own asset.
  scope?: IntegrityAllowRuleScope
  assetIds?: string[]
}>()
const emit = defineEmits<{ saved: [] }>()

const scope = ref<IntegrityAllowRuleScope>('fleet')
const chosen = ref<string[]>([])
const note = ref('')
const busy = ref(false)
const error = ref('')

watch(open, (v) => {
  if (!v) return
  scope.value = props.scope ?? (props.nodes.length > 1 ? 'fleet' : 'asset')
  chosen.value = props.assetIds ? [...props.assetIds] : props.nodes.slice(0, 1).map((n) => n.assetId)
  note.value = ''
  error.value = ''
})

const valid = computed(() => note.value.trim() !== '' && (scope.value === 'fleet' || chosen.value.length > 0))

async function save() {
  if (!valid.value || busy.value) return
  busy.value = true
  error.value = ''
  try {
    await createIntegrityAllowRules({
      scope: scope.value,
      assetIds: scope.value === 'asset' ? chosen.value : undefined,
      path: props.path,
      status: props.status,
      actualSha256: props.status === 'modified' ? props.sha256 : undefined,
      note: note.value.trim(),
    })
    open.value = false
    emit('saved')
  } catch (e) {
    error.value = toApiError(e).message
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <AppModal v-model:open="open" title="변경 허용">
    <form id="integrity-allow-form" class="grid grid-cols-1 gap-3" @submit.prevent="save">
      <div class="text-sm">
        <div class="mono break-all">{{ path }}</div>
        <div class="mt-0.5 text-xs text-ink-2">
          <template v-if="status === 'modified'">SHA-256 <span class="mono">{{ sha256?.slice(0, 16) }}…</span></template>
          <template v-else>누락된 파일</template>
        </div>
      </div>

      <label class="grid cursor-pointer grid-cols-[auto_1fr] gap-2 rounded-md border p-2.5" :class="scope === 'asset' ? 'border-accent bg-accent-soft' : 'border-line'">
        <input v-model="scope" type="radio" value="asset" class="mt-0.5 accent-(--accent)" />
        <span>
          <span class="block text-sm font-semibold">선택한 노드만</span>
          <span class="block text-xs text-ink-2">다른 노드에서 같은 해시가 나오면 그 노드에서는 보입니다.</span>
          <span v-if="scope === 'asset'" class="mt-1.5 flex flex-wrap gap-x-3 gap-y-1">
            <label v-for="n in nodes" :key="n.assetId" class="inline-flex items-center gap-1.5 text-xs">
              <input v-model="chosen" type="checkbox" :value="n.assetId" class="accent-(--accent)" />
              <span class="mono">{{ n.assetName || n.assetId }}</span>
            </label>
          </span>
        </span>
      </label>
      <label class="grid cursor-pointer grid-cols-[auto_1fr] gap-2 rounded-md border p-2.5" :class="scope === 'fleet' ? 'border-accent bg-accent-soft' : 'border-line'">
        <input v-model="scope" type="radio" value="fleet" class="mt-0.5 accent-(--accent)" />
        <span>
          <span class="block text-sm font-semibold">같은 해시의 모든 노드 (현재 {{ nodes.length }}대)</span>
          <span class="block text-xs text-ink-2">이후 같은 경로에서 같은 해시를 보고하는 노드도 숨깁니다.</span>
        </span>
      </label>

      <FormField label="사유" hint="허용 규칙 목록에 남습니다.">
        <textarea v-model="note" class="input min-h-16 w-full" maxlength="1000" placeholder="예: 배포 파이프라인이 덮어쓰는 기본 페이지" />
      </FormField>
      <p class="text-xs text-ink-3">파일이 다시 바뀌어 해시가 달라지면 새 항목으로 다시 보입니다.</p>
      <p v-if="error" class="note note-danger" role="alert">{{ error }}</p>
    </form>
    <template #footer>
      <AppButton @click="open = false">취소</AppButton>
      <AppButton type="submit" form="integrity-allow-form" variant="primary" :disabled="!valid || busy">허용</AppButton>
    </template>
  </AppModal>
</template>
