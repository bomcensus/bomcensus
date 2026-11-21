<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import { X } from '@lucide/vue'

// Modal based on <dialog>. Opened with v-model:open. Put buttons in the footer slot.
const open = defineModel<boolean>('open', { required: true })
defineProps<{ title: string; wide?: boolean }>()

const dialog = ref<HTMLDialogElement>()

watch(
  [open, dialog],
  ([isOpen, el]) => {
    if (!el) return
    if (isOpen && !el.open) el.showModal()
    if (!isOpen && el.open) el.close()
  },
  { immediate: true },
)
</script>

<template>
  <dialog
    ref="dialog"
    class="m-auto w-[calc(100%-2rem)] rounded-lg border border-line-strong bg-surface p-0 text-ink backdrop:bg-ink/40"
    :class="wide ? 'max-w-2xl' : 'max-w-md'"
    @close="open = false"
    @click.self="open = false"
  >
    <div class="flex items-center justify-between border-b border-line px-4 py-3">
      <h2 class="text-base font-semibold">{{ title }}</h2>
      <button type="button" class="inline-flex size-7 items-center justify-center rounded-sm text-ink-2 hover:bg-surface-2" aria-label="닫기" @click="open = false">
        <X :size="15" aria-hidden="true" />
      </button>
    </div>
    <div class="max-h-[70vh] overflow-y-auto px-4 py-4">
      <slot />
    </div>
    <div v-if="$slots.footer" class="flex justify-end gap-2 border-t border-line px-4 py-3">
      <slot name="footer" />
    </div>
  </dialog>
</template>
