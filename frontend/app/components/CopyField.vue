<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import { Check, Copy } from '@lucide/vue'

// Monospaced value with a copy button. Long values wrap.
const props = defineProps<{ value: string; label?: string }>()
const copied = ref(false)

async function copy() {
  try {
    await navigator.clipboard.writeText(props.value)
    copied.value = true
    setTimeout(() => (copied.value = false), 1500)
  } catch {
    copied.value = false
  }
}
</script>

<template>
  <div class="flex items-start gap-2 rounded-md border border-line bg-surface-2 py-1.5 pl-2.5 pr-1.5">
    <code class="mono min-w-0 flex-1 break-all py-0.5 text-xs leading-5">{{ value }}</code>
    <button
      type="button"
      class="inline-flex size-6 shrink-0 items-center justify-center rounded-sm text-ink-2 hover:bg-surface hover:text-ink"
      :aria-label="copied ? '복사됨' : `${label ?? '값'} 복사`"
      @click="copy"
    >
      <component :is="copied ? Check : Copy" :size="13" aria-hidden="true" />
    </button>
  </div>
</template>
