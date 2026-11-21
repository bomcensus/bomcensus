<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { Tone } from '~/utils/labels'

withDefaults(defineProps<{ tone?: Tone; label: string; dot?: boolean }>(), { tone: 'neutral', dot: false })

const toneClass: Record<Tone, string> = {
  ok: 'bg-ok-soft text-ok',
  warn: 'bg-medium-soft text-medium',
  danger: 'bg-critical-soft text-critical',
  info: 'bg-accent-soft text-accent',
  neutral: 'bg-surface-2 text-ink-2',
}
const dotClass: Record<Tone, string> = {
  ok: 'bg-ok',
  warn: 'bg-medium',
  danger: 'bg-critical',
  info: 'bg-accent',
  neutral: 'bg-ink-3',
}
</script>

<template>
  <span
    class="inline-flex items-center gap-1.5 whitespace-nowrap rounded-sm px-1.5 py-px text-xs font-semibold leading-5"
    :class="toneClass[tone]"
  >
    <span v-if="dot" class="size-1.5 rounded-full" :class="dotClass[tone]" aria-hidden="true" />
    {{ label }}
  </span>
</template>
