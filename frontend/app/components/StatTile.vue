<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { Tone } from '~/utils/labels'

// A number with a label. Becomes a link when `to` is given.
const props = withDefaults(
  defineProps<{ label: string; value: string | number; hint?: string; tone?: Tone; to?: string }>(),
  { tone: 'neutral' },
)

const valueClass: Record<Tone, string> = {
  ok: 'text-ok',
  warn: 'text-medium',
  danger: 'text-critical',
  info: 'text-accent',
  neutral: 'text-ink',
}
const tag = computed(() => (props.to ? resolveComponent('NuxtLink') : 'div'))
</script>

<template>
  <component
    :is="tag"
    :to="to"
    class="block min-w-0 rounded-lg border border-line bg-surface px-3.5 py-3"
    :class="to ? 'transition-colors duration-100 hover:border-line-strong hover:bg-surface-2' : ''"
  >
    <div class="text-xs text-ink-3">{{ label }}</div>
    <div class="mono mt-1 text-2xl font-semibold leading-8" :class="valueClass[tone]">{{ value }}</div>
    <div v-if="hint" class="mt-0.5 text-xs text-ink-2">{{ hint }}</div>
  </component>
</template>
