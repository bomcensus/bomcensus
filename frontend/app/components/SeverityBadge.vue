<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { Severity } from '~/types'

// CVSS rating with the score. Without a rating, a dash.
defineProps<{ severity?: Severity; score?: number }>()

const toneClass: Record<Severity, string> = {
  critical: 'bg-critical-soft text-critical',
  high: 'bg-high-soft text-high',
  medium: 'bg-medium-soft text-medium',
  low: 'bg-low-soft text-low',
  none: 'bg-surface-2 text-ink-2',
}
</script>

<template>
  <span v-if="severity" class="inline-flex items-center gap-1.5 whitespace-nowrap">
    <span class="rounded-sm px-1.5 py-px text-xs font-semibold leading-5" :class="toneClass[severity]">{{ severityLabel[severity] }}</span>
    <span v-if="score !== undefined" class="mono text-xs text-ink-2">{{ score.toFixed(1) }}</span>
  </span>
  <span v-else class="text-ink-3">—</span>
</template>
