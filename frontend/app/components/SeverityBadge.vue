<script setup lang="ts">
import type { Severity } from '~/types'

defineProps<{ severity: Severity }>()

const cls: Record<Severity, string> = {
  critical: 'bg-critical-soft text-critical',
  high: 'bg-high-soft text-high',
  medium: 'bg-medium-soft text-medium',
  low: 'bg-low-soft text-low',
}
</script>

<template>
  <span
    class="inline-flex min-w-9 items-center justify-center whitespace-nowrap rounded-sm px-1.5 py-px text-xs font-semibold leading-5"
    :class="cls[severity]"
  >
    {{ severityLabel[severity] }}
  </span>
</template>
