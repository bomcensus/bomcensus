<script setup lang="ts">
import type { Severity, SeverityCounts } from '~/types'

// 심각도별 건수를 한 줄로 보여 준다. 0건인 심각도는 흐리게 표시한다.
defineProps<{ counts: SeverityCounts }>()

const order: Severity[] = ['critical', 'high', 'medium', 'low']
const cls: Record<Severity, string> = {
  critical: 'bg-critical-soft text-critical',
  high: 'bg-high-soft text-high',
  medium: 'bg-medium-soft text-medium',
  low: 'bg-low-soft text-low',
}
</script>

<template>
  <span class="inline-flex gap-1" role="group" aria-label="심각도별 취약점 수">
    <span
      v-for="s in order"
      :key="s"
      class="mono inline-flex min-w-6 justify-center rounded-sm px-1 text-xs font-semibold leading-5"
      :class="counts[s] > 0 ? cls[s] : 'text-ink-3 opacity-50'"
      :title="`${severityLabel[s]} ${counts[s]}건`"
    >
      {{ counts[s] }}
    </span>
  </span>
</template>
