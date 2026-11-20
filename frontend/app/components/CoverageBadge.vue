<script setup lang="ts">
import type { Coverage } from '~/types'

// 수집 범위. 전체가 아니면 사유를 title로 보여 준다.
defineProps<{ coverage: Coverage; reason?: string }>()
</script>

<template>
  <StatusBadge :tone="coverageTone[coverage]" :label="coverageLabel[coverage]" :title="reason" dot />
</template>
