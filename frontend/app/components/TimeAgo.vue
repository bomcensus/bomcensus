<script setup lang="ts">
// 상대 시간을 보여 주고 정확한 시각은 title로 둔다.
defineProps<{ at?: string }>()
</script>

<template>
  <time v-if="at" :datetime="at" :title="formatDateTime(at)" class="whitespace-nowrap">{{ formatRelative(at) }}</time>
  <span v-else class="text-ink-3">—</span>
</template>
