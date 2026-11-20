<script setup lang="ts">
// 라벨 + 입력 + 도움말. 기본 슬롯에 .input / .select 요소를 넣는다.
defineProps<{ label: string; hint?: string; error?: string }>()
</script>

<template>
  <label class="block">
    <span class="mb-1 block text-xs font-medium text-ink-2">{{ label }}</span>
    <slot />
    <span v-if="error" class="mt-1 block text-xs text-critical">{{ error }}</span>
    <span v-else-if="hint" class="mt-1 block text-xs text-ink-3">{{ hint }}</span>
  </label>
</template>
