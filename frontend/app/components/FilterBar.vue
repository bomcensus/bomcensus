<script setup lang="ts">
// 목록 위의 필터 줄. 안에 SearchInput, SelectFilter 를 넣는다. 오른쪽에 건수를 보여 준다.
defineProps<{ count?: number; total?: number; unit?: string }>()
</script>

<template>
  <div class="mb-3 flex flex-wrap items-center gap-2">
    <slot />
    <span v-if="count !== undefined" class="ml-auto whitespace-nowrap text-xs text-ink-3">
      <span class="mono text-ink-2">{{ formatNumber(count) }}</span>
      <template v-if="total !== undefined && total !== count"> / {{ formatNumber(total) }}</template>
      {{ unit ?? '건' }}
    </span>
  </div>
</template>
