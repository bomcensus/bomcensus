<script setup lang="ts">
// 테두리 있는 영역. flush 를 주면 본문 여백이 없다(표를 바로 넣을 때).
defineProps<{ title?: string; description?: string; flush?: boolean }>()
</script>

<template>
  <section class="min-w-0 rounded-lg border border-line bg-surface">
    <div
      v-if="title || $slots.actions"
      class="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 border-b border-line px-3.5 py-2.5"
    >
      <div class="min-w-0">
        <h2 class="text-sm font-semibold">{{ title }}</h2>
        <p v-if="description" class="text-xs text-ink-3">{{ description }}</p>
      </div>
      <div v-if="$slots.actions" class="flex items-center gap-2">
        <slot name="actions" />
      </div>
    </div>
    <div :class="flush ? '' : 'p-3.5'">
      <slot />
    </div>
  </section>
</template>
