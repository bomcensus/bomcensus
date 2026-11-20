<script setup lang="ts">
defineProps<{ title: string; description?: string }>()
</script>

<template>
  <div class="px-4 py-10 text-center">
    <p class="text-sm font-medium text-ink-2">{{ title }}</p>
    <p v-if="description" class="mx-auto mt-1 max-w-md text-xs text-ink-3">{{ description }}</p>
    <div v-if="$slots.default" class="mt-3 flex justify-center gap-2">
      <slot />
    </div>
  </div>
</template>
