<script setup lang="ts">
import { Search } from '@lucide/vue'

const model = defineModel<string>({ default: '' })
defineProps<{ placeholder?: string; label?: string }>()
</script>

<template>
  <label class="relative block w-full sm:w-64">
    <span class="sr-only">{{ label ?? '검색' }}</span>
    <Search :size="14" class="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-ink-3" aria-hidden="true" />
    <input v-model="model" type="search" class="input w-full pl-8" :placeholder="placeholder ?? '검색'" />
  </label>
</template>
