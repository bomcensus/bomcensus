<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
// Tab row. v-model is the key of the selected tab. When queryKey is given, it is synced with the URL query.
const props = defineProps<{ tabs: { key: string; label: string; count?: number }[]; queryKey?: string }>()
const model = defineModel<string>({ required: true })

const route = useRoute()
const router = useRouter()

if (props.queryKey) {
  const fromQuery = route.query[props.queryKey]
  if (typeof fromQuery === 'string' && props.tabs.some((t) => t.key === fromQuery)) model.value = fromQuery
}

function select(key: string) {
  model.value = key
  if (props.queryKey) router.replace({ query: { ...route.query, [props.queryKey]: key } })
}
</script>

<template>
  <div class="flex gap-0.5 overflow-x-auto overflow-y-hidden shadow-[inset_0_-1px_0_var(--line)]" role="tablist">
    <button
      v-for="t in tabs"
      :key="t.key"
      type="button"
      role="tab"
      :aria-selected="model === t.key"
      class="inline-flex items-center gap-1.5 whitespace-nowrap border-b-2 px-3 py-2 text-sm transition-colors duration-100"
      :class="model === t.key ? 'border-accent font-semibold text-ink' : 'border-transparent text-ink-2 hover:text-ink'"
      @click="select(t.key)"
    >
      {{ t.label }}
      <span v-if="t.count !== undefined" class="mono rounded-sm bg-surface-2 px-1 text-2xs leading-4 text-ink-2">{{ t.count }}</span>
    </button>
  </div>
</template>
