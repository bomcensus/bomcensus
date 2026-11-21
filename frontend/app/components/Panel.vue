<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
// Bordered area. With flush, the body has no padding (for putting a table directly inside).
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
