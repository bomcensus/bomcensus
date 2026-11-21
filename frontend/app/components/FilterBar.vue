<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
// Filter row above a list. Put SearchInput and SelectFilter inside. Shows the count on the right.
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
