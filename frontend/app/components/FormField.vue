<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
// Label + input + help text. Put .input / .select elements in the default slot.
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
