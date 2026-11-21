<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
// Shows relative time, with the exact time in the title.
defineProps<{ at?: string }>()
</script>

<template>
  <time v-if="at" :datetime="at" :title="formatDateTime(at)" class="whitespace-nowrap">{{ formatRelative(at) }}</time>
  <span v-else class="text-ink-3">—</span>
</template>
