<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import { parseScanMessage } from '~/utils/labels'

// Server-side diagnostic text (English), kept verbatim on its own line.
// With `scan`, a leading reason code gets a Korean label in front.
const props = defineProps<{ text: string; scan?: boolean }>()
const parsed = computed(() => (props.scan ? parseScanMessage(props.text) : { detail: props.text }))
</script>

<template>
  <div class="break-all text-xs">
    <div v-if="parsed.label" class="text-ink-2">{{ parsed.label }}</div>
    <div v-if="parsed.detail" class="mono text-ink-2">{{ parsed.detail }}</div>
  </div>
</template>
