<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { Exposure } from '~/types'

// Four bars for the exposure level, with its name unless bare.
const props = defineProps<{ exposure: Exposure; bare?: boolean }>()
const level = computed(() => exposureLevel[props.exposure])
</script>

<template>
  <span class="inline-flex items-center gap-1.5 whitespace-nowrap" :title="exposureLabel[exposure]">
    <span class="inline-flex items-center gap-px" aria-hidden="true">
      <span
        v-for="i in 4"
        :key="i"
        class="inline-block h-3 w-[5px] rounded-[1px]"
        :class="i <= level ? (level >= 3 ? 'bg-ink' : 'bg-ink-3') : 'bg-line-strong'"
      />
    </span>
    <span v-if="!bare" class="text-xs" :class="level >= 3 ? 'text-ink' : 'text-ink-2'">{{ exposureLabel[exposure] }}</span>
    <span v-else class="sr-only">{{ exposureLabel[exposure] }}</span>
  </span>
</template>
