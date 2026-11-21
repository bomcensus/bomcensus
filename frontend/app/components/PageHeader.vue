<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
// Page top. The default slot goes below the title (tabs etc.); the actions slot holds the buttons on the right.
defineProps<{ title: string; subtitle?: string; back?: { to: string; label: string } }>()
</script>

<template>
  <header class="mb-4">
    <NuxtLink v-if="back" :to="back.to" class="mb-1 inline-block text-xs text-ink-3 hover:text-ink">← {{ back.label }}</NuxtLink>
    <div class="flex flex-wrap items-start justify-between gap-x-4 gap-y-2">
      <div class="min-w-0">
        <h1 class="text-xl leading-7 [overflow-wrap:anywhere]">{{ title }}</h1>
        <p v-if="subtitle || $slots.subtitle" class="mt-0.5 text-sm text-ink-2">
          <slot name="subtitle">{{ subtitle }}</slot>
        </p>
      </div>
      <div v-if="$slots.actions" class="flex flex-wrap items-center gap-2">
        <slot name="actions" />
      </div>
    </div>
    <div v-if="$slots.default" class="mt-3">
      <slot />
    </div>
  </header>
</template>
