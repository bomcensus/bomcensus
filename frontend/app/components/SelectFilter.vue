<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
// A value of '' means "All". The value of each option is a string.
const model = defineModel<string>({ default: '' })
defineProps<{ label: string; options: { value: string; label: string }[] }>()
</script>

<template>
  <label class="inline-flex items-center">
    <span class="sr-only">{{ label }}</span>
    <select v-model="model" class="select max-w-44" :class="model ? 'border-accent text-accent' : ''">
      <option value="">{{ label }}: 전체</option>
      <option v-for="o in options" :key="o.value" :value="o.value">{{ o.label }}</option>
    </select>
  </label>
</template>
