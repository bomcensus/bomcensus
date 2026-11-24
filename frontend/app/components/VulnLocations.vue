<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { VulnLocation } from '~/types'

// Places a vulnerable component is: asset, container, files, how it was found, exposure, processes.
defineProps<{ items: VulnLocation[]; where: (l: VulnLocation) => string; processText: (l: VulnLocation) => string }>()
</script>

<template>
  <div class="overflow-x-auto">
    <table class="w-full min-w-[640px] border-collapse text-sm">
      <thead>
        <tr class="border-b border-line text-left text-xs text-ink-3">
          <th class="py-2 pl-3.5 font-normal">자산</th>
          <th class="px-3 py-2 font-normal">파일</th>
          <th class="hidden px-3 py-2 font-normal md:table-cell">탐지</th>
          <th class="px-3 py-2 font-normal">영향도</th>
          <th class="py-2 pl-3 pr-3.5 font-normal">프로세스</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="l in items" :key="`${l.assetId}/${l.container ?? ''}/${l.componentId}`" class="border-b border-line align-top last:border-b-0">
          <td class="py-2 pl-3.5">
            <NuxtLink :to="`/assets/${l.assetId}?tab=vulnerabilities`" class="font-medium hover:underline">{{ l.assetName }}</NuxtLink>
            <div class="text-xs text-ink-3">{{ where(l) }}</div>
          </td>
          <td class="px-3 py-2">
            <span v-if="l.locations.length" class="mono break-all text-xs">{{ l.locations[0] }}</span>
            <span v-if="l.locations.length > 1" class="text-xs text-ink-3"> 외 {{ l.locations.length - 1 }}</span>
            <span v-if="!l.locations.length" class="text-ink-3">—</span>
            <div class="mono text-xs text-ink-3">{{ l.componentName }} {{ l.componentVersion }}</div>
          </td>
          <td class="hidden px-3 py-2 text-xs text-ink-2 md:table-cell">{{ l.method ? detectMethodLabel[l.method] : '—' }}</td>
          <td class="px-3 py-2"><ExposureMeter :exposure="l.exposure" /></td>
          <td class="mono py-2 pl-3 pr-3.5 text-xs text-ink-2">{{ processText(l) || '—' }}</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
