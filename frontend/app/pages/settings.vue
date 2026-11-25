<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
useHead({ title: '설정 · bomcensus' })

const route = useRoute()
const tabs = [
  { to: '/settings/tls', label: 'TLS' },
  { to: '/settings/feed', label: '취약점 피드' },
  { to: '/settings/detect-dirs', label: '감지 대상 디렉터리' },
  { to: '/settings/integrity', label: '파일 무결성' },
]
</script>

<template>
  <div>
    <PageHeader title="설정" />
    <nav class="mb-4 flex gap-0.5 overflow-x-auto overflow-y-hidden shadow-[inset_0_-1px_0_var(--line)]" aria-label="설정">
      <NuxtLink
        v-for="t in tabs"
        :key="t.to"
        :to="t.to"
        :aria-current="route.path === t.to ? 'page' : undefined"
        class="inline-flex items-center whitespace-nowrap border-b-2 px-3 py-2 text-sm transition-colors duration-100"
        :class="route.path === t.to ? 'border-accent font-semibold text-ink' : 'border-transparent text-ink-2 hover:text-ink'"
      >
        {{ t.label }}
      </NuxtLink>
    </nav>
    <NuxtPage />
  </div>
</template>
