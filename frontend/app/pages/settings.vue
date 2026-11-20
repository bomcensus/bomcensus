<script setup lang="ts">
useHead({ title: '설정 · bomcensus' })

const items = [
  { to: '/settings/tls', label: 'TLS' },
  { to: '/settings/feeds', label: '취약점 피드' },
]
const route = useRoute()
const isActive = (to: string) => route.path === to || route.path.startsWith(`${to}/`)
</script>

<template>
  <div>
    <PageHeader title="설정" />
    <nav class="mb-4 flex gap-0.5 overflow-x-auto overflow-y-hidden shadow-[inset_0_-1px_0_var(--line)]" aria-label="설정 메뉴">
      <NuxtLink
        v-for="i in items"
        :key="i.to"
        :to="i.to"
        :aria-current="isActive(i.to) ? 'page' : undefined"
        class="whitespace-nowrap border-b-2 px-3 py-2 text-sm transition-colors duration-100"
        :class="isActive(i.to) ? 'border-accent font-semibold text-ink' : 'border-transparent text-ink-2 hover:text-ink'"
      >
        {{ i.label }}
      </NuxtLink>
    </nav>
    <NuxtPage />
  </div>
</template>
