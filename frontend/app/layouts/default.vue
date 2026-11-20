<script setup lang="ts">
import type { Component as VueComponent } from 'vue'
import {
  Activity,
  Boxes,
  Container,
  Download,
  KeyRound,
  LayoutDashboard,
  Menu,
  Moon,
  Network,
  Package,
  Radio,
  Server,
  Settings,
  ShieldAlert,
  Sun,
  Terminal,
  X,
} from '@lucide/vue'

interface NavItem {
  to: string
  label: string
  icon: VueComponent
}

const nav: { title?: string; items: NavItem[] }[] = [
  { items: [{ to: '/', label: '대시보드', icon: LayoutDashboard }] },
  {
    title: '인벤토리',
    items: [
      { to: '/assets', label: '자산', icon: Server },
      { to: '/components', label: '컴포넌트', icon: Package },
      { to: '/images', label: '이미지', icon: Container },
      { to: '/kubernetes', label: 'Kubernetes', icon: Boxes },
    ],
  },
  {
    title: '위험',
    items: [
      { to: '/vulnerabilities', label: '취약점', icon: ShieldAlert },
      { to: '/processes', label: '프로세스', icon: Activity },
    ],
  },
  {
    title: '수집',
    items: [
      { to: '/agents', label: '에이전트', icon: Radio },
      { to: '/register-keys', label: 'Register Key', icon: KeyRound },
      { to: '/scans', label: 'Agentless 수집', icon: Terminal },
      { to: '/updates', label: '업데이트', icon: Download },
    ],
  },
  { title: '관리', items: [{ to: '/settings', label: '설정', icon: Settings }] },
]

const route = useRoute()
const isActive = (to: string) => (to === '/' ? route.path === '/' : route.path === to || route.path.startsWith(`${to}/`))

const menuOpen = ref(false)
watch(
  () => route.path,
  () => (menuOpen.value = false),
)

const theme = ref<'light' | 'dark'>('light')
onMounted(() => {
  const saved = localStorage.getItem('theme')
  theme.value = saved === 'dark' || saved === 'light' ? saved : matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  document.documentElement.dataset.theme = theme.value
})
function toggleTheme() {
  theme.value = theme.value === 'dark' ? 'light' : 'dark'
  document.documentElement.dataset.theme = theme.value
  localStorage.setItem('theme', theme.value)
}
</script>

<template>
  <div class="min-h-dvh">
    <a href="#main" class="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded-md focus:bg-surface focus:px-3 focus:py-1.5">
      본문으로 건너뛰기
    </a>

    <div v-if="menuOpen" class="fixed inset-0 z-30 bg-ink/40 lg:hidden" @click="menuOpen = false" />

    <aside
      class="fixed inset-y-0 left-0 z-40 flex w-(--rail-w) flex-col border-r border-line bg-surface transition-transform duration-150 ease-(--ease-out) lg:translate-x-0"
      :class="menuOpen ? 'translate-x-0' : '-translate-x-full'"
    >
      <div class="flex h-(--bar-h) shrink-0 items-center justify-between border-b border-line px-4">
        <NuxtLink to="/" class="mono text-base font-semibold tracking-tight">bomcensus</NuxtLink>
        <button type="button" class="inline-flex size-7 items-center justify-center rounded-sm text-ink-2 hover:bg-surface-2 lg:hidden" aria-label="메뉴 닫기" @click="menuOpen = false">
          <X :size="16" aria-hidden="true" />
        </button>
      </div>

      <nav class="flex-1 overflow-y-auto px-2 py-3" aria-label="주 메뉴">
        <div v-for="(group, i) in nav" :key="i" class="mb-3">
          <div v-if="group.title" class="px-2 pb-1 text-2xs font-medium text-ink-3">{{ group.title }}</div>
          <NuxtLink
            v-for="item in group.items"
            :key="item.to"
            :to="item.to"
            class="flex h-8 items-center gap-2.5 whitespace-nowrap rounded-md px-2 text-sm transition-colors duration-100"
            :class="isActive(item.to) ? 'bg-accent-soft font-semibold text-accent' : 'text-ink-2 hover:bg-surface-2 hover:text-ink'"
            :aria-current="isActive(item.to) ? 'page' : undefined"
          >
            <component :is="item.icon" :size="15" aria-hidden="true" />
            {{ item.label }}
          </NuxtLink>
        </div>
      </nav>

      <div class="shrink-0 border-t border-line px-4 py-2.5 text-2xs text-ink-3">
        <div class="flex items-center gap-1.5"><Network :size="12" aria-hidden="true" /> 서버 <span class="mono">0.1.0-mock</span></div>
      </div>
    </aside>

    <div class="lg:pl-(--rail-w)">
      <div class="sticky top-0 z-20 flex h-(--bar-h) items-center gap-2 border-b border-line bg-surface px-3 sm:px-5">
        <button type="button" class="inline-flex size-8 items-center justify-center rounded-md text-ink-2 hover:bg-surface-2 lg:hidden" aria-label="메뉴 열기" @click="menuOpen = true">
          <Menu :size="17" aria-hidden="true" />
        </button>
        <span class="whitespace-nowrap rounded-sm bg-medium-soft px-1.5 py-px text-2xs font-semibold leading-5 text-medium">목업 데이터</span>
        <div class="ml-auto flex items-center gap-1">
          <button
            type="button"
            class="inline-flex size-8 items-center justify-center rounded-md text-ink-2 hover:bg-surface-2 hover:text-ink"
            :aria-label="theme === 'dark' ? '밝은 화면으로' : '어두운 화면으로'"
            @click="toggleTheme"
          >
            <component :is="theme === 'dark' ? Sun : Moon" :size="16" aria-hidden="true" />
          </button>
          <span class="ml-1 whitespace-nowrap text-xs text-ink-2">admin</span>
        </div>
      </div>

      <main id="main" class="mx-auto max-w-[1400px] px-3 py-4 sm:px-5 sm:py-5">
        <slot />
      </main>
    </div>
  </div>
</template>
