<script setup lang="ts">
import type { Component as VueComponent } from 'vue'

const props = withDefaults(
  defineProps<{
    variant?: 'primary' | 'secondary' | 'ghost' | 'danger'
    size?: 'sm' | 'md'
    icon?: VueComponent
    to?: string
    disabled?: boolean
    type?: 'button' | 'submit'
  }>(),
  { variant: 'secondary', size: 'md', type: 'button' },
)

const variantClass = {
  primary: 'bg-accent text-accent-ink border-transparent hover:bg-accent-hover',
  secondary: 'bg-surface text-ink border-line-strong hover:bg-surface-2',
  ghost: 'bg-transparent text-ink-2 border-transparent hover:bg-surface-2 hover:text-ink',
  danger: 'bg-surface text-critical border-line-strong hover:bg-critical-soft',
}
const sizeClass = { sm: 'h-7 px-2 text-xs gap-1', md: 'h-[30px] px-3 text-sm gap-1.5' }

const cls = computed(() => [
  'inline-flex shrink-0 items-center justify-center whitespace-nowrap rounded-md border font-medium transition-colors duration-100 active:translate-y-px',
  variantClass[props.variant],
  sizeClass[props.size],
  props.disabled ? 'pointer-events-none opacity-50' : '',
])
</script>

<template>
  <NuxtLink v-if="to" :to="to" :class="cls">
    <component :is="icon" v-if="icon" :size="14" aria-hidden="true" />
    <slot />
  </NuxtLink>
  <button v-else :type="type" :disabled="disabled" :class="cls">
    <component :is="icon" v-if="icon" :size="14" aria-hidden="true" />
    <slot />
  </button>
</template>
