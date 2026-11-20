<script setup lang="ts">
// 탭 줄. v-model 은 선택된 탭의 key. queryKey 를 주면 URL 쿼리와 동기화한다.
const props = defineProps<{ tabs: { key: string; label: string; count?: number }[]; queryKey?: string }>()
const model = defineModel<string>({ required: true })

const route = useRoute()
const router = useRouter()

if (props.queryKey) {
  const fromQuery = route.query[props.queryKey]
  if (typeof fromQuery === 'string' && props.tabs.some((t) => t.key === fromQuery)) model.value = fromQuery
}

function select(key: string) {
  model.value = key
  if (props.queryKey) router.replace({ query: { ...route.query, [props.queryKey]: key } })
}
</script>

<template>
  <div class="flex gap-0.5 overflow-x-auto overflow-y-hidden shadow-[inset_0_-1px_0_var(--line)]" role="tablist">
    <button
      v-for="t in tabs"
      :key="t.key"
      type="button"
      role="tab"
      :aria-selected="model === t.key"
      class="inline-flex items-center gap-1.5 whitespace-nowrap border-b-2 px-3 py-2 text-sm transition-colors duration-100"
      :class="model === t.key ? 'border-accent font-semibold text-ink' : 'border-transparent text-ink-2 hover:text-ink'"
      @click="select(t.key)"
    >
      {{ t.label }}
      <span v-if="t.count !== undefined" class="mono rounded-sm bg-surface-2 px-1 text-2xs leading-4 text-ink-2">{{ t.count }}</span>
    </button>
  </div>
</template>
