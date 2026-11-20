<script setup lang="ts">
// 값이 '' 이면 "전체". options 의 value 는 문자열.
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
