<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { DetectDir } from '~/types'

// Checkbox list of the detect directories; v-model holds the chosen ids.
const props = defineProps<{ dirs: DetectDir[]; disabled?: boolean }>()
const model = defineModel<string[]>({ required: true })

function toggle(id: string, on: boolean) {
  const set = new Set(model.value)
  if (on) set.add(id)
  else set.delete(id)
  // Keep the list order (by path) so that the value is stable.
  model.value = props.dirs.filter((d) => set.has(d.id)).map((d) => d.id)
}
</script>

<template>
  <div>
    <p v-if="dirs.length === 0" class="text-sm text-ink-3">
      등록된 디렉터리가 없습니다. <NuxtLink to="/settings/detect-dirs" class="link">설정 · 감지 대상 디렉터리</NuxtLink>에서 추가하세요.
    </p>
    <ul v-else class="grid max-h-72 grid-cols-1 gap-1 overflow-y-auto">
      <li v-for="d in dirs" :key="d.id">
        <label class="flex cursor-pointer items-start gap-2 rounded px-1 py-1 text-sm hover:bg-surface-2">
          <input
            type="checkbox"
            class="mt-0.5 size-[15px] shrink-0 accent-(--accent)"
            :checked="model.includes(d.id)"
            :disabled="disabled"
            @change="toggle(d.id, ($event.target as HTMLInputElement).checked)"
          />
          <span class="min-w-0">
            <span class="mono block text-xs [overflow-wrap:anywhere]">{{ d.path }}</span>
            <span v-if="d.description" class="block text-xs text-ink-3">{{ d.description }}</span>
          </span>
        </label>
      </li>
    </ul>
  </div>
</template>
