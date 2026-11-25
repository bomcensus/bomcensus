<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { IntegrityMode } from '~/types'

// The integrity mode of an agent or scan target. kindLabel names the
// default it inherits ("에이전트", "Agentless (SSH)"), kindDefault its value.
const model = defineModel<IntegrityMode>({ required: true })
defineProps<{ kindLabel: string; kindDefault?: boolean; disabled?: boolean; name: string }>()
</script>

<template>
  <div class="grid grid-cols-1 gap-2">
    <label
      v-for="m in (['inherit', 'on', 'off'] as const)"
      :key="m"
      class="grid cursor-pointer grid-cols-[auto_1fr] gap-2 rounded-md border p-2.5"
      :class="[model === m ? 'border-accent bg-accent-soft' : 'border-line', disabled ? 'pointer-events-none opacity-60' : '']"
    >
      <input v-model="model" type="radio" :name="name" :value="m" :disabled="disabled" class="mt-0.5 accent-(--accent)" />
      <span>
        <span class="block text-sm font-semibold">{{ integrityModeLabel[m] }}</span>
        <span v-if="m === 'inherit'" class="block text-xs text-ink-2">
          설정 › 파일 무결성의 {{ kindLabel }} 기본값을 따릅니다.
          <template v-if="kindDefault !== undefined">지금은 {{ kindDefault ? '켜짐' : '꺼짐' }}입니다.</template>
        </span>
        <span v-else-if="m === 'on'" class="block text-xs text-ink-2">기본값을 꺼도 검사합니다.</span>
        <span v-else class="block text-xs text-ink-2">진행 중인 검사는 다음 접속 때 멈춥니다. 이미 올라온 항목은 남습니다.</span>
      </span>
    </label>
  </div>
</template>
