<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { Reachability } from '~/types'

// Result of the Go symbol check. Nothing is shown while it is not known. The checked
// functions are the evidence for "absent", which lowers the exposure to installed.
const props = defineProps<{ reachability?: Reachability; symbols?: string[] }>()
const title = computed(() => {
  if (!props.reachability) return ''
  const list = props.symbols?.length ? `\n확인한 함수:\n${props.symbols.join('\n')}` : ''
  return props.reachability === 'symbol_absent'
    ? `실행 파일에 취약 함수가 링크되어 있지 않아 영향도를 설치 수준으로 낮췄습니다.${list}`
    : `실행 파일에 취약 함수가 링크되어 있습니다.${list}`
})
</script>

<template>
  <div v-if="reachability" class="mt-0.5" :title="title">
    <StatusBadge :tone="reachability === 'symbol_present' ? 'danger' : 'neutral'" :label="reachabilityLabel[reachability]" />
  </div>
</template>
