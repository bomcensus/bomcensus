<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { ApiError } from '~/api'

// Failed load from useLoad. With `back`, a 404 shows "찾을 수 없음" and a link to the list instead of a retry.
defineProps<{ error: ApiError; back?: { to: string; label: string } }>()
defineEmits<{ retry: [] }>()
</script>

<template>
  <EmptyState v-if="back && error.status === 404" title="찾을 수 없음">
    <AppButton :to="back.to">{{ back.label }}</AppButton>
  </EmptyState>
  <EmptyState v-else title="불러오지 못함" :description="error.message">
    <AppButton @click="$emit('retry')">다시 시도</AppButton>
  </EmptyState>
</template>
