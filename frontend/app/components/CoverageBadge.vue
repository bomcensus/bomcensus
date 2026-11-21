<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { Coverage } from '~/types'

// Collection coverage. When it is not full, the reason is shown as the title.
defineProps<{ coverage: Coverage; reason?: string }>()
</script>

<template>
  <StatusBadge :tone="coverageTone[coverage]" :label="coverageLabel[coverage]" :title="reason" dot />
</template>
