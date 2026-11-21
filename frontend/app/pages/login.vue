<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import { ApiError, login } from '~/api'

definePageMeta({ layout: 'bare' })
useHead({ title: '로그인 · bomcensus' })

const route = useRoute()
const user = useCurrentUser()

const username = ref('')
const password = ref('')
const submitting = ref(false)
const error = ref('')

// Only same-site paths are accepted as the return target.
const next = computed(() => {
  const v = route.query.next
  return typeof v === 'string' && v.startsWith('/') && !v.startsWith('//') ? v : '/'
})

async function submit() {
  if (!username.value || !password.value || submitting.value) return
  submitting.value = true
  error.value = ''
  try {
    user.value = await login({ username: username.value, password: password.value })
    await navigateTo(next.value, { replace: true })
  } catch (e) {
    password.value = ''
    if (e instanceof ApiError && e.status === 401) error.value = '사용자 이름 또는 비밀번호가 올바르지 않습니다.'
    else if (e instanceof ApiError && e.status === 429) error.value = '로그인 시도가 너무 많습니다. 잠시 후에 다시 시도할 수 있습니다.'
    else error.value = e instanceof Error ? e.message : String(e)
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <div class="w-full max-w-80">
    <div class="mono mb-4 text-center text-lg font-semibold tracking-tight">bomcensus</div>
    <form class="space-y-3 rounded-lg border border-line bg-surface p-4" @submit.prevent="submit">
      <FormField label="사용자 이름">
        <input v-model="username" class="input w-full" autocomplete="username" autofocus required />
      </FormField>
      <FormField label="비밀번호">
        <input v-model="password" type="password" class="input w-full" autocomplete="current-password" required />
      </FormField>
      <p v-if="error" class="note note-danger" role="alert">{{ error }}</p>
      <AppButton type="submit" variant="primary" class="w-full" :disabled="submitting || !username || !password">로그인</AppButton>
    </form>
  </div>
</template>
