<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import { getIntegrityPolicy, putIntegrityPolicy, toApiError } from '~/api'

useHead({ title: '파일 무결성 · 설정 · bomcensus' })

const { data: policy, error, refresh } = useLoad('settings:integrity', getIntegrityPolicy)

const form = reactive({
  agents: true,
  ssh: true,
  windowStart: '02:00',
  windowEnd: '05:00',
  intervalDays: 1,
  maxReadMbps: 20,
  fullRehashDays: 7,
  excludePaths: '',
})
watch(
  policy,
  (p) => {
    if (!p) return
    Object.assign(form, { ...p, excludePaths: p.excludePaths.join('\n') })
  },
  { immediate: true },
)

const hhmm = /^([01][0-9]|2[0-3]):[0-5][0-9]$/
const excludeList = computed(() =>
  form.excludePaths
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean),
)
const errors = computed(() => ({
  window: hhmm.test(form.windowStart) && hhmm.test(form.windowEnd) ? '' : 'HH:MM 형식으로 입력하세요',
  interval: Number.isInteger(form.intervalDays) && form.intervalDays >= 1 && form.intervalDays <= 30 ? '' : '1~30일',
  rate: Number.isInteger(form.maxReadMbps) && form.maxReadMbps >= 1 && form.maxReadMbps <= 1000 ? '' : '1~1000 MB/s',
  rehash: Number.isInteger(form.fullRehashDays) && form.fullRehashDays >= 1 && form.fullRehashDays <= 365 ? '' : '1~365일',
  exclude: excludeList.value.every((p) => p.startsWith('/')) ? '' : '절대 경로를 입력하세요',
}))
const valid = computed(() => Object.values(errors.value).every((e) => !e))

const busy = ref(false)
const saveError = ref('')
const saved = ref(false)

async function save() {
  if (!valid.value || busy.value) return
  busy.value = true
  saveError.value = ''
  saved.value = false
  try {
    await putIntegrityPolicy({
      agents: form.agents,
      ssh: form.ssh,
      windowStart: form.windowStart,
      windowEnd: form.windowEnd,
      intervalDays: form.intervalDays,
      maxReadMbps: form.maxReadMbps,
      fullRehashDays: form.fullRehashDays,
      excludePaths: excludeList.value,
    })
    await refresh()
    saved.value = true
  } catch (e) {
    saveError.value = toApiError(e).message
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <Panel
    title="파일 무결성"
    description="새벽 시간대에 OS 패키지가 설치한 파일을 패키지 DB의 해시와 비교합니다. conffile, %config, %ghost처럼 바뀌는 것이 정상인 파일은 항상 제외됩니다."
  >
    <LoadError v-if="error" :error="error" @retry="refresh" />
    <LoadingText v-else-if="!policy" />
    <form v-else class="grid max-w-3xl grid-cols-1 gap-4 md:grid-cols-2" @submit.prevent="save">
      <fieldset class="md:col-span-2">
        <legend class="mb-1 block text-xs font-medium text-ink-2">기본 사용 여부</legend>
        <div class="flex flex-wrap gap-4">
          <label class="inline-flex items-center gap-1.5 text-sm"><input v-model="form.agents" type="checkbox" class="accent-(--accent)" /> 에이전트</label>
          <label class="inline-flex items-center gap-1.5 text-sm"><input v-model="form.ssh" type="checkbox" class="accent-(--accent)" /> Agentless (SSH)</label>
        </div>
        <p class="mt-1 text-xs text-ink-3">에이전트 상세와 SSH 대상 편집에서 개별로 켜거나 끌 수 있습니다.</p>
      </fieldset>
      <FormField label="검사 시간대" hint="노드의 현지 시각. 끝이 시작보다 이르면 자정을 넘깁니다." :error="errors.window || undefined">
        <span class="flex items-center gap-2">
          <input v-model="form.windowStart" class="input mono w-24" placeholder="02:00" aria-label="시작" />
          <span class="text-ink-3">~</span>
          <input v-model="form.windowEnd" class="input mono w-24" placeholder="05:00" aria-label="끝" />
        </span>
      </FormField>
      <FormField label="검사 주기" hint="일" :error="errors.interval || undefined">
        <input v-model.number="form.intervalDays" type="number" min="1" max="30" class="input mono w-full" />
      </FormField>
      <FormField label="최대 읽기 속도" hint="MB/s, 노드당" :error="errors.rate || undefined">
        <input v-model.number="form.maxReadMbps" type="number" min="1" max="1000" class="input mono w-full" />
      </FormField>
      <FormField label="전체 재해시 주기" hint="일. 그 사이에는 크기·mtime·ctime·inode가 그대로인 파일만 캐시를 씁니다." :error="errors.rehash || undefined">
        <input v-model.number="form.fullRehashDays" type="number" min="1" max="365" class="input mono w-full" />
      </FormField>
      <FormField class="md:col-span-2" label="제외 경로" hint="한 줄에 하나. 경로 접두사나 glob(**는 여러 디렉터리)." :error="errors.exclude || undefined">
        <textarea v-model="form.excludePaths" rows="4" class="input mono w-full" placeholder="/usr/share/doc/**" />
      </FormField>
      <div class="flex items-center gap-3 md:col-span-2">
        <AppButton type="submit" variant="primary" :disabled="!valid || busy">저장</AppButton>
        <span v-if="saved" class="text-sm text-ok" role="status">저장했습니다.</span>
        <p v-if="saveError" class="note note-danger" role="alert">{{ saveError }}</p>
      </div>
    </form>
  </Panel>
</template>
