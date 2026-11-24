<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { DetectDir } from '~/types'
import { createDetectDir, deleteDetectDir, listDetectDirs, toApiError, updateDetectDir } from '~/api'

useHead({ title: '감지 대상 디렉터리 · bomcensus' })

const { data: list, error, refresh } = useLoad('detect-dirs', () => listDetectDirs())
const dirs = computed(() => list.value?.items ?? [])

// Same rules as the server: absolute, no glob characters.
function pathError(p: string): string {
  const v = p.trim()
  if (!v) return ''
  if (!v.startsWith('/')) return '절대 경로를 입력하세요'
  if (/[*?[]/.test(v)) return '와일드카드는 쓸 수 없습니다'
  return ''
}

// ── Add / edit ────────────────────────────────────────

const formOpen = ref(false)
const editing = ref<DetectDir>()
const form = reactive({ path: '', description: '' })
const formBusy = ref(false)
const formError = ref('')
const formPathError = computed(() => pathError(form.path))
const formValid = computed(() => !!form.path.trim() && !formPathError.value)

function openAdd() {
  editing.value = undefined
  Object.assign(form, { path: '', description: '' })
  formError.value = ''
  formOpen.value = true
}

function openEdit(d: DetectDir) {
  editing.value = d
  Object.assign(form, { path: d.path, description: d.description ?? '' })
  formError.value = ''
  formOpen.value = true
}

async function save() {
  if (!formValid.value || formBusy.value) return
  formBusy.value = true
  formError.value = ''
  const body = { path: form.path.trim(), description: form.description.trim() }
  try {
    if (editing.value) await updateDetectDir(editing.value.id, body)
    else await createDetectDir(body)
    formOpen.value = false
    await refresh()
  } catch (e) {
    const err = toApiError(e)
    formError.value = err.status === 409 ? '같은 경로가 이미 있습니다' : err.message
  } finally {
    formBusy.value = false
  }
}

// ── Remove ────────────────────────────────────────────

const removing = ref<DetectDir>()
const removeBusy = ref(false)
const removeError = ref('')
watch(removing, () => (removeError.value = ''))
const removeOpen = computed({
  get: () => !!removing.value,
  set: (v) => {
    if (!v) removing.value = undefined
  },
})

async function remove() {
  const d = removing.value
  if (!d || removeBusy.value) return
  removeBusy.value = true
  try {
    await deleteDetectDir(d.id)
    removing.value = undefined
    await refresh()
  } catch (e) {
    removeError.value = toApiError(e).message
  } finally {
    removeBusy.value = false
  }
}

function usage(d: DetectDir): string {
  const parts = []
  if (d.agents > 0) parts.push(`에이전트 ${formatNumber(d.agents)}개`)
  if (d.scanTargets > 0) parts.push(`스캔 대상 ${formatNumber(d.scanTargets)}개`)
  return parts.join(', ')
}
</script>

<template>
  <div class="grid grid-cols-1 gap-4">
    <Panel
      title="감지 대상 디렉터리"
      description="에이전트와 스캔 대상마다 고른 디렉터리만 하위까지 탐색해 소프트웨어를 찾습니다. 디렉터리를 고르지 않은 호스트는 실행 중인 프로그램과 그 프로그램이 연 파일(jar 등)만 수집합니다. 컨테이너 이미지는 항상 전체를 탐색합니다."
      flush
    >
      <template #actions>
        <AppButton size="sm" variant="primary" @click="openAdd">디렉터리 추가</AppButton>
      </template>
      <LoadError v-if="error" :error="error" @retry="refresh" />
      <LoadingText v-else-if="!list" class="p-3.5" />
      <EmptyState v-else-if="dirs.length === 0" title="등록된 디렉터리가 없습니다" description="지금은 모든 호스트가 실행 중인 소프트웨어만 수집합니다." />
      <div v-else class="overflow-x-auto">
        <table class="w-full min-w-[720px] table-fixed border-collapse text-sm">
          <colgroup>
            <col class="w-[34%]" />
            <col />
            <col class="w-24" />
            <col class="w-24" />
            <col class="w-36" />
          </colgroup>
          <thead>
            <tr class="border-b border-line text-left text-xs whitespace-nowrap text-ink-3">
              <th class="py-2 pl-3.5 font-normal">경로</th>
              <th class="px-3 py-2 font-normal">설명</th>
              <th class="px-3 py-2 text-right font-normal">에이전트</th>
              <th class="px-3 py-2 text-right font-normal">스캔 대상</th>
              <th class="py-2 pl-3 pr-3.5 text-right font-normal">동작</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="d in dirs" :key="d.id" class="border-b border-line align-top">
              <td class="mono min-w-0 py-3 pl-3.5 text-xs [overflow-wrap:anywhere]">{{ d.path }}</td>
              <td class="min-w-0 px-3 py-3 break-words text-ink-2">{{ d.description || '—' }}</td>
              <td class="mono px-3 py-3 text-right">{{ formatNumber(d.agents) }}</td>
              <td class="mono px-3 py-3 text-right">{{ formatNumber(d.scanTargets) }}</td>
              <td class="py-3 pl-3 pr-3.5">
                <div class="flex flex-wrap justify-end gap-1.5">
                  <AppButton size="sm" @click="openEdit(d)">수정</AppButton>
                  <AppButton size="sm" variant="danger" @click="removing = d">삭제</AppButton>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </Panel>

    <AppModal v-model:open="formOpen" :title="editing ? '감지 대상 디렉터리 수정' : '감지 대상 디렉터리 추가'">
      <form id="detect-dir-form" class="grid grid-cols-1 gap-3" @submit.prevent="save">
        <FormField label="경로" hint="호스트의 절대 경로입니다. 하위 디렉터리까지 탐색합니다." :error="formPathError">
          <input v-model="form.path" type="text" class="input mono w-full" maxlength="1024" placeholder="/opt" spellcheck="false" />
        </FormField>
        <FormField label="설명">
          <input v-model="form.description" type="text" class="input w-full" maxlength="200" />
        </FormField>
        <p v-if="editing && usage(editing)" class="note">경로를 바꾸면 이 디렉터리를 고른 {{ usage(editing) }}에 다음 수집부터 적용됩니다.</p>
        <p v-if="formError" class="note note-danger" role="alert">{{ formError }}</p>
      </form>
      <template #footer>
        <AppButton @click="formOpen = false">취소</AppButton>
        <AppButton type="submit" form="detect-dir-form" variant="primary" :disabled="!formValid || formBusy">
          {{ editing ? '저장' : '추가' }}
        </AppButton>
      </template>
    </AppModal>

    <AppModal v-model:open="removeOpen" title="감지 대상 디렉터리 삭제">
      <p class="text-sm">
        <span class="mono text-xs">{{ removing?.path }}</span>을 삭제합니다.
        <template v-if="removing && usage(removing)">
          이 디렉터리를 고른 {{ usage(removing) }}에서 빠지고, 다음 수집부터 이 디렉터리를 탐색하지 않습니다.
        </template>
      </p>
      <p v-if="removeError" class="note note-danger mt-3" role="alert">{{ removeError }}</p>
      <template #footer>
        <AppButton @click="removeOpen = false">취소</AppButton>
        <AppButton variant="danger" :disabled="removeBusy" @click="remove">삭제</AppButton>
      </template>
    </AppModal>
  </div>
</template>
