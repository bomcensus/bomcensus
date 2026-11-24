<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { FeedServer, FeedServerStatus } from '~/types'
import type { Tone } from '~/utils/labels'
import {
  createFeedServer,
  deleteFeedServer,
  getFeedInstance,
  listFeedServers,
  rematchFeedServer,
  testFeedServer,
  toApiError,
  trustFeedServerKey,
  updateFeedServer,
} from '~/api'

useHead({ title: '취약점 피드 · bomcensus' })

const { data: instance, error: instanceError, refresh: refreshInstance } = useLoad('feed-instance', () => getFeedInstance())
const { data: list, error, refresh } = useLoad('feed-servers', () => listFeedServers())

const servers = computed(() => list.value?.items ?? [])
const active = computed(() => servers.value.find((s) => s.active))

const statusLabel: Record<FeedServerStatus, string> = {
  never: '연결한 적 없음',
  connected: '연결됨',
  key_changed: '키 변경 감지',
  error: '오류',
}
const statusTone: Record<FeedServerStatus, Tone> = {
  never: 'neutral',
  connected: 'ok',
  key_changed: 'danger',
  error: 'warn',
}

function statusNote(s: FeedServer): string {
  if (s.status === 'connected') return [s.lastOkAt ? formatRelative(s.lastOkAt) : '', s.grade].filter(Boolean).join(' · ')
  if (s.status === 'key_changed') return formatDateTime(s.presentedAt)
  if (s.status === 'error') return formatRelative(s.lastErrorAt)
  return ''
}

// One action at a time per server; errors are shown under the table.
const busy = ref<string>()
const actionError = ref('')

function replace(s: FeedServer) {
  if (!list.value) return
  list.value = { ...list.value, items: list.value.items.map((x) => (x.id === s.id ? s : x)) }
}

async function run(id: string, fn: () => Promise<unknown>) {
  if (busy.value) return
  busy.value = id
  actionError.value = ''
  try {
    await fn()
  } catch (e) {
    actionError.value = toApiError(e).message
  } finally {
    busy.value = undefined
  }
}

const activate = (s: FeedServer) =>
  run(s.id, async () => {
    await updateFeedServer(s.id, { active: true })
    await refresh()
  })
const setTelemetry = (s: FeedServer, telemetry: boolean) => run(s.id, async () => replace(await updateFeedServer(s.id, { telemetry })))
const setEnabled = (s: FeedServer, enabled: boolean) => run(s.id, async () => replace(await updateFeedServer(s.id, { enabled })))
const test = (s: FeedServer) => run(s.id, async () => replace(await testFeedServer(s.id)))

const rematchQueued = ref(false)
const rematch = (s: FeedServer) =>
  run(s.id, async () => {
    await rematchFeedServer(s.id)
    rematchQueued.value = true
    await refresh()
  })

// ── Key change ────────────────────────────────────────

const dismissed = ref(new Set<string>())
const trust = (s: FeedServer) =>
  run(s.id, async () => {
    if (!s.presentedKey) return
    replace(await trustFeedServerKey(s.id, s.presentedKey))
  })

// ── Add ───────────────────────────────────────────────

const addOpen = ref(false)
const addForm = reactive({ name: '', url: '', telemetry: true })
const addBusy = ref(false)
const addError = ref('')
const addValid = computed(() => !!addForm.name.trim() && /^https?:\/\//i.test(addForm.url.trim()))

function openAdd() {
  Object.assign(addForm, { name: '', url: '', telemetry: true })
  addError.value = ''
  addOpen.value = true
}

async function add() {
  if (!addValid.value || addBusy.value) return
  addBusy.value = true
  addError.value = ''
  try {
    await createFeedServer({ name: addForm.name.trim(), url: addForm.url.trim(), telemetry: addForm.telemetry })
    addOpen.value = false
    await refresh()
  } catch (e) {
    const err = toApiError(e)
    addError.value = err.status === 409 ? '같은 URL의 서버가 이미 있습니다' : err.message
  } finally {
    addBusy.value = false
  }
}

// ── Remove ────────────────────────────────────────────

const removing = ref<FeedServer>()
watch(removing, () => (actionError.value = ''))
const removeOpen = computed({
  get: () => !!removing.value,
  set: (v) => {
    if (!v) removing.value = undefined
  },
})
async function remove() {
  const s = removing.value
  if (!s) return
  await run(s.id, async () => {
    await deleteFeedServer(s.id)
    removing.value = undefined
    await refresh()
  })
}
</script>

<template>
  <div class="grid grid-cols-1 gap-4">
    <Panel title="이 서버의 instance" description="feed 서버는 이 키로 bomcensus 서버를 구분합니다. 설치할 때 만들어졌고 바꿀 수 없습니다.">
      <LoadError v-if="instanceError" :error="instanceError" @retry="refreshInstance" />
      <LoadingText v-else-if="!instance" />
      <dl v-else class="kv">
        <dt>instance ID</dt>
        <dd class="min-w-0"><CopyField :value="instance.instanceId" label="instance ID" /></dd>
        <dt>만든 시각</dt>
        <dd>{{ formatDateTime(instance.createdAt) }}</dd>
      </dl>
    </Panel>

    <Panel title="feed 서버" description="취약점 매칭은 활성 서버 하나로 합니다. 서버 키는 처음 연결할 때 저장하고, 이후 바뀌면 연결을 멈춥니다." flush>
      <template #actions>
        <AppButton size="sm" variant="primary" @click="openAdd">서버 추가</AppButton>
      </template>
      <LoadError v-if="error" :error="error" @retry="refresh" />
      <LoadingText v-else-if="!list" class="p-3.5" />
      <div v-else class="overflow-x-auto">
        <table class="w-full min-w-[980px] table-fixed border-collapse text-sm">
          <colgroup>
            <col class="w-14" />
            <col class="w-[26%]" />
            <col class="w-40" />
            <col />
            <col class="w-28" />
            <col class="w-32" />
            <col class="w-48" />
          </colgroup>
          <thead>
            <tr class="border-b border-line text-left text-xs whitespace-nowrap text-ink-3">
              <th class="w-14 py-2 pl-3.5 font-normal">활성</th>
              <th class="px-3 py-2 font-normal">서버</th>
              <th class="px-3 py-2 font-normal">상태</th>
              <th class="px-3 py-2 font-normal">서버 키</th>
              <th class="px-3 py-2 font-normal">통계 동의</th>
              <th class="px-3 py-2 font-normal">데이터</th>
              <th class="py-2 pl-3 pr-3.5 text-right font-normal">동작</th>
            </tr>
          </thead>
          <tbody>
            <template v-for="s in servers" :key="s.id">
              <tr class="border-b border-line align-top">
                <td class="py-3 pl-3.5">
                  <input
                    type="radio"
                    name="feed-active"
                    class="mt-0.5 size-4 accent-(--accent)"
                    :checked="s.active"
                    :disabled="!s.enabled || !!busy"
                    :aria-label="`${s.name} 활성`"
                    @change="activate(s)"
                  />
                </td>
                <td class="min-w-0 px-3 py-3">
                  <span class="font-semibold">{{ s.name }}</span>
                  <StatusBadge v-if="s.builtin" class="ml-1" label="기본" />
                  <StatusBadge v-if="!s.enabled" class="ml-1" label="사용 안 함" />
                  <span class="mono block text-xs [overflow-wrap:anywhere] text-ink-2">{{ s.url }}</span>
                </td>
                <td class="px-3 py-3">
                  <StatusBadge dot :tone="statusTone[s.status]" :label="statusLabel[s.status]" />
                  <span v-if="statusNote(s)" class="mt-0.5 block text-xs text-ink-3">{{ statusNote(s) }}</span>
                  <span v-if="s.status === 'error' && s.lastError" class="mt-0.5 block max-w-64 text-xs break-words text-ink-2">{{ s.lastError }}</span>
                </td>
                <td class="min-w-0 px-3 py-3">
                  <template v-if="s.serverKey">
                    <span class="mono text-xs break-all">{{ s.serverKey }}</span>
                    <span class="mt-0.5 block text-xs text-ink-3">
                      {{ s.status === 'key_changed' ? '저장된 키' : `저장 ${formatDateTime(s.keyTrustedAt)}` }}
                    </span>
                  </template>
                  <template v-else>
                    <span class="text-ink-3">첫 연결 때 저장</span>
                    <span class="mt-0.5 block text-xs text-ink-3">아직 연결하지 않음</span>
                  </template>
                </td>
                <td class="px-3 py-3">
                  <label class="inline-flex cursor-pointer items-center gap-1.5">
                    <input
                      type="checkbox"
                      class="size-[15px] accent-(--accent)"
                      :checked="s.telemetry"
                      :disabled="!!busy"
                      @change="setTelemetry(s, ($event.target as HTMLInputElement).checked)"
                    />
                    {{ s.telemetry ? '켬' : '끔' }}
                  </label>
                </td>
                <td class="px-3 py-3 text-xs text-ink-2">
                  <template v-if="s.revision !== undefined">
                    <span class="mono">rev {{ s.revision }}</span>
                    <span class="block whitespace-nowrap text-ink-3">{{ formatRelative(s.statusCheckedAt) }} 확인</span>
                  </template>
                  <span v-else class="text-ink-3">—</span>
                </td>
                <td class="py-3 pl-3 pr-3.5">
                  <div class="flex flex-wrap justify-end gap-1.5">
                    <AppButton size="sm" :disabled="!!busy" @click="test(s)">{{ busy === s.id ? '연결 중' : '연결 시험' }}</AppButton>
                    <AppButton v-if="!s.active" size="sm" :disabled="!!busy" @click="setEnabled(s, !s.enabled)">
                      {{ s.enabled ? '사용 안 함' : '사용' }}
                    </AppButton>
                    <AppButton v-if="!s.builtin && !s.active" size="sm" variant="danger" :disabled="!!busy" @click="removing = s">삭제</AppButton>
                  </div>
                </td>
              </tr>
              <tr v-if="s.status === 'key_changed' && !dismissed.has(s.id)" class="border-b border-line bg-critical-soft">
                <td colspan="7" class="py-3 pl-[70px] pr-3.5">
                  <div class="flex flex-col gap-2.5">
                    <p class="font-semibold text-critical">서버가 처음 연결 때와 다른 키를 보냈습니다. {{ s.active ? '매칭을 멈췄습니다.' : '이 서버를 쓰지 않습니다.' }}</p>
                    <dl class="grid grid-cols-[110px_minmax(0,1fr)] gap-x-3 gap-y-1">
                      <dt class="text-ink-2">저장된 키</dt>
                      <dd class="mono text-xs break-all">
                        {{ s.serverKey }} <span class="text-ink-3">· {{ formatDate(s.keyTrustedAt) }}부터</span>
                      </dd>
                      <dt class="text-ink-2">받은 키</dt>
                      <dd class="mono text-xs break-all">
                        {{ s.presentedKey }} <span class="text-ink-3">· {{ formatDateTime(s.presentedAt) }}</span>
                      </dd>
                    </dl>
                    <p class="max-w-[80ch] text-ink-2">
                      서버를 다시 설치했거나 키를 교체했다면 운영자에게 받은 공개 키와 위의 받은 키가 같은지 확인한 뒤 신뢰하세요. 모르는 변경이면 중간에서
                      가로채는 상황일 수 있습니다.
                    </p>
                    <div class="flex flex-wrap gap-2">
                      <AppButton variant="danger" :disabled="!!busy" @click="trust(s)">받은 키를 신뢰하고 다시 연결</AppButton>
                      <AppButton @click="dismissed = new Set([...dismissed, s.id])">그대로 두기</AppButton>
                    </div>
                  </div>
                </td>
              </tr>
            </template>
          </tbody>
        </table>
      </div>
      <p v-if="actionError" class="note note-danger m-3.5" role="alert">{{ actionError }}</p>
    </Panel>

    <Panel
      v-if="active"
      :title="`활성 서버 데이터 · ${active.name}`"
      description="데이터 리비전이나 규칙이 바뀌면 고유 컴포넌트를 다시 조회합니다. 15분마다 확인합니다."
    >
      <template #actions>
        <AppButton size="sm" :disabled="!!busy" @click="rematch(active)">전체 재조회</AppButton>
      </template>
      <p v-if="rematchQueued" class="note mb-3">재조회를 예약했습니다. 컴포넌트 수에 따라 몇 분 걸립니다.</p>
      <div v-if="active.revision !== undefined" class="grid grid-cols-1 gap-4 md:grid-cols-2">
        <dl class="kv">
          <dt>데이터 리비전</dt>
          <dd class="mono">{{ active.revision }}</dd>
          <dt>규칙</dt>
          <dd class="mono">{{ active.rulesDigest || '—' }}</dd>
          <dt>세션</dt>
          <dd>
            <template v-if="active.sessionExpiresAt">{{ active.grade || '—' }} · 만료 {{ formatDateTime(active.sessionExpiresAt) }}</template>
            <span v-else class="text-ink-3">없음</span>
          </dd>
          <dt>확인 시각</dt>
          <dd>{{ formatDateTime(active.statusCheckedAt) }}</dd>
          <template v-if="active.matching">
            <dt>매칭</dt>
            <dd>
              <span class="mono">{{ formatNumber(active.matching.checked) }}</span> 컴포넌트 ·
              <span class="mono">{{ formatNumber(active.matching.unsupported) }}</span> unsupported
              <template v-if="active.matching.pending > 0"> · <span class="mono">{{ formatNumber(active.matching.pending) }}</span> 대기</template>
            </dd>
            <dt>취약 컴포넌트</dt>
            <dd class="mono">{{ formatNumber(active.matching.vulnerable) }}</dd>
          </template>
        </dl>
        <p v-if="active.sources.length === 0" class="text-sm text-ink-3">서버가 알려 준 원본이 없습니다.</p>
        <table v-else class="w-full text-sm">
          <thead>
            <tr class="border-b border-line text-left text-xs text-ink-3">
              <th class="pb-1.5 font-normal">원본</th>
              <th class="pb-1.5 font-normal">갱신</th>
              <th class="pb-1.5 text-right font-normal">상태</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="src in active.sources" :key="src.name" class="border-b border-line">
              <td class="mono py-1.5 text-xs">{{ src.name }}</td>
              <td class="py-1.5 text-xs text-ink-2">{{ src.updatedAt ? formatDateTime(src.updatedAt) : '—' }}</td>
              <td class="py-1.5 text-right text-xs" :class="src.healthy === false ? 'text-critical' : 'text-ok'">
                {{ src.healthy === false ? '오류' : '정상' }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-else class="text-sm text-ink-2">아직 연결하지 않았습니다. <b class="font-semibold">연결 시험</b>을 누르면 서버 키를 저장하고 데이터 상태를 가져옵니다.</p>
    </Panel>

    <AppModal v-model:open="addOpen" title="feed 서버 추가">
      <form id="feed-add-form" class="grid grid-cols-1 gap-3" @submit.prevent="add">
        <FormField label="이름">
          <input v-model="addForm.name" type="text" class="input w-full" maxlength="100" />
        </FormField>
        <FormField label="URL" hint="https만 받습니다. 서버 키는 처음 연결할 때 저장합니다.">
          <input v-model="addForm.url" type="url" class="input mono w-full" placeholder="https://feed.example.com" spellcheck="false" />
        </FormField>
        <label class="inline-flex items-center gap-2 text-sm">
          <input v-model="addForm.telemetry" type="checkbox" class="size-[15px] accent-(--accent)" />
          익명 통계에 동의 (컴포넌트·취약점 일별 집계, instance와 연결되지 않음)
        </label>
        <p v-if="addError" class="note note-danger" role="alert">{{ addError }}</p>
      </form>
      <template #footer>
        <AppButton @click="addOpen = false">취소</AppButton>
        <AppButton type="submit" form="feed-add-form" variant="primary" :disabled="!addValid || addBusy">추가</AppButton>
      </template>
    </AppModal>

    <AppModal v-model:open="removeOpen" title="feed 서버 삭제">
      <p class="text-sm">
        <b class="font-semibold">{{ removing?.name }}</b> <span class="mono text-xs text-ink-2">{{ removing?.url }}</span>을 삭제합니다. 저장된 서버 키도
        지워집니다.
      </p>
      <p v-if="actionError" class="note note-danger mt-3" role="alert">{{ actionError }}</p>
      <template #footer>
        <AppButton @click="removeOpen = false">취소</AppButton>
        <AppButton variant="danger" :disabled="!!busy" @click="remove">삭제</AppButton>
      </template>
    </AppModal>
  </div>
</template>
