<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { DetectorTableCheck, DetectorTableProblem, DetectorTableRevision, DetectorTableUsage } from '~/types'
import {
  checkDetectorTable,
  getDefaultDetectorTable,
  getDetectorTable,
  getDetectorTableRevision,
  getDetectorTableUsage,
  listDetectorTableRevisions,
  resetDetectorTable,
  saveDetectorTable,
  toApiError,
} from '~/api'

useHead({ title: '소프트웨어 탐지 규칙 · bomcensus' })

const { data: state, error, refresh } = useLoad('detector-table', () => getDetectorTable())
const { data: def, refresh: refreshDefault } = useLoad('detector-table-default', () => getDefaultDetectorTable())
const { data: usage, error: usageError, refresh: refreshUsage } = useLoad('detector-table-usage', async () => (await getDetectorTableUsage()).items, () => [])
const { data: revisions, refresh: refreshRevisions } = useLoad('detector-table-revisions', async () => (await listDetectorTableRevisions()).items, () => [])

async function refreshAll() {
  await Promise.all([refresh(), refreshDefault(), refreshUsage(), refreshRevisions()])
}

// ── Editor ────────────────────────────────────────────

const text = ref('')
const loadedFrom = ref('')
watch(
  state,
  (s) => {
    if (s && !text.value) {
      text.value = s.yaml
      loadedFrom.value = '적용 중인 테이블'
    }
  },
  { immediate: true },
)
const dirty = computed(() => !!state.value && text.value !== state.value.yaml)

const check = ref<DetectorTableCheck>()
const checkedText = ref('')
const busy = ref(false)
const message = ref('')
const messageTone = ref<'ok' | 'danger'>('ok')
watch(text, () => {
  if (text.value !== checkedText.value) check.value = undefined
})

const errors = computed(() => (check.value?.problems ?? []).filter((p) => p.severity === 'error'))
const warnings = computed(() => (check.value ? check.value.problems : (state.value?.warnings ?? [])).filter((p) => p.severity === 'warning'))

function where(p: DetectorTableProblem): string {
  if (p.index < 0) return '테이블'
  return p.id ? `${p.index + 1}번째 탐지기 (${p.id})` : `${p.index + 1}번째 탐지기`
}

async function runCheck() {
  if (busy.value) return
  busy.value = true
  message.value = ''
  try {
    const t = text.value
    check.value = await checkDetectorTable(t)
    checkedText.value = t
    if (check.value.valid) {
      messageTone.value = 'ok'
      message.value = `오류가 없습니다. 탐지기 ${formatNumber(check.value.detectors ?? 0)}개`
    }
  } catch (e) {
    messageTone.value = 'danger'
    message.value = toApiError(e).message
  } finally {
    busy.value = false
  }
}

async function save() {
  if (busy.value || !dirty.value) return
  busy.value = true
  message.value = ''
  try {
    const t = text.value
    const res = await saveDetectorTable(t)
    if (res.check) {
      check.value = res.check
      checkedText.value = t
      messageTone.value = 'danger'
      message.value = '오류가 있어 저장하지 않았습니다.'
      return
    }
    check.value = undefined
    text.value = res.state?.yaml ?? t
    loadedFrom.value = '적용 중인 테이블'
    messageTone.value = 'ok'
    message.value = '저장했습니다. 에이전트와 스캐너는 다음 폴링 때 새 테이블을 받습니다.'
    await refreshAll()
  } catch (e) {
    messageTone.value = 'danger'
    message.value = toApiError(e).message
  } finally {
    busy.value = false
  }
}

function loadDefault() {
  if (!def.value) return
  text.value = def.value.yaml
  loadedFrom.value = '기본 테이블'
}

function revert() {
  if (!state.value) return
  text.value = state.value.yaml
  loadedFrom.value = '적용 중인 테이블'
}

async function loadRevision(r: DetectorTableRevision) {
  if (r.reset) {
    loadDefault()
    return
  }
  try {
    const full = await getDetectorTableRevision(r.revision)
    text.value = full.yaml ?? ''
    loadedFrom.value = `리비전 ${r.revision}`
  } catch (e) {
    messageTone.value = 'danger'
    message.value = toApiError(e).message
  }
}

// ── Diff against the default ──────────────────────────

const diffOpen = ref(false)
const diff = computed(() => (diffOpen.value && def.value ? diffHunks(lineDiff(def.value.yaml, text.value)) : []))
const diffStats = computed(() => {
  let added = 0
  let removed = 0
  for (const l of diff.value) {
    if (l.op === '+') added++
    else if (l.op === '-') removed++
  }
  return { added, removed }
})

// ── Reset ─────────────────────────────────────────────

const resetOpen = ref(false)
const resetError = ref('')
async function reset() {
  if (busy.value) return
  busy.value = true
  resetError.value = ''
  try {
    const s = await resetDetectorTable()
    text.value = s.yaml
    loadedFrom.value = '적용 중인 테이블'
    check.value = undefined
    resetOpen.value = false
    messageTone.value = 'ok'
    message.value = '기본 테이블로 되돌렸습니다.'
    await refreshAll()
  } catch (e) {
    resetError.value = toApiError(e).message
  } finally {
    busy.value = false
  }
}

// ── Usage ─────────────────────────────────────────────

const kindLabel: Record<string, string> = { agent: '에이전트', scanner: '스캐너' }

function tableLabel(u: DetectorTableUsage): { label: string; tone: 'ok' | 'warn' | 'neutral' | 'info' } {
  if (!u.reported) return { label: '보고 안 함 · 프로브 내장 테이블 (이전 버전)', tone: 'neutral' }
  if (!u.digest) return { label: '받지 않음 · 프로브 내장 테이블', tone: 'warn' }
  if (u.current) return { label: '적용 중인 테이블', tone: 'ok' }
  if (u.digest === state.value?.defaultDigest) return { label: '기본 테이블', tone: 'info' }
  return { label: '이전 테이블', tone: 'warn' }
}

const usageTotal = computed(() => (usage.value ?? []).reduce((n, u) => n + u.count, 0))
</script>

<template>
  <div class="grid grid-cols-1 gap-4">
    <Panel
      title="소프트웨어 탐지 규칙"
      description="패키지 관리자 밖에 설치된 소프트웨어(JDK, Tomcat, Genian NAC 등)를 파일 이름과 버전 문자열로 찾는 규칙입니다. 저장한 테이블은 에이전트와 스캐너가 다음 폴링 때 받아 프로브에 넘깁니다."
    >
      <LoadError v-if="error" :error="error" @retry="refresh" />
      <LoadingText v-else-if="!state" />
      <dl v-else class="kv">
        <dt>적용 중</dt>
        <dd>
          <StatusBadge v-if="state.custom" tone="info" label="관리자가 저장한 테이블" />
          <StatusBadge v-else tone="neutral" label="기본 테이블" />
          <span class="ml-2 text-ink-2">탐지기 {{ formatNumber(state.detectors) }}개</span>
        </dd>
        <dt>다이제스트</dt>
        <dd><span class="mono text-xs" :title="state.digest">{{ shortHash(state.digest, 16) }}</span></dd>
        <template v-if="state.revision">
          <dt>마지막 변경</dt>
          <dd>
            리비전 {{ state.revision }} · <TimeAgo :at="state.updatedAt" />
            <template v-if="state.updatedBy"> · {{ state.updatedBy }}</template>
          </dd>
        </template>
        <dt>기본 테이블</dt>
        <dd>
          <span class="mono text-xs" :title="state.defaultDigest">{{ shortHash(state.defaultDigest, 16) }}</span>
          <span v-if="def" class="ml-2 text-ink-3">{{ def.source === 'built-in' ? '서버 내장' : def.source }}</span>
          <span v-if="state.defaultDigest !== state.builtinDigest" class="ml-2 text-ink-3">(서버 내장 테이블과 다름)</span>
        </dd>
      </dl>
      <p class="note mt-3">
        프로브는 자신에게 내장된 테이블과 같은 항목만 그대로 신뢰합니다. 버전 명령(exec)은 내장 항목과 이름, 경로, 인수, 환경 변수가 모두 같을 때만 실행하고,
        내장 테이블과 다른 항목은 정적 규칙만 씁니다. 이때 옆 파일은 일치한 파일에서 두 단계 위까지, 민감한 위치(/root, /home, 키 파일 등)를 뺀 곳만 읽고, 찾은
        버전과 빌드는 숫자로 시작하는 64자 이하의 버전 형식이어야 합니다.
      </p>
    </Panel>

    <Panel title="YAML 편집" :description="loadedFrom ? `불러온 내용: ${loadedFrom}` : undefined">
      <template #actions>
        <div class="flex flex-wrap justify-end gap-1.5">
          <AppButton size="sm" :disabled="!def" @click="loadDefault">기본 테이블 불러오기</AppButton>
          <AppButton size="sm" :disabled="!dirty" @click="revert">변경 취소</AppButton>
          <AppButton size="sm" :disabled="!def" @click="diffOpen = !diffOpen">{{ diffOpen ? '비교 닫기' : '기본 테이블과 비교' }}</AppButton>
        </div>
      </template>
      <textarea
        v-model="text"
        rows="28"
        class="input mono w-full text-xs"
        spellcheck="false"
        autocomplete="off"
        aria-label="탐지 규칙 YAML"
        :disabled="!state"
      />
      <div class="mt-3 flex flex-wrap items-center gap-1.5">
        <AppButton :disabled="busy || !text.trim()" @click="runCheck">검사</AppButton>
        <AppButton variant="primary" :disabled="busy || !dirty" @click="save">저장</AppButton>
        <AppButton variant="danger" :disabled="busy || !state?.custom" @click="resetOpen = true">기본 테이블로 되돌리기</AppButton>
        <span v-if="dirty" class="text-xs text-ink-3">저장하지 않은 변경이 있습니다.</span>
      </div>
      <p v-if="message" class="note mt-3" :class="messageTone === 'danger' ? 'note-danger' : ''" role="status">{{ message }}</p>

      <div v-if="errors.length" class="mt-3" role="alert">
        <h3 class="mb-1 text-sm font-semibold text-critical">오류 {{ errors.length }}건 · 저장할 수 없습니다</h3>
        <ul class="grid gap-1 text-sm">
          <li v-for="(p, i) in errors" :key="`e${i}`" class="note note-danger">
            <span class="font-medium">{{ where(p) }}</span>: <span class="mono text-xs [overflow-wrap:anywhere]">{{ p.message }}</span>
          </li>
        </ul>
      </div>
      <div v-if="warnings.length" class="mt-3">
        <h3 class="mb-1 text-sm font-semibold text-medium">주의 {{ warnings.length }}건</h3>
        <ul class="grid gap-1 text-sm">
          <li v-for="(p, i) in warnings" :key="`w${i}`" class="note note-warn">
            <span class="font-medium">{{ where(p) }}</span>: 버전 명령이 내장 탐지기와 달라 실행하지 않고 정적 규칙만 씁니다.
          </li>
        </ul>
      </div>

      <div v-if="diffOpen && def" class="mt-4">
        <h3 class="mb-1 text-sm font-semibold">기본 테이블과 비교 <span class="font-normal text-ink-3">(+{{ diffStats.added }} −{{ diffStats.removed }})</span></h3>
        <p v-if="diff.length === 0" class="note">기본 테이블과 같습니다.</p>
        <div v-else class="pre max-h-[480px] overflow-y-auto p-0">
          <div
            v-for="(l, i) in diff"
            :key="i"
            class="flex gap-2 px-3"
            :class="l.op === '+' ? 'bg-ok-soft' : l.op === '-' ? 'bg-critical-soft' : ''"
          >
            <template v-if="l.op === 'gap'">
              <span class="text-ink-3">… 같은 줄 {{ l.count }}개</span>
            </template>
            <template v-else>
              <span class="w-10 shrink-0 select-none text-right text-ink-3">{{ l.oldNo ?? '' }}</span>
              <span class="w-10 shrink-0 select-none text-right text-ink-3">{{ l.newNo ?? '' }}</span>
              <span class="w-3 shrink-0 select-none">{{ l.op === ' ' ? '' : l.op }}</span>
              <span class="whitespace-pre">{{ l.text }}</span>
            </template>
          </div>
        </div>
      </div>
    </Panel>

    <Panel title="에이전트와 스캐너가 쓰는 테이블" :description="`승인된 에이전트와 스캐너 ${formatNumber(usageTotal)}개, 마지막 폴링 기준`" flush>
      <LoadError v-if="usageError" :error="usageError" @retry="refreshUsage" />
      <EmptyState v-else-if="(usage ?? []).length === 0" title="승인된 에이전트가 없습니다" />
      <div v-else class="overflow-x-auto">
        <table class="w-full min-w-[560px] table-fixed border-collapse text-sm">
          <colgroup>
            <col class="w-28" />
            <col />
            <col class="w-44" />
            <col class="w-20" />
          </colgroup>
          <thead>
            <tr class="border-b border-line text-left text-xs whitespace-nowrap text-ink-3">
              <th class="py-2 pl-3.5 font-normal">종류</th>
              <th class="px-3 py-2 font-normal">테이블</th>
              <th class="px-3 py-2 font-normal">다이제스트</th>
              <th class="py-2 pl-3 pr-3.5 text-right font-normal">수</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(u, i) in usage" :key="i" class="border-b border-line">
              <td class="py-2.5 pl-3.5">{{ kindLabel[u.kind] ?? u.kind }}</td>
              <td class="px-3 py-2.5"><StatusBadge :tone="tableLabel(u).tone" :label="tableLabel(u).label" /></td>
              <td class="mono px-3 py-2.5 text-xs" :title="u.digest">{{ u.digest ? shortHash(u.digest, 12) : '—' }}</td>
              <td class="mono py-2.5 pl-3 pr-3.5 text-right">{{ formatNumber(u.count) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </Panel>

    <Panel title="변경 기록" flush>
      <EmptyState v-if="(revisions ?? []).length === 0" title="변경 기록이 없습니다" description="저장하거나 되돌리면 여기에 남습니다." />
      <div v-else class="overflow-x-auto">
        <table class="w-full min-w-[560px] table-fixed border-collapse text-sm">
          <colgroup>
            <col class="w-20" />
            <col class="w-32" />
            <col />
            <col class="w-44" />
            <col class="w-28" />
          </colgroup>
          <thead>
            <tr class="border-b border-line text-left text-xs whitespace-nowrap text-ink-3">
              <th class="py-2 pl-3.5 font-normal">리비전</th>
              <th class="px-3 py-2 font-normal">시각</th>
              <th class="px-3 py-2 font-normal">변경</th>
              <th class="px-3 py-2 font-normal">다이제스트</th>
              <th class="py-2 pl-3 pr-3.5 text-right font-normal">동작</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in revisions" :key="r.revision" class="border-b border-line">
              <td class="mono py-2.5 pl-3.5">{{ r.revision }}</td>
              <td class="px-3 py-2.5"><TimeAgo :at="r.createdAt" /></td>
              <td class="px-3 py-2.5">
                {{ r.reset ? '기본 테이블로 되돌림' : '저장' }}<span v-if="r.createdBy" class="text-ink-3"> · {{ r.createdBy }}</span>
              </td>
              <td class="mono px-3 py-2.5 text-xs" :title="r.digest">{{ r.digest ? shortHash(r.digest, 12) : '—' }}</td>
              <td class="py-2.5 pl-3 pr-3.5 text-right">
                <AppButton size="sm" @click="loadRevision(r)">불러오기</AppButton>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </Panel>

    <AppModal v-model:open="resetOpen" title="기본 테이블로 되돌리기">
      <p class="text-sm">저장한 테이블 대신 기본 테이블을 씁니다. 에이전트와 스캐너는 다음 폴링 때 기본 테이블을 받습니다. 저장한 내용은 변경 기록에 남습니다.</p>
      <p v-if="resetError" class="note note-danger mt-3" role="alert">{{ resetError }}</p>
      <template #footer>
        <AppButton @click="resetOpen = false">취소</AppButton>
        <AppButton variant="danger" :disabled="busy" @click="reset">되돌리기</AppButton>
      </template>
    </AppModal>
  </div>
</template>
