<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import { Ban, Check, Pencil } from '@lucide/vue'
import type { Agent, IntegrityMode } from '~/types'
import {
  approveAgent,
  getAgent,
  getAsset,
  getIntegrityPolicy,
  getRegisterKey,
  listDetectDirs,
  optional,
  revokeAgent,
  toApiError,
  updateAgent,
} from '~/api'

const route = useRoute()
const id = String(route.params.id)

const { data: detail, error, refresh } = useLoad(`agent:${id}`, async () => {
  const agent = await getAgent(id)
  // The asset may be gone; the agent still shows without it.
  const asset = agent.assetId ? await optional(getAsset(agent.assetId)) : undefined
  // The key may be revoked and deleted; the agent still shows its id.
  const key = agent.registerKeyId ? await optional(getRegisterKey(agent.registerKeyId)) : undefined
  // Only agents take detect directories and integrity modes.
  const dirs = agent.kind === 'agent' ? (await listDetectDirs()).items : []
  const integrity = agent.kind === 'agent' ? await getIntegrityPolicy() : undefined
  return { agent, asset, key, dirs, integrity }
})

const agent = computed(() => detail.value?.agent)
const asset = computed(() => detail.value?.asset)
const key = computed(() => detail.value?.key)
const dirs = computed(() => detail.value?.dirs ?? [])
const assignedDirs = computed(() => {
  const ids = new Set(agent.value?.detectDirIds ?? [])
  return dirs.value.filter((d) => ids.has(d.id))
})

useHead({ title: computed(() => `${agent.value?.hostname ?? '에이전트'} · bomcensus`) })

const kindLabel = (a: Agent) => (a.kind === 'agent' ? 'Agent' : 'Scanner')
const certDays = computed(() => (agent.value?.certExpiresAt ? daysUntil(agent.value.certExpiresAt) : undefined))

// ── Approve ───────────────────────────────────────────

const approveBusy = ref(false)
const actionError = ref('')

async function approve() {
  approveBusy.value = true
  actionError.value = ''
  try {
    await approveAgent(id)
    await refresh()
  } catch (e) {
    const err = toApiError(e)
    actionError.value = err.status === 409 ? '승인 대기 상태가 아닙니다' : err.message
  } finally {
    approveBusy.value = false
  }
}

// ── Description ───────────────────────────────────────

const descOpen = ref(false)
const descText = ref('')
const descBusy = ref(false)
const descError = ref('')
const descValid = computed(() => [...descText.value.trim()].length <= agentDescriptionMax)

function openDescription() {
  descText.value = agent.value?.description ?? ''
  descError.value = ''
  descOpen.value = true
}

async function saveDescription() {
  if (!descValid.value || descBusy.value) return
  descBusy.value = true
  descError.value = ''
  try {
    await updateAgent(id, { description: descText.value.trim() })
    descOpen.value = false
    await refresh()
  } catch (e) {
    descError.value = toApiError(e).message
  } finally {
    descBusy.value = false
  }
}

// ── Detect directories ────────────────────────────────

const dirsOpen = ref(false)
const dirsChosen = ref<string[]>([])
const dirsBusy = ref(false)
const dirsError = ref('')

function openDirs() {
  dirsChosen.value = [...(agent.value?.detectDirIds ?? [])]
  dirsError.value = ''
  dirsOpen.value = true
}

async function saveDirs() {
  if (dirsBusy.value) return
  dirsBusy.value = true
  dirsError.value = ''
  try {
    await updateAgent(id, { detectDirIds: dirsChosen.value })
    dirsOpen.value = false
    await refresh()
  } catch (e) {
    dirsError.value = toApiError(e).message
  } finally {
    dirsBusy.value = false
  }
}

// ── File integrity ────────────────────────────────────

const integrityMode = ref<IntegrityMode>('inherit')
watch(agent, (a) => (integrityMode.value = a?.integrity ?? 'inherit'), { immediate: true })
const integrityBusy = ref(false)
const integrityError = ref('')
watch(integrityMode, async (m) => {
  if (!agent.value || m === (agent.value.integrity ?? 'inherit') || integrityBusy.value) return
  integrityBusy.value = true
  integrityError.value = ''
  try {
    await updateAgent(id, { integrity: m })
    await refresh()
  } catch (e) {
    integrityError.value = toApiError(e).message
    integrityMode.value = agent.value.integrity ?? 'inherit'
  } finally {
    integrityBusy.value = false
  }
})

// ── Revoke ────────────────────────────────────────────

const revokeOpen = ref(false)
const revokeBusy = ref(false)
const revokeError = ref('')

function openRevoke() {
  revokeError.value = ''
  revokeOpen.value = true
}

async function revoke() {
  revokeBusy.value = true
  revokeError.value = ''
  try {
    await revokeAgent(id)
    revokeOpen.value = false
    await refresh()
  } catch (e) {
    const err = toApiError(e)
    revokeError.value = err.status === 409 ? '이미 폐기되었습니다' : err.message
  } finally {
    revokeBusy.value = false
  }
}
</script>

<template>
  <div>
    <template v-if="!agent">
      <PageHeader title="에이전트" :back="{ to: '/agents', label: '에이전트 목록' }" />
      <Panel>
        <LoadError v-if="error" :error="error" :back="{ to: '/agents', label: '에이전트 목록' }" @retry="refresh" />
        <LoadingText v-else />
      </Panel>
    </template>

    <template v-else>
      <PageHeader :title="agent.hostname" :back="{ to: '/agents', label: '에이전트 목록' }">
        <template #subtitle>
          <template v-if="agent.description">{{ agent.description }} · </template>
          {{ kindLabel(agent) }} · {{ agent.os }} · <span class="mono">{{ agent.address }}</span>
        </template>
        <template #actions>
          <StatusBadge dot :tone="agentStatusTone[agent.status]" :label="agentStatusLabel[agent.status]" />
          <AppButton v-if="agent.status === 'pending_approval'" variant="primary" :icon="Check" :disabled="approveBusy" @click="approve">승인</AppButton>
          <AppButton v-if="agent.status !== 'revoked'" variant="danger" :icon="Ban" @click="openRevoke">폐기</AppButton>
        </template>
      </PageHeader>

      <p v-if="actionError" class="note note-danger mb-4" role="alert">{{ actionError }}</p>

      <div v-if="agent.tlsMode !== 'pinned'" class="note note-warn mb-4">
        TLS 검증이 완화되어 있어 전송 구간에서 내용이 읽힐 수 있습니다. 인증과 무결성은 메시지 서명으로 유지됩니다.
      </div>

      <Panel title="정보">
        <dl class="kv">
          <dt>ID</dt>
          <dd class="mono">{{ agent.id }}</dd>
          <dt>종류</dt>
          <dd>{{ kindLabel(agent) }}</dd>
          <dt>설명</dt>
          <dd class="flex items-start gap-2">
            <span v-if="agent.description" class="break-words">{{ agent.description }}</span>
            <span v-else class="text-ink-3">—</span>
            <AppButton size="sm" variant="ghost" :icon="Pencil" @click="openDescription">편집</AppButton>
          </dd>
          <dt>자산</dt>
          <dd>
            <NuxtLink v-if="asset" :to="`/assets/${asset.id}`" class="link">{{ asset.name }}</NuxtLink>
            <span v-else-if="agent.assetId" class="mono text-ink-3">{{ agent.assetId }}</span>
            <span v-else class="text-ink-3">—</span>
          </dd>
          <dt>OS · 아키텍처</dt>
          <dd>{{ agent.os }} · <span class="mono">{{ agent.arch }}</span></dd>
          <dt>버전</dt>
          <dd class="mono">{{ agent.version }}</dd>
          <dt>업데이트 상태</dt>
          <dd>
            <StatusBadge :tone="updateStateTone[agent.updateState]" :label="updateStateLabel[agent.updateState]" />
            <Diagnostic v-if="agent.updateMessage" :text="agent.updateMessage" class="mt-0.5" />
          </dd>
          <dt>연결 모드</dt>
          <dd>{{ connModeLabel[agent.connMode] }}</dd>
          <template v-if="agent.connMode === 'listen'">
            <dt>listen 주소</dt>
            <dd>
              <NuxtLink v-if="agent.listenAddress" to="/agents?tab=listen" class="link mono">{{ agent.listenAddress }}</NuxtLink>
              <span v-else class="text-ink-3">—</span>
            </dd>
          </template>
          <dt>TLS 모드</dt>
          <dd><StatusBadge :tone="tlsModeTone[agent.tlsMode]" :label="tlsModeLabel[agent.tlsMode]" /></dd>
          <dt>관측된 발급자</dt>
          <dd>
            <template v-if="agent.tlsInterceptedBy">{{ agent.tlsInterceptedBy }} <span class="text-ink-3">(전송 중 TLS가 풀립니다)</span></template>
            <span v-else class="text-ink-3">서버 인증서와 일치</span>
          </dd>
          <dt>권한</dt>
          <dd>{{ privilegeLabel[agent.privilege] }}</dd>
          <dt>exec helper</dt>
          <dd>{{ agent.execHelper ? '사용' : '미사용' }}</dd>
          <dt>Register Key</dt>
          <dd>
            <NuxtLink to="/register-keys" class="link">{{ key?.name ?? agent.registerKeyId }}</NuxtLink>
            <span v-if="key" class="mono text-xs text-ink-3"> {{ key.id }}</span>
          </dd>
          <dt>인증서 만료</dt>
          <dd>
            <template v-if="agent.certExpiresAt && certDays !== undefined">
              {{ formatDate(agent.certExpiresAt) }}
              <span :class="certDays < 30 ? 'text-high' : 'text-ink-3'">({{ certDays >= 0 ? `${certDays}일 남음` : `${-certDays}일 지남` }})</span>
            </template>
            <span v-else class="text-ink-3">—</span>
          </dd>
          <dt>신뢰 번들</dt>
          <dd>
            <StatusBadge :tone="agent.trustBundleSynced ? 'ok' : 'warn'" :label="agent.trustBundleSynced ? '동기화됨' : '미동기화'" />
          </dd>
          <dt>등록 시각</dt>
          <dd>{{ formatDateTime(agent.enrolledAt) }}</dd>
          <dt>최근 접속</dt>
          <dd>{{ formatDateTime(agent.lastSeen) }} <TimeAgo :at="agent.lastSeen" class="text-ink-3" /></dd>
        </dl>
      </Panel>

      <Panel
        v-if="agent.kind === 'agent'"
        class="mt-4"
        title="감지 대상 디렉터리"
        description="고른 디렉터리만 하위까지 탐색해 소프트웨어를 찾습니다. 고르지 않으면 실행 중인 프로그램과 그 프로그램이 연 파일(jar 등)만 수집합니다."
      >
        <template #actions>
          <AppButton v-if="agent.status !== 'revoked'" size="sm" :icon="Pencil" @click="openDirs">선택</AppButton>
        </template>
        <ul v-if="assignedDirs.length > 0" class="grid grid-cols-1 gap-1">
          <li v-for="d in assignedDirs" :key="d.id" class="text-sm">
            <span class="mono text-xs [overflow-wrap:anywhere]">{{ d.path }}</span>
            <span v-if="d.description" class="ml-2 text-xs text-ink-3">{{ d.description }}</span>
          </li>
        </ul>
        <p v-else class="text-sm text-ink-3">선택한 디렉터리가 없습니다. 실행 중인 소프트웨어만 수집합니다.</p>
      </Panel>

      <Panel
        v-if="agent.kind === 'agent'"
        class="mt-4"
        title="파일 무결성 검사"
        :description="detail?.integrity ? `검사 시간대(${detail.integrity.windowStart}~${detail.integrity.windowEnd}, 노드 현지 시각)에 패키지 파일을 DB 해시와 비교합니다.` : undefined"
      >
        <template #actions>
          <StatusBadge :tone="agent.integrityEnabled ? 'ok' : 'neutral'" :label="agent.integrityEnabled ? '켜짐' : '꺼짐'" dot />
        </template>
        <IntegrityModePicker
          v-model="integrityMode"
          name="agent-integrity"
          kind-label="에이전트"
          :kind-default="detail?.integrity?.agents"
          :disabled="integrityBusy || agent.status === 'revoked'"
        />
        <p v-if="integrityError" class="note note-danger mt-2" role="alert">{{ integrityError }}</p>
        <p v-if="asset" class="mt-2 text-xs text-ink-2">
          결과는 <NuxtLink :to="`/assets/${asset.id}?tab=integrity`" class="link">자산 › 파일 무결성</NuxtLink>에서 봅니다.
        </p>
      </Panel>

      <AppModal v-model:open="dirsOpen" title="감지 대상 디렉터리 선택">
        <form id="agent-dirs-form" class="grid grid-cols-1 gap-3" @submit.prevent="saveDirs">
          <DetectDirPicker v-model="dirsChosen" :dirs="dirs" :disabled="dirsBusy" />
          <p class="text-xs text-ink-3">바꾼 내용은 에이전트가 다음에 서버에 접속할 때 반영되고, 그때 소프트웨어를 다시 수집합니다.</p>
          <p v-if="dirsError" class="note note-danger" role="alert">{{ dirsError }}</p>
        </form>
        <template #footer>
          <AppButton @click="dirsOpen = false">취소</AppButton>
          <AppButton type="submit" form="agent-dirs-form" variant="primary" :disabled="dirsBusy">저장</AppButton>
        </template>
      </AppModal>

      <AppModal v-model:open="descOpen" title="설명 편집">
        <form id="agent-description-form" class="grid grid-cols-1 gap-3" @submit.prevent="saveDescription">
          <FormField
            label="설명"
            :hint="`같은 호스트명의 에이전트를 구분할 때 씁니다. 최대 ${agentDescriptionMax}자`"
            :error="descValid ? undefined : `${agentDescriptionMax}자 이하로 입력합니다`"
          >
            <input v-model="descText" class="input w-full" placeholder="예: prod 클러스터 scanner" />
          </FormField>
          <p v-if="descError" class="note note-danger" role="alert">{{ descError }}</p>
        </form>
        <template #footer>
          <AppButton @click="descOpen = false">취소</AppButton>
          <AppButton type="submit" form="agent-description-form" variant="primary" :disabled="!descValid || descBusy">저장</AppButton>
        </template>
      </AppModal>

      <AppModal v-model:open="revokeOpen" title="에이전트 폐기">
        <p class="text-sm">
          <strong>{{ agent.hostname }}</strong>의 인증서를 폐기합니다. 이 에이전트는 더 이상 서버와 통신할 수 없고, 다시 쓰려면 새로 등록해야 합니다.
        </p>
        <p v-if="revokeError" class="note note-danger mt-3" role="alert">{{ revokeError }}</p>
        <template #footer>
          <AppButton @click="revokeOpen = false">취소</AppButton>
          <AppButton variant="danger" :disabled="revokeBusy" @click="revoke">폐기</AppButton>
        </template>
      </AppModal>
    </template>
  </div>
</template>
