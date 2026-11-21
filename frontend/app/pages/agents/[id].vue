<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import { Ban, Check } from '@lucide/vue'
import type { Agent } from '~/types'
import { approveAgent, getAgent, getAsset, getRegisterKey, optional, revokeAgent, toApiError } from '~/api'

const route = useRoute()
const id = String(route.params.id)

const { data: detail, error, refresh } = useLoad(`agent:${id}`, async () => {
  const agent = await getAgent(id)
  // The asset may be gone; the agent still shows without it.
  const asset = agent.assetId ? await optional(getAsset(agent.assetId)) : undefined
  // The key may be revoked and deleted; the agent still shows its id.
  const key = agent.registerKeyId ? await optional(getRegisterKey(agent.registerKeyId)) : undefined
  return { agent, asset, key }
})

const agent = computed(() => detail.value?.agent)
const asset = computed(() => detail.value?.asset)
const key = computed(() => detail.value?.key)

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
