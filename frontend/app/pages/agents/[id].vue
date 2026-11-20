<script setup lang="ts">
import { Ban, Check } from '@lucide/vue'
import type { Agent } from '~/types'
import { agents as mockAgents, getAsset, getRegisterKey } from '~/mock'

const route = useRoute()
const id = computed(() => String(route.params.id ?? ''))

// 승인·폐기는 이 페이지의 복사본에만 반영된다
const agents = ref<Agent[]>(mockAgents.map((a) => ({ ...a })))
const agent = computed(() => agents.value.find((a) => a.id === id.value))
const asset = computed(() => (agent.value?.assetId ? getAsset(agent.value.assetId) : undefined))
const key = computed(() => (agent.value ? getRegisterKey(agent.value.registerKeyId) : undefined))

useHead({ title: computed(() => `${agent.value?.hostname ?? '에이전트'} · bomcensus`) })

const revokeOpen = ref(false)

function approve() {
  if (agent.value) agent.value.status = 'online'
}
function revoke() {
  if (agent.value) agent.value.status = 'revoked'
  revokeOpen.value = false
}

const certDays = computed(() => (agent.value ? daysUntil(agent.value.certExpiresAt) : 0))
const kindLabel = (a: Agent) => (a.kind === 'agent' ? 'Agent' : 'Scanner')
</script>

<template>
  <div>
    <EmptyState v-if="!agent" title="찾을 수 없음">
      <AppButton to="/agents">에이전트 목록</AppButton>
    </EmptyState>

    <template v-else>
      <PageHeader :title="agent.hostname" :back="{ to: '/agents', label: '에이전트 목록' }">
        <template #subtitle>
          {{ kindLabel(agent) }} · {{ agent.os }} · <span class="mono">{{ agent.address }}</span>
        </template>
        <template #actions>
          <StatusBadge dot :tone="agentStatusTone[agent.status]" :label="agentStatusLabel[agent.status]" />
          <AppButton v-if="agent.status === 'pending_approval'" variant="primary" :icon="Check" @click="approve">승인</AppButton>
          <AppButton v-if="agent.status !== 'revoked'" variant="danger" :icon="Ban" @click="revokeOpen = true">폐기</AppButton>
        </template>
      </PageHeader>

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
            <span v-else class="text-ink-3">연결된 자산 없음</span>
          </dd>
          <dt>OS · 아키텍처</dt>
          <dd>{{ agent.os }} · <span class="mono">{{ agent.arch }}</span></dd>
          <dt>버전</dt>
          <dd class="mono">{{ agent.version }}</dd>
          <dt>업데이트 상태</dt>
          <dd><StatusBadge :tone="updateStateTone[agent.updateState]" :label="updateStateLabel[agent.updateState]" /></dd>
          <dt>연결 모드</dt>
          <dd>{{ connModeLabel[agent.connMode] }}</dd>
          <template v-if="agent.connMode === 'listen'">
            <dt>listen 주소</dt>
            <dd class="mono">{{ agent.listenAddress ?? '—' }}</dd>
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
            {{ formatDate(agent.certExpiresAt) }}
            <span :class="certDays < 30 ? 'text-high' : 'text-ink-3'">({{ certDays >= 0 ? `${certDays}일 남음` : `${-certDays}일 지남` }})</span>
          </dd>
          <dt>등록 시각</dt>
          <dd>{{ formatDateTime(agent.enrolledAt) }}</dd>
          <dt>최근 접속</dt>
          <dd>{{ formatDateTime(agent.lastSeen) }} <span class="text-ink-3">({{ formatRelative(agent.lastSeen) }})</span></dd>
        </dl>
      </Panel>

      <AppModal v-model:open="revokeOpen" title="에이전트 폐기">
        <p class="text-sm">
          <strong>{{ agent.hostname }}</strong>의 인증서를 폐기합니다. 이 에이전트는 더 이상 서버와 통신할 수 없고, 다시 쓰려면 새로 등록해야 합니다.
        </p>
        <template #footer>
          <AppButton @click="revokeOpen = false">취소</AppButton>
          <AppButton variant="danger" @click="revoke">폐기</AppButton>
        </template>
      </AppModal>
    </template>
  </div>
</template>
