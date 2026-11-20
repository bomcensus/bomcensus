<script setup lang="ts">
import type { TlsEndpoint } from '~/types'
import { tlsState } from '~/mock'

useHead({ title: 'TLS · bomcensus' })

type EndpointKey = 'web' | 'agent'

// 전환과 적용은 이 페이지의 복사본에만 반영된다
const tls = reactive({ web: { ...tlsState.web }, agent: { ...tlsState.agent } })
const panels: { key: EndpointKey; title: string }[] = [
  { key: 'web', title: 'Web/API TLS' },
  { key: 'agent', title: 'Agent TLS' },
]
const modeLabel: Record<TlsEndpoint['mode'], string> = { auto: '자동', manual: '수동' }
const otherOf = (m: TlsEndpoint['mode']): TlsEndpoint['mode'] => (m === 'auto' ? 'manual' : 'auto')

const remaining = (days: number) => (days < 0 ? `${-days}일 지남` : `${days}일 남음`)
const dayTone = (days: number): Tone => (days < 0 ? 'danger' : days <= 30 ? 'warn' : 'ok')
const days = (key: EndpointKey) => daysUntil(tls[key].expiresAt)
const caDays = computed(() => daysUntil(tlsState.agentCaExpiresAt))

const switchKey = ref<EndpointKey>()
const switchOpen = computed({
  get: () => !!switchKey.value,
  set: (v) => {
    if (!v) switchKey.value = undefined
  },
})
const switchTitle = computed(() => (switchKey.value ? panels.find((p) => p.key === switchKey.value)!.title : ''))
function switchMode() {
  const k = switchKey.value
  if (k) tls[k].mode = otherOf(tls[k].mode)
  switchKey.value = undefined
}
</script>

<template>
  <div class="grid grid-cols-1 gap-4">
    <Panel v-for="p in panels" :key="p.key" :title="p.title">
      <template #actions>
        <StatusBadge tone="info" :label="modeLabel[tls[p.key].mode]" />
        <AppButton size="sm" @click="switchKey = p.key">{{ modeLabel[otherOf(tls[p.key].mode)] }}로 전환</AppButton>
      </template>

      <dl class="kv">
        <dt>주체</dt>
        <dd class="mono break-all">{{ tls[p.key].subject || '—' }}</dd>
        <dt>발급자</dt>
        <dd class="mono break-all">{{ tls[p.key].issuer || '—' }}</dd>
        <dt>이름</dt>
        <dd class="mono break-all">{{ tls[p.key].names.length ? tls[p.key].names.join(', ') : '—' }}</dd>
        <dt>만료</dt>
        <dd>
          <span class="whitespace-nowrap">{{ formatDate(tls[p.key].expiresAt) }}</span>
          <StatusBadge class="ml-1" :tone="dayTone(days(p.key))" :label="remaining(days(p.key))" />
        </dd>
        <template v-if="p.key === 'agent'">
          <dt>신뢰 앵커 SPKI 해시</dt>
          <dd class="min-w-0"><CopyField v-if="tlsState.anchorSpkiHash" :value="tlsState.anchorSpkiHash" /><span v-else>—</span></dd>
          <dt>Agent CA 만료</dt>
          <dd>
            <span class="whitespace-nowrap">{{ formatDate(tlsState.agentCaExpiresAt) }}</span>
            <StatusBadge class="ml-1" :tone="dayTone(caDays)" :label="remaining(caDays)" />
          </dd>
        </template>
      </dl>

      <p v-if="days(p.key) <= 30" class="note note-warn mt-3">
        {{ days(p.key) < 0 ? '인증서가 만료되었습니다.' : `인증서가 ${days(p.key)}일 안에 만료됩니다.` }}
      </p>

      <div v-if="tls[p.key].mode === 'manual'" class="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2">
        <FormField label="인증서 체인"><input type="file" class="input w-full" /></FormField>
        <FormField label="키"><input type="file" class="input w-full" /></FormField>
        <p v-if="p.key === 'agent'" class="note note-warn md:col-span-2">
          신뢰 앵커가 다른 체인을 적용하면 기존 등록 문자열을 쓸 수 없고, 등록된 Agent는 다시 등록해야 합니다.
        </p>
        <div class="md:col-span-2"><AppButton variant="primary">적용</AppButton></div>
      </div>
    </Panel>

    <AppModal v-model:open="switchOpen" :title="`${switchTitle} 전환`">
      <p v-if="switchKey" class="text-sm">{{ switchTitle }}을 {{ modeLabel[otherOf(tls[switchKey].mode)] }}로 전환합니다.</p>
      <p v-if="switchKey === 'agent'" class="note note-warn mt-3">
        Agent TLS의 신뢰 앵커가 바뀝니다. 기존 등록 문자열을 쓸 수 없고, 등록된 Agent는 다시 등록해야 합니다.
      </p>
      <template #footer>
        <AppButton @click="switchOpen = false">취소</AppButton>
        <AppButton variant="primary" @click="switchMode">전환</AppButton>
      </template>
    </AppModal>
  </div>
</template>
