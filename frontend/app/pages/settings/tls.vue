<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { TlsCertMode, TlsEndpointName } from '~/types'
import type { Tone } from '~/utils/labels'
import { changeAgentTlsAnchor, getTlsSettings, toApiError, updateTlsEndpoint } from '~/api'

useHead({ title: 'TLS · bomcensus' })

const { data: tls, error, refresh } = useLoad('tls-settings', () => getTlsSettings())

const panels: { key: TlsEndpointName; title: string }[] = [
  { key: 'web', title: 'Web/API TLS' },
  { key: 'agent', title: 'Agent TLS' },
]
const modeLabel: Record<TlsCertMode, string> = { auto: '자동', manual: '수동', off: '미사용' }

const remaining = (days: number) => (days < 0 ? `${-days}일 지남` : `${days}일 남음`)
const dayTone = (days: number): Tone => (days < 0 ? 'danger' : days <= 30 ? 'warn' : 'ok')
const daysOf = (iso?: string) => (iso ? daysUntil(iso) : undefined)
const titleOf = (key?: TlsEndpointName) => panels.find((p) => p.key === key)?.title ?? ''

const pendingAnchor = computed(() => tls.value?.pendingAnchor)

// ── Switch to automatic ───────────────────────────────

const autoKey = ref<TlsEndpointName>()
const autoOpen = computed({
  get: () => !!autoKey.value,
  set: (v) => {
    if (!v) autoKey.value = undefined
  },
})
const autoBusy = ref(false)
const autoError = ref('')

function askAuto(key: TlsEndpointName) {
  autoError.value = ''
  autoKey.value = key
}

async function switchToAuto() {
  const key = autoKey.value
  if (!key || autoBusy.value) return
  autoBusy.value = true
  autoError.value = ''
  try {
    await updateTlsEndpoint(key, { mode: 'auto' })
    autoKey.value = undefined
    await refresh()
  } catch (e) {
    autoError.value = toApiError(e).message
  } finally {
    autoBusy.value = false
  }
}

// ── Manual certificate ────────────────────────────────

const manualKey = ref<TlsEndpointName>()
const manualOpen = computed({
  get: () => !!manualKey.value,
  set: (v) => {
    if (!v) manualKey.value = undefined
  },
})
// Keys live only in this form and are cleared when the modal closes.
const emptyManual = () => ({ certificateChain: '', privateKey: '', clientCertificateChain: '', clientPrivateKey: '' })
const manual = reactive(emptyManual())
type ManualField = keyof ReturnType<typeof emptyManual>
const manualBusy = ref(false)
const manualError = ref('')
const manualValid = computed(
  () =>
    !!manual.certificateChain.trim() &&
    !!manual.privateKey.trim() &&
    // The client pair is all or nothing
    !!manual.clientCertificateChain.trim() === !!manual.clientPrivateKey.trim(),
)

watch(manualOpen, (open) => {
  if (!open) Object.assign(manual, emptyManual())
})

function openManual(key: TlsEndpointName) {
  Object.assign(manual, emptyManual())
  manualError.value = ''
  manualKey.value = key
}

async function readPem(e: Event, set: (text: string) => void, onError: (message: string) => void) {
  const input = e.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  try {
    set(await file.text())
  } catch (err) {
    onError(toApiError(err).message)
  }
  input.value = ''
}
const readManual = (e: Event, field: ManualField) =>
  readPem(e, (text) => (manual[field] = text), (message) => (manualError.value = message))

async function applyManual() {
  const key = manualKey.value
  if (!key || !manualValid.value || manualBusy.value) return
  manualBusy.value = true
  manualError.value = ''
  const withClient = key === 'agent' && !!manual.clientCertificateChain.trim()
  try {
    await updateTlsEndpoint(key, {
      mode: 'manual',
      certificateChain: manual.certificateChain,
      privateKey: manual.privateKey,
      clientCertificateChain: withClient ? manual.clientCertificateChain : undefined,
      clientPrivateKey: withClient ? manual.clientPrivateKey : undefined,
    })
    manualKey.value = undefined
    await refresh()
  } catch (e) {
    const err = toApiError(e)
    manualError.value = err.code === 'anchor_mismatch' ? '체인에 현재 신뢰 앵커(또는 준비된 앵커)가 없습니다' : err.message
  } finally {
    manualBusy.value = false
  }
}

// ── Trust anchor change ───────────────────────────────

const anchorOpen = ref(false)
const anchorCert = ref('')
const anchorForce = ref(false)
const anchorBusy = ref(false)
const anchorError = ref('')
const unsynced = computed(() => pendingAnchor.value?.unsyncedAgents ?? 0)
const prepareValid = computed(() => tls.value?.agent.mode !== 'manual' || !!anchorCert.value.trim())

function openAnchor() {
  anchorCert.value = ''
  anchorForce.value = false
  anchorError.value = ''
  anchorOpen.value = true
}

async function anchorStep(action: 'prepare' | 'activate' | 'cancel') {
  if (anchorBusy.value) return
  anchorBusy.value = true
  anchorError.value = ''
  try {
    await changeAgentTlsAnchor({
      action,
      certificate: action === 'prepare' && tls.value?.agent.mode === 'manual' ? anchorCert.value : undefined,
      force: action === 'activate' && unsynced.value > 0 ? anchorForce.value : undefined,
    })
    anchorOpen.value = false
    await refresh()
  } catch (e) {
    const err = toApiError(e)
    if (err.code === 'agents_not_synced') {
      anchorError.value = '신뢰 번들을 받아가지 않은 Agent가 있습니다'
      anchorForce.value = false
      await refresh()
    } else {
      anchorError.value = err.message
    }
  } finally {
    anchorBusy.value = false
  }
}
</script>

<template>
  <div>
    <Panel v-if="!tls">
      <LoadError v-if="error" :error="error" @retry="refresh" />
      <LoadingText v-else />
    </Panel>

    <div v-else class="grid grid-cols-1 gap-4">
      <Panel v-for="p in panels" :key="p.key" :title="p.title">
        <template #actions>
          <StatusBadge :tone="tls[p.key].mode === 'off' ? 'neutral' : 'info'" :label="modeLabel[tls[p.key].mode]" />
          <template v-if="tls[p.key].mode === 'auto'">
            <AppButton size="sm" @click="openManual(p.key)">수동으로 전환</AppButton>
          </template>
          <template v-else-if="tls[p.key].mode === 'manual'">
            <AppButton size="sm" @click="openManual(p.key)">인증서 교체</AppButton>
            <AppButton size="sm" @click="askAuto(p.key)">자동으로 전환</AppButton>
          </template>
        </template>

        <p v-if="tls[p.key].mode === 'off'" class="note">BOMCENSUS_WEB_TLS=off로 실행 중이어서 서버가 TLS를 처리하지 않습니다.</p>

        <template v-else>
          <dl class="kv">
            <dt>주체</dt>
            <dd class="mono break-all">{{ tls[p.key].subject || '—' }}</dd>
            <dt>발급자</dt>
            <dd class="mono break-all">{{ tls[p.key].issuer || '—' }}</dd>
            <dt>이름</dt>
            <dd class="mono break-all">{{ tls[p.key].names.length ? tls[p.key].names.join(', ') : '—' }}</dd>
            <dt>만료</dt>
            <dd>
              <template v-if="tls[p.key].expiresAt">
                <span class="whitespace-nowrap">{{ formatDate(tls[p.key].expiresAt) }}</span>
                <StatusBadge class="ml-1" :tone="dayTone(daysOf(tls[p.key].expiresAt)!)" :label="remaining(daysOf(tls[p.key].expiresAt)!)" />
              </template>
              <span v-else class="text-ink-3">—</span>
            </dd>
            <template v-if="p.key === 'agent'">
              <dt>신뢰 앵커 SPKI 해시</dt>
              <dd class="min-w-0"><CopyField v-if="tls.anchorSpkiHash" :value="tls.anchorSpkiHash" label="SPKI 해시" /><span v-else>—</span></dd>
              <template v-if="tls.agent.clientSubject">
                <dt>클라이언트 인증서 주체</dt>
                <dd class="mono break-all">{{ tls.agent.clientSubject }}</dd>
              </template>
              <template v-if="tls.agent.clientExpiresAt">
                <dt>클라이언트 인증서 만료</dt>
                <dd>
                  <span class="whitespace-nowrap">{{ formatDate(tls.agent.clientExpiresAt) }}</span>
                  <StatusBadge class="ml-1" :tone="dayTone(daysUntil(tls.agent.clientExpiresAt))" :label="remaining(daysUntil(tls.agent.clientExpiresAt))" />
                </dd>
              </template>
              <dt>Agent CA 만료</dt>
              <dd>
                <span class="whitespace-nowrap">{{ formatDate(tls.agentCaExpiresAt) }}</span>
                <StatusBadge class="ml-1" :tone="dayTone(daysUntil(tls.agentCaExpiresAt))" :label="remaining(daysUntil(tls.agentCaExpiresAt))" />
              </dd>
              <dt>신뢰 번들 미동기화</dt>
              <dd class="mono">{{ tls.unsyncedAgents }}</dd>
            </template>
          </dl>

          <p v-if="(daysOf(tls[p.key].expiresAt) ?? 31) <= 30" class="note note-warn mt-3">
            {{ daysOf(tls[p.key].expiresAt)! < 0 ? '인증서가 만료되었습니다.' : `인증서가 ${daysOf(tls[p.key].expiresAt)}일 안에 만료됩니다.` }}
          </p>

          <template v-if="p.key === 'agent'">
            <p v-if="tls.unsyncedAgents > 0" class="note note-warn mt-3">
              신뢰 번들을 받아가지 않은 Agent가 {{ tls.unsyncedAgents }}개 있습니다.
            </p>

            <div class="mt-4 border-t border-line pt-3">
              <div class="flex flex-wrap items-center justify-between gap-2">
                <h3 class="text-sm font-semibold">신뢰 앵커 교체</h3>
                <AppButton size="sm" @click="openAnchor">{{ pendingAnchor ? '전환' : '새 앵커 준비' }}</AppButton>
              </div>
              <dl v-if="pendingAnchor" class="kv mt-2">
                <dt>새 앵커 SPKI 해시</dt>
                <dd class="min-w-0"><CopyField :value="pendingAnchor.spkiHash" label="새 앵커 SPKI 해시" /></dd>
                <dt>주체</dt>
                <dd class="mono break-all">{{ pendingAnchor.subject || '—' }}</dd>
                <dt>만료</dt>
                <dd class="whitespace-nowrap">{{ formatDate(pendingAnchor.expiresAt) }}</dd>
                <dt>준비 시각</dt>
                <dd>{{ formatDateTime(pendingAnchor.preparedAt) }} <TimeAgo :at="pendingAnchor.preparedAt" class="text-ink-3" /></dd>
                <dt>미동기화 Agent</dt>
                <dd class="mono" :class="pendingAnchor.unsyncedAgents > 0 ? 'text-high' : ''">{{ pendingAnchor.unsyncedAgents }}</dd>
              </dl>
            </div>
          </template>
        </template>
      </Panel>

      <AppModal v-model:open="autoOpen" :title="`${titleOf(autoKey)} 자동으로 전환`">
        <p class="text-sm">{{ titleOf(autoKey) }}을 자동으로 전환합니다.</p>
        <p v-if="autoError" class="note note-danger mt-3" role="alert">{{ autoError }}</p>
        <template #footer>
          <AppButton @click="autoOpen = false">취소</AppButton>
          <AppButton variant="primary" :disabled="autoBusy" @click="switchToAuto">전환</AppButton>
        </template>
      </AppModal>

      <AppModal v-model:open="manualOpen" :title="`${titleOf(manualKey)} 수동 인증서`" wide>
        <form id="manual-tls-form" class="grid grid-cols-1 gap-3" @submit.prevent="applyManual">
          <FormField label="인증서 체인" hint="PEM, leaf부터">
            <textarea v-model="manual.certificateChain" rows="5" class="input mono w-full" spellcheck="false" />
          </FormField>
          <input type="file" class="input w-full" aria-label="인증서 체인 파일" @change="readManual($event, 'certificateChain')" />
          <FormField label="키" hint="PEM">
            <textarea v-model="manual.privateKey" rows="4" class="input mono w-full" spellcheck="false" autocomplete="off" />
          </FormField>
          <input type="file" class="input w-full" aria-label="키 파일" @change="readManual($event, 'privateKey')" />
          <template v-if="manualKey === 'agent'">
            <FormField label="클라이언트 인증서 체인" hint="PEM, leaf부터. 비우면 위 인증서를 listen 접속에도 씁니다">
              <textarea v-model="manual.clientCertificateChain" rows="4" class="input mono w-full" spellcheck="false" />
            </FormField>
            <input type="file" class="input w-full" aria-label="클라이언트 인증서 체인 파일" @change="readManual($event, 'clientCertificateChain')" />
            <FormField label="클라이언트 키" hint="PEM">
              <textarea v-model="manual.clientPrivateKey" rows="4" class="input mono w-full" spellcheck="false" autocomplete="off" />
            </FormField>
            <input type="file" class="input w-full" aria-label="클라이언트 키 파일" @change="readManual($event, 'clientPrivateKey')" />
          </template>
          <p v-if="manualError" class="note note-danger" role="alert">{{ manualError }}</p>
        </form>
        <template #footer>
          <AppButton @click="manualOpen = false">취소</AppButton>
          <AppButton type="submit" form="manual-tls-form" variant="primary" :disabled="!manualValid || manualBusy">적용</AppButton>
        </template>
      </AppModal>

      <AppModal v-model:open="anchorOpen" title="신뢰 앵커 교체" wide>
        <template v-if="!pendingAnchor">
          <p v-if="tls.agent.mode !== 'manual'" class="text-sm">새 내부 CA를 만들어 신뢰 번들에 추가합니다.</p>
          <template v-else>
            <FormField label="새 앵커 인증서" hint="PEM">
              <textarea v-model="anchorCert" rows="5" class="input mono w-full" spellcheck="false" />
            </FormField>
            <input
              type="file"
              class="input mt-3 w-full"
              aria-label="새 앵커 인증서 파일"
              @change="readPem($event, (text) => (anchorCert = text), (message) => (anchorError = message))"
            />
          </template>
        </template>

        <template v-else>
          <dl class="kv">
            <dt>새 앵커 SPKI 해시</dt>
            <dd class="mono break-all">{{ pendingAnchor.spkiHash }}</dd>
            <dt>미동기화 Agent</dt>
            <dd class="mono">{{ pendingAnchor.unsyncedAgents }}</dd>
          </dl>
          <p class="note note-warn mt-3">전환하면 이전에 만든 등록 문자열을 쓸 수 없습니다.</p>
          <template v-if="unsynced > 0">
            <p class="note note-danger mt-3">신뢰 번들을 받아가지 않은 Agent {{ unsynced }}개는 전환 후 접속이 끊깁니다.</p>
            <label class="mt-3 inline-flex items-center gap-1.5 text-sm">
              <input v-model="anchorForce" type="checkbox" class="accent-(--accent)" /> Agent {{ unsynced }}개의 접속이 끊기는 것을 확인했습니다
            </label>
          </template>
        </template>

        <p v-if="anchorError" class="note note-danger mt-3" role="alert">{{ anchorError }}</p>

        <template #footer>
          <AppButton @click="anchorOpen = false">닫기</AppButton>
          <template v-if="!pendingAnchor">
            <AppButton variant="primary" :disabled="!prepareValid || anchorBusy" @click="anchorStep('prepare')">준비</AppButton>
          </template>
          <template v-else>
            <AppButton variant="danger" :disabled="anchorBusy" @click="anchorStep('cancel')">준비 취소</AppButton>
            <AppButton variant="primary" :disabled="anchorBusy || (unsynced > 0 && !anchorForce)" @click="anchorStep('activate')">전환</AppButton>
          </template>
        </template>
      </AppModal>
    </div>
  </div>
</template>
