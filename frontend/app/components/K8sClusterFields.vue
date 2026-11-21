<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { Agent, Credential } from '~/types'
import type { K8sClusterForm } from '~/utils/k8sCluster'

// Fields of the cluster create / edit modals. The parent owns the form object and the submit button.
const form = defineModel<K8sClusterForm>({ required: true })
const props = defineProps<{ credentials: Credential[]; agents: Agent[] }>()

const kubeconfigs = computed(() => props.credentials.filter((c) => c.kind === 'kubeconfig'))
const scanners = computed(() => props.agents.filter((a) => a.kind === 'scanner' && a.status !== 'revoked'))

const filterFields: { label: string; include: keyof K8sClusterForm['filter']; exclude: keyof K8sClusterForm['filter']; placeholder: string }[] = [
  { label: 'namespace', include: 'nsInclude', exclude: 'nsExclude', placeholder: 'kube-*' },
  { label: 'label', include: 'labelInclude', exclude: 'labelExclude', placeholder: 'app=web' },
  { label: 'annotation', include: 'annotationInclude', exclude: 'annotationExclude', placeholder: 'bomcensus/skip' },
]
</script>

<template>
  <div class="grid grid-cols-1 gap-3">
    <FormField label="이름"><input v-model="form.name" class="input w-full" /></FormField>
    <FormField label="연결 방식">
      <select v-model="form.connection" class="select w-full">
        <option value="kubeconfig">kubeconfig</option>
        <option value="in_cluster">in-cluster</option>
      </select>
    </FormField>
    <template v-if="form.connection === 'kubeconfig'">
      <FormField label="kubeconfig 자격증명" :hint="kubeconfigs.length ? undefined : 'kubeconfig 자격증명이 없습니다'">
        <select v-model="form.credentialId" class="select w-full">
          <option value="" disabled>선택</option>
          <option v-for="c in kubeconfigs" :key="c.id" :value="c.id">{{ c.name }}</option>
        </select>
      </FormField>
      <FormField label="Scanner">
        <select v-model="form.scannerId" class="select w-full">
          <option value="">내장 Scanner</option>
          <option v-for="s in scanners" :key="s.id" :value="s.id">{{ s.hostname }}</option>
        </select>
      </FormField>
    </template>
    <FormField v-else label="Scanner" hint="클러스터 안에 배포된 Scanner">
      <select v-model="form.scannerId" class="select w-full">
        <option value="" disabled>선택</option>
        <option v-for="s in scanners" :key="s.id" :value="s.id">{{ s.hostname }}</option>
      </select>
    </FormField>
    <label class="inline-flex items-center gap-1.5 text-sm">
      <input v-model="form.execEnabled" type="checkbox" class="accent-(--accent)" /> exec 수집 사용
    </label>
    <p v-if="!form.execEnabled" class="note note-warn">exec 수집을 쓰지 않으면 이미지 인벤토리만 수집합니다.</p>

    <h3 class="mt-1 text-xs font-medium text-ink-2">수집 필터 <span class="font-normal text-ink-3">(줄마다 하나, exclude 우선)</span></h3>
    <div v-for="f in filterFields" :key="f.label" class="grid grid-cols-1 gap-3 sm:grid-cols-2">
      <FormField :label="`${f.label} include`">
        <textarea v-model="form.filter[f.include]" rows="2" class="input mono w-full" :placeholder="f.placeholder" spellcheck="false" />
      </FormField>
      <FormField :label="`${f.label} exclude`">
        <textarea v-model="form.filter[f.exclude]" rows="2" class="input mono w-full" spellcheck="false" />
      </FormField>
    </div>
  </div>
</template>
