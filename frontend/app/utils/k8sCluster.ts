// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

import type { K8sCluster, K8sClusterCreate, K8sClusterUpdate, K8sConnection, K8sFilter, K8sSyncStatus } from '~/types'
import type { Tone } from '~/utils/labels'

export const k8sSyncStatusLabel: Record<K8sSyncStatus, string> = { never: '없음', ok: '정상', failed: '실패' }
export const k8sSyncStatusTone: Record<K8sSyncStatus, Tone> = { never: 'neutral', ok: 'ok', failed: 'danger' }

/** Editable fields of a cluster. Filter lists are text with one pattern per line. */
export interface K8sClusterForm {
  name: string
  connection: K8sConnection
  credentialId: string
  /** '' is the embedded scanner (kubeconfig only) */
  scannerId: string
  execEnabled: boolean
  filter: Record<keyof K8sFilter, string>
}

const filterKeys: (keyof K8sFilter)[] = ['nsInclude', 'nsExclude', 'labelInclude', 'labelExclude', 'annotationInclude', 'annotationExclude']

export function k8sClusterForm(cluster?: K8sCluster): K8sClusterForm {
  const filter = Object.fromEntries(filterKeys.map((k) => [k, (cluster?.filter[k] ?? []).join('\n')])) as K8sClusterForm['filter']
  return {
    name: cluster?.name ?? '',
    connection: cluster?.connection ?? 'kubeconfig',
    credentialId: cluster?.credentialId ?? '',
    scannerId: cluster?.scannerId ?? '',
    execEnabled: cluster?.execEnabled ?? false,
    filter,
  }
}

export const k8sClusterFormValid = (f: K8sClusterForm) =>
  !!f.name.trim() && (f.connection === 'kubeconfig' ? !!f.credentialId : !!f.scannerId)

/** Request body for create. */
export function k8sClusterBody(f: K8sClusterForm): K8sClusterCreate {
  const lines = (s: string) => s.split('\n').map((l) => l.trim()).filter(Boolean)
  return {
    name: f.name.trim(),
    connection: f.connection,
    credentialId: f.connection === 'kubeconfig' ? f.credentialId : undefined,
    scannerId: f.scannerId || undefined,
    execEnabled: f.execEnabled,
    filter: Object.fromEntries(filterKeys.map((k) => [k, lines(f.filter[k])])) as unknown as K8sFilter,
  }
}

/** Request body for update: every field is sent, and `null` clears the credential or assigns the embedded scanner. */
export function k8sClusterUpdateBody(f: K8sClusterForm): K8sClusterUpdate {
  return {
    ...k8sClusterBody(f),
    credentialId: f.connection === 'kubeconfig' ? f.credentialId : null,
    scannerId: f.scannerId || null,
  }
}
