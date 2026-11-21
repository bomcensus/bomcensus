// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

import type { AssetSummary } from '~/types'

/** "cluster / namespace" for a workload, the address for a host */
export function assetLocation(asset: Pick<AssetSummary, 'kind' | 'address' | 'clusterName' | 'namespace'>): string | undefined {
  if (asset.kind !== 'workload') return asset.address
  return [asset.clusterName, asset.namespace].filter(Boolean).join(' / ') || undefined
}

/** "name version", or the name alone when it already contains the version */
export function osLabel(os: { name: string; version?: string } | undefined): string | undefined {
  if (!os) return undefined
  const version = os.version?.trim()
  if (!version || os.name.includes(version)) return os.name
  return `${os.name} ${version}`
}
