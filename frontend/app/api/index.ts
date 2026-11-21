// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Admin API calls for pages. Every function resolves to the response body or throws ApiError.
// List functions return one page ({ items, total }); wrap them in fetchAll() to get every item.

import * as sdk from './gen/sdk.gen'
import type * as gen from './gen/types.gen'
import type {
  AgentAnchorChange,
  CredentialCreate,
  K8sClusterCreate,
  K8sClusterUpdate,
  CredentialSecretUpdate,
  ListenTargetCreate,
  ListenTargetUpdate,
  LoginRequest,
  RegisterKeyCreate,
  ScanTargetCreate,
  ScanTargetUpdate,
  TlsEndpointName,
  TlsEndpointUpdate,
  UpdateSettings,
} from '~/types'
import { call } from './client'

export { ApiError, fetchAll, optional, toApiError, type Page } from './client'

type Query<T extends { query?: unknown }> = NonNullable<T['query']>

// ── meta / auth / dashboard ─────────────────────────────

export const getMeta = () => call(sdk.getMeta())
// Wrong credentials are a 401 the login page shows; they must not redirect.
export const login = (body: LoginRequest) => call(sdk.login({ body }), { redirect: false })
export const logout = async () => {
  await call(sdk.logout(), { redirect: false })
}
export const getCurrentUser = () => call(sdk.getCurrentUser(), { redirect: false })
export const getDashboard = () => call(sdk.getDashboard())

// ── assets ──────────────────────────────────────────────

export const listAssets = (query?: Query<gen.ListAssetsData>) => call(sdk.listAssets({ query }))
export const listAssetGroups = (query?: Query<gen.ListAssetGroupsData>) => call(sdk.listAssetGroups({ query }))
export const getAsset = (id: string) => call(sdk.getAsset({ path: { id } }))
export const listAssetComponents = (id: string, query?: Query<gen.ListAssetComponentsData>) =>
  call(sdk.listAssetComponents({ path: { id }, query }))
export const listAssetProcesses = (id: string, query?: Query<gen.ListAssetProcessesData>) =>
  call(sdk.listAssetProcesses({ path: { id }, query }))
export const listAssetInstances = (id: string, query?: Query<gen.ListAssetInstancesData>) =>
  call(sdk.listAssetInstances({ path: { id }, query }))
export const collectAsset = (id: string) => call(sdk.collectAsset({ path: { id } }))

// ── components ──────────────────────────────────────────

export const listComponents = (query?: Query<gen.ListComponentsData>) => call(sdk.listComponents({ query }))
export const getComponent = (id: string) => call(sdk.getComponent({ path: { id } }))
export const listComponentAssets = (id: string, query?: Query<gen.ListComponentAssetsData>) =>
  call(sdk.listComponentAssets({ path: { id }, query }))

// ── processes ───────────────────────────────────────────

export const listProcesses = (query?: Query<gen.ListProcessesData>) => call(sdk.listProcesses({ query }))
export const listListenPorts = (query?: Query<gen.ListListenPortsData>) => call(sdk.listListenPorts({ query }))

// ── images ──────────────────────────────────────────────

export const listImages = (query?: Query<gen.ListImagesData>) => call(sdk.listImages({ query }))
export const getImage = (digest: string) => call(sdk.getImage({ path: { digest } }))

// ── kubernetes ──────────────────────────────────────────

export const listK8sClusters = (query?: Query<gen.ListK8sClustersData>) => call(sdk.listK8sClusters({ query }))
export const createK8sCluster = (body: K8sClusterCreate) => call(sdk.createK8sCluster({ body }))
export const getK8sCluster = (id: string) => call(sdk.getK8sCluster({ path: { id } }))
export const updateK8sCluster = (id: string, body: K8sClusterUpdate) => call(sdk.updateK8sCluster({ path: { id }, body }))
export const deleteK8sCluster = async (id: string) => {
  await call(sdk.deleteK8sCluster({ path: { id } }))
}
export const listK8sWorkloads = (clusterId: string, query?: Query<gen.ListK8sWorkloadsData>) =>
  call(sdk.listK8sWorkloads({ path: { id: clusterId }, query }))
export const listK8sWorkloadPods = (workloadId: string, query?: Query<gen.ListK8sWorkloadPodsData>) =>
  call(sdk.listK8sWorkloadPods({ path: { id: workloadId }, query }))
export const syncK8sCluster = async (id: string) => {
  await call(sdk.syncK8sCluster({ path: { id } }))
}

// ── agents ──────────────────────────────────────────────

export const listAgents = (query?: Query<gen.ListAgentsData>) => call(sdk.listAgents({ query }))
export const getAgent = (id: string) => call(sdk.getAgent({ path: { id } }))
export const approveAgent = (id: string) => call(sdk.approveAgent({ path: { id } }))
export const revokeAgent = (id: string) => call(sdk.revokeAgent({ path: { id } }))
export const listListenTargets = (query?: Query<gen.ListListenTargetsData>) => call(sdk.listListenTargets({ query }))
export const createListenTarget = (body: ListenTargetCreate) => call(sdk.createListenTarget({ body }))
export const updateListenTarget = (id: string, body: ListenTargetUpdate) =>
  call(sdk.updateListenTarget({ path: { id }, body }))
export const deleteListenTarget = async (id: string) => {
  await call(sdk.deleteListenTarget({ path: { id } }))
}

// ── enrollment ──────────────────────────────────────────

export const listRegisterKeys = (query?: Query<gen.ListRegisterKeysData>) => call(sdk.listRegisterKeys({ query }))
/** The enrollment string in the result is returned only once. */
export const createRegisterKey = (body: RegisterKeyCreate) => call(sdk.createRegisterKey({ body }))
export const getRegisterKey = (id: string) => call(sdk.getRegisterKey({ path: { id } }))
export const revokeRegisterKey = (id: string) => call(sdk.revokeRegisterKey({ path: { id } }))

// ── updates ─────────────────────────────────────────────

export const listReleases = (query?: Query<gen.ListReleasesData>) => call(sdk.listReleases({ query }))
export const uploadRelease = (bundle: Blob) => call(sdk.uploadRelease({ body: { bundle } }))
export const getUpdateSettings = () => call(sdk.getUpdateSettings())
export const setUpdateSettings = (body: UpdateSettings) => call(sdk.setUpdateSettings({ body }))

// ── scans ───────────────────────────────────────────────

export const listScanTargets = (query?: Query<gen.ListScanTargetsData>) => call(sdk.listScanTargets({ query }))
export const createScanTarget = (body: ScanTargetCreate) => call(sdk.createScanTarget({ body }))
export const updateScanTarget = (id: string, body: ScanTargetUpdate) =>
  call(sdk.updateScanTarget({ path: { id }, body }))
export const deleteScanTarget = async (id: string) => {
  await call(sdk.deleteScanTarget({ path: { id } }))
}
export const runScanTarget = async (id: string) => {
  await call(sdk.runScanTarget({ path: { id } }))
}
export const listCredentials = (query?: Query<gen.ListCredentialsData>) => call(sdk.listCredentials({ query }))
export const createCredential = (body: CredentialCreate) => call(sdk.createCredential({ body }))
export const rotateCredentialSecret = (id: string, body: CredentialSecretUpdate) =>
  call(sdk.rotateCredentialSecret({ path: { id }, body }))
export const deleteCredential = async (id: string) => {
  await call(sdk.deleteCredential({ path: { id } }))
}

// ── settings ────────────────────────────────────────────

export const getTlsSettings = () => call(sdk.getTlsSettings())
export const updateTlsEndpoint = (endpoint: TlsEndpointName, body: TlsEndpointUpdate) =>
  call(sdk.updateTlsEndpoint({ path: { endpoint }, body }))
export const changeAgentTlsAnchor = (body: AgentAnchorChange) => call(sdk.changeAgentTlsAnchor({ body }))
