// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Admin API calls for pages. Every function resolves to the response body or throws ApiError.
// List functions return one page ({ items, total }); wrap them in fetchAll() to get every item.

import * as sdk from './gen/sdk.gen'
import type * as gen from './gen/types.gen'
import type {
  AgentAnchorChange,
  AgentUpdate,
  CredentialCreate,
  K8sClusterCreate,
  K8sClusterUpdate,
  CredentialSecretUpdate,
  DetectDirCreate,
  DetectDirUpdate,
  FeedServerCreate,
  FeedServerUpdate,
  TriageRuleCreate,
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
export const listComponentVulnerabilities = (id: string) => call(sdk.listComponentVulnerabilities({ path: { id } }))

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
export const updateAgent = (id: string, body: AgentUpdate) => call(sdk.updateAgent({ path: { id }, body }))
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

// ── detection ───────────────────────────────────────────

export const listDetectDirs = () => call(sdk.listDetectDirs())
export const createDetectDir = (body: DetectDirCreate) => call(sdk.createDetectDir({ body }))
export const updateDetectDir = (id: string, body: DetectDirUpdate) => call(sdk.updateDetectDir({ path: { id }, body }))
export const deleteDetectDir = async (id: string) => {
  await call(sdk.deleteDetectDir({ path: { id } }))
}

// ── settings ────────────────────────────────────────────

export const getTlsSettings = () => call(sdk.getTlsSettings())
export const updateTlsEndpoint = (endpoint: TlsEndpointName, body: TlsEndpointUpdate) =>
  call(sdk.updateTlsEndpoint({ path: { endpoint }, body }))
export const changeAgentTlsAnchor = (body: AgentAnchorChange) => call(sdk.changeAgentTlsAnchor({ body }))

// ── feed ────────────────────────────────────────────────

export const getFeedInstance = () => call(sdk.getFeedInstance())
export const listFeedServers = () => call(sdk.listFeedServers())
export const createFeedServer = (body: FeedServerCreate) => call(sdk.createFeedServer({ body }))
export const updateFeedServer = (id: string, body: FeedServerUpdate) => call(sdk.updateFeedServer({ path: { id }, body }))
export const deleteFeedServer = async (id: string) => {
  await call(sdk.deleteFeedServer({ path: { id } }))
}
/** Contacts the server; the outcome is in the returned server's status and lastError. */
export const testFeedServer = (id: string) => call(sdk.testFeedServer({ path: { id } }))
export const trustFeedServerKey = (id: string, key: string) => call(sdk.trustFeedServerKey({ path: { id }, body: { key } }))
/** Queues matching every component against the active server again. */
export const rematchFeedServer = async (id: string) => {
  await call(sdk.rematchFeedServer({ path: { id } }))
}

// ── vulnerabilities ─────────────────────────────────────

export const getVulnerabilitySummary = () => call(sdk.getVulnerabilitySummary())
export const listVulnerableComponents = (query?: Query<gen.ListVulnerableComponentsData>) =>
  call(sdk.listVulnerableComponents({ query }))
export const getVulnerableComponent = (id: string) => call(sdk.getVulnerableComponent({ path: { id } }))
export const listVulnerabilities = (query?: Query<gen.ListVulnerabilitiesData>) => call(sdk.listVulnerabilities({ query }))
export const getVulnerability = (vulnId: string) => call(sdk.getVulnerability({ path: { vulnId } }))
export const listAssetVulnerabilities = (id: string) => call(sdk.listAssetVulnerabilities({ path: { id } }))
export const listVulnerableProcesses = (query?: Query<gen.ListVulnerableProcessesData>) =>
  call(sdk.listVulnerableProcesses({ query }))
export const getVulnerableProcess = (exe: string) => call(sdk.getVulnerableProcess({ query: { exe } }))
export const listVulnerableImages = (query?: Query<gen.ListVulnerableImagesData>) => call(sdk.listVulnerableImages({ query }))
export const getVulnerableImage = (digest: string) => call(sdk.getVulnerableImage({ path: { digest } }))

// ── triage ──────────────────────────────────────────────

export const listTriageRules = (query?: Query<gen.ListTriageRulesData>) => call(sdk.listTriageRules({ query }))
export const createTriageRule = (body: TriageRuleCreate) => call(sdk.createTriageRule({ body }))
export const revokeTriageRule = (id: string) => call(sdk.revokeTriageRule({ path: { id } }))
/** The active rules as an OpenVEX document. */
export const exportVex = () => call(sdk.exportVex())
