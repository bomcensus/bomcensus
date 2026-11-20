// 목업 데이터 조회 계층. 페이지는 data/ 를 직접 import 하지 않고 여기 함수만 쓴다.
// 서버 API가 생기면 이 파일의 함수를 생성된 클라이언트 호출로 바꾼다.

import type {
  Agent,
  Asset,
  AssetComponent,
  AssetContainer,
  SoftwareComponent,
  ComponentVuln,
  ContainerImage,
  Finding,
  K8sPod,
  K8sWorkload,
  ProcessInfo,
  Severity,
  SeverityCounts,
  Vulnerability,
} from '~/types'
import { assets } from './data/assets'
import { assetComponents, components } from './data/components'
import { componentVulns, findings, vulnerabilities } from './data/vulnerabilities'
import { processes } from './data/processes'
import { clusters, images, pods, workloads } from './data/containers'
import { agents, registerKeys, releases, updateSettings } from './data/agents'
import { credentials, scanTargets } from './data/scans'
import { feeds, tlsState } from './data/settings'

export {
  assets,
  components,
  assetComponents,
  vulnerabilities,
  componentVulns,
  findings,
  processes,
  images,
  clusters,
  workloads,
  pods,
  agents,
  registerKeys,
  releases,
  updateSettings,
  scanTargets,
  credentials,
  feeds,
  tlsState,
}

// 목업의 기준 시각. 상대 시간 표시는 모두 이 값을 기준으로 한다.
export const MOCK_NOW = '2026-11-20T09:00:00+09:00'

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low']
const severityRank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 }
export const compareSeverity = (a: Severity, b: Severity) => severityRank[a] - severityRank[b]

function index<T>(list: T[], key: (item: T) => string): Map<string, T> {
  return new Map(list.map((item) => [key(item), item]))
}

const assetById = index(assets, (a) => a.id)
const componentById = index(components, (c) => c.id)
const vulnById = index(vulnerabilities, (v) => v.id)
const agentById = index(agents, (a) => a.id)
const imageByDigest = index(images, (i) => i.digest)

export const getAsset = (id: string): Asset | undefined => assetById.get(id)
export const getComponent = (id: string): SoftwareComponent | undefined => componentById.get(id)
export const getVuln = (id: string): Vulnerability | undefined => vulnById.get(id)
export const getAgent = (id: string): Agent | undefined => agentById.get(id)
export const getImage = (digest: string): ContainerImage | undefined => imageByDigest.get(digest)
export const getCluster = (id: string) => clusters.find((c) => c.id === id)
export const getRegisterKey = (id: string) => registerKeys.find((k) => k.id === id)
export const getCredential = (id: string) => credentials.find((c) => c.id === id)

// ── 컴포넌트 ─────────────────────────────────────────

export interface AssetComponentRow extends AssetComponent {
  component: SoftwareComponent
}

/** 자산에 현재 설치된 컴포넌트 (제거된 것은 제외) */
export function componentsOfAsset(assetId: string): AssetComponentRow[] {
  return assetComponents
    .filter((ac) => ac.assetId === assetId && !ac.removedAt)
    .flatMap((ac) => {
      const component = componentById.get(ac.componentId)
      return component ? [{ ...ac, component }] : []
    })
}

export interface ComponentAssetRow extends AssetComponent {
  asset: Asset
}

/** 컴포넌트가 설치된 자산 */
export function assetsOfComponent(componentId: string): ComponentAssetRow[] {
  return assetComponents
    .filter((ac) => ac.componentId === componentId && !ac.removedAt)
    .flatMap((ac) => {
      const asset = assetById.get(ac.assetId)
      return asset ? [{ ...ac, asset }] : []
    })
}

export interface ComponentVulnRow extends ComponentVuln {
  vuln: Vulnerability
}

export function vulnsOfComponent(componentId: string): ComponentVulnRow[] {
  return componentVulns
    .filter((cv) => cv.componentId === componentId)
    .flatMap((cv) => {
      const vuln = vulnById.get(cv.vulnId)
      return vuln ? [{ ...cv, vuln }] : []
    })
    .sort((a, b) => compareSeverity(a.vuln.severity, b.vuln.severity))
}

export function componentsOfVuln(vulnId: string): (ComponentVuln & { component: SoftwareComponent })[] {
  return componentVulns
    .filter((cv) => cv.vulnId === vulnId)
    .flatMap((cv) => {
      const component = componentById.get(cv.componentId)
      return component ? [{ ...cv, component }] : []
    })
}

// ── Finding ──────────────────────────────────────────

export interface FindingRow extends Finding {
  asset: Asset
  component: SoftwareComponent
  vuln: Vulnerability
  match?: ComponentVuln
}

function toFindingRow(f: Finding): FindingRow[] {
  const asset = assetById.get(f.assetId)
  const component = componentById.get(f.componentId)
  const vuln = vulnById.get(f.vulnId)
  if (!asset || !component || !vuln) return []
  const match = componentVulns.find((cv) => cv.componentId === f.componentId && cv.vulnId === f.vulnId)
  return [{ ...f, asset, component, vuln, match }]
}

const bySeverity = (a: FindingRow, b: FindingRow) => compareSeverity(a.vuln.severity, b.vuln.severity)

export const allFindingRows = (): FindingRow[] => findings.flatMap(toFindingRow).sort(bySeverity)
export const findingsOfAsset = (assetId: string): FindingRow[] =>
  findings.filter((f) => f.assetId === assetId).flatMap(toFindingRow).sort(bySeverity)
export const findingsOfVuln = (vulnId: string): FindingRow[] =>
  findings.filter((f) => f.vulnId === vulnId).flatMap(toFindingRow)
export const findingsOfComponent = (componentId: string): FindingRow[] =>
  findings.filter((f) => f.componentId === componentId).flatMap(toFindingRow).sort(bySeverity)

/** 조치가 필요한 상태인지 (open, restart_required) */
export const isActive = (f: Pick<Finding, 'status'>) => f.status === 'open' || f.status === 'restart_required'

export function emptyCounts(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0 }
}

/** 조치가 필요한 finding만 심각도별로 센다. 같은 자산의 같은 취약점은 한 번만 센다. */
export function countBySeverity(rows: { status: Finding['status']; assetId: string; vulnId: string }[]): SeverityCounts {
  const counts = emptyCounts()
  const seen = new Set<string>()
  for (const row of rows) {
    if (!isActive(row)) continue
    const key = `${row.assetId}|${row.vulnId}`
    if (seen.has(key)) continue
    seen.add(key)
    const vuln = vulnById.get(row.vulnId)
    if (vuln) counts[vuln.severity]++
  }
  return counts
}

export const severityCountsOfAsset = (assetId: string) => countBySeverity(findings.filter((f) => f.assetId === assetId))
export const severityCountsOfComponent = (componentId: string) =>
  countBySeverity(findings.filter((f) => f.componentId === componentId))
export const totalOf = (c: SeverityCounts) => c.critical + c.high + c.medium + c.low

/** 취약점의 영향을 받는(조치 필요) 자산 수 */
export function affectedAssetCount(vulnId: string): number {
  return new Set(findings.filter((f) => f.vulnId === vulnId && isActive(f)).map((f) => f.assetId)).size
}

// ── 프로세스 ─────────────────────────────────────────

export const processesOfAsset = (assetId: string): ProcessInfo[] => processes.filter((p) => p.assetId === assetId)

/** 구버전이 메모리에 남아 있어 재시작이 필요한 프로세스 */
export const needsRestart = (p: ProcessInfo) => p.exeState === 'replaced' || p.deletedLibs.some((l) => l.state === 'replaced')
/** 실행 파일이나 라이브러리가 삭제되었거나 파일 없이 실행된 프로세스 */
export const isSuspicious = (p: ProcessInfo) =>
  p.exeState === 'deleted' || p.exeState === 'memfd' || p.deletedLibs.some((l) => l.state === 'deleted')

// ── 컨테이너 / Kubernetes ────────────────────────────

/** 자산 안의 컨테이너를 이름으로 찾는다 */
export const getContainer = (assetId: string, name?: string): AssetContainer | undefined =>
  name ? assetById.get(assetId)?.containers.find((c) => c.name === name) : undefined

/** 컨테이너 하나에서 나온 조치 필요 취약점 건수 */
export const severityCountsOfContainer = (assetId: string, name: string) =>
  countBySeverity(findings.filter((f) => f.assetId === assetId && f.container === name))

/** 자산의 위치: 워크로드는 "클러스터 / 네임스페이스", 호스트는 주소 */
export function assetLocation(asset: Asset): string | undefined {
  if (asset.kind !== 'workload') return asset.address
  const cluster = clusters.find((c) => c.id === asset.clusterId)?.name
  return [cluster, asset.namespace].filter(Boolean).join(' / ') || undefined
}

export const workloadsOfCluster = (clusterId: string): K8sWorkload[] => workloads.filter((w) => w.clusterId === clusterId)
export const podsOfWorkload = (workloadId: string): K8sPod[] => pods.filter((p) => p.workloadId === workloadId)
/** 워크로드 자산에 대응하는 Kubernetes 워크로드 */
export const workloadOfAsset = (assetId: string): K8sWorkload | undefined => workloads.find((w) => w.assetId === assetId)
/** 워크로드 자산의 인스턴스(pod) */
export function podsOfAsset(assetId: string): K8sPod[] {
  const workload = workloadOfAsset(assetId)
  return workload ? podsOfWorkload(workload.id) : []
}

// ── 이미지 ───────────────────────────────────────────
// 이미지는 자산이 아니다. 아래 함수는 자산의 컨테이너를 이미지 다이제스트로 묶은 집계다.

export interface ImageUseRow {
  asset: Asset
  container: AssetContainer
}

/** 이 이미지로 도는 컨테이너 (호스트의 컨테이너와 워크로드의 컨테이너) */
export function containersOfImage(digest: string): ImageUseRow[] {
  return assets.flatMap((asset) =>
    asset.containers.filter((container) => container.imageDigest === digest).map((container) => ({ asset, container })),
  )
}

/** 이미지 사용처: 자산 수, 컨테이너 수, 떠 있는 인스턴스 수 */
export function imageUsage(digest: string): { assets: number; containers: number; instances: number } {
  const rows = containersOfImage(digest)
  return {
    assets: new Set(rows.map((r) => r.asset.id)).size,
    containers: rows.length,
    instances: rows.reduce((sum, r) => sum + r.container.instances, 0),
  }
}

/** 이미지에 포함된 컴포넌트에서 나온 finding. 그 이미지를 쓰는 모든 자산의 것을 모은다. 실행 중 추가된 컴포넌트는 뺀다. */
export function findingsOfImage(digest: string): FindingRow[] {
  return findings
    .filter((f) => {
      if (getContainer(f.assetId, f.container)?.imageDigest !== digest) return false
      const installed = assetComponents.find(
        (ac) => ac.assetId === f.assetId && ac.componentId === f.componentId && ac.container === f.container,
      )
      return installed?.layer !== 'runtime'
    })
    .flatMap(toFindingRow)
    .sort(bySeverity)
}

/** 이 이미지의 내용(이미지에 포함된 컴포넌트)을 수집한 적이 있는지. 없으면 취약점 유무를 알 수 없다. */
export function imageContentKnown(digest: string): boolean {
  return assetComponents.some(
    (ac) => ac.container !== undefined && ac.layer !== 'runtime' && getContainer(ac.assetId, ac.container)?.imageDigest === digest,
  )
}

/** 이미지의 조치 필요 취약점을 고유 취약점 기준으로 센다. 이미지를 고치면 한 번에 해소되는 단위다. */
export function severityCountsOfImage(digest: string): SeverityCounts {
  const counts = emptyCounts()
  const seen = new Set<string>()
  for (const f of findingsOfImage(digest)) {
    if (!isActive(f) || seen.has(f.vulnId)) continue
    seen.add(f.vulnId)
    counts[f.vuln.severity]++
  }
  return counts
}

// ── 에이전트 ─────────────────────────────────────────

export const agentsOfKey = (keyId: string): Agent[] => agents.filter((a) => a.registerKeyId === keyId)
export const agentOfAsset = (assetId: string): Agent | undefined => agents.find((a) => a.assetId === assetId)

export const assetGroups = (): string[] => [...new Set(assets.map((a) => a.group))].sort()
