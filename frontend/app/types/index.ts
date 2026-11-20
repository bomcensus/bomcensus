// 목업용 도메인 타입. 서버의 admin.yaml이 생기면 생성된 클라이언트 타입으로 바꾼다.

export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type SeverityCounts = Record<Severity, number>

// ── 자산 ─────────────────────────────────────────────

// 자산은 호스트와 워크로드 둘뿐이다. 컨테이너는 자산의 하위 항목이고, 이미지는 자산이 아니다.
export type AssetKind = 'host' | 'workload'
export type CollectMethod = 'agent' | 'ssh' | 'winrm' | 'k8s_exec' | 'k8s_inventory'
export type Coverage = 'full' | 'partial' | 'process_only' | 'inventory_only' | 'unsupported' | 'failed'
export type PrivilegeLevel = 'privileged' | 'non_root'
export type SectionName = 'host' | 'packages' | 'artifacts' | 'processes' | 'containers'

export interface SectionCoverage {
  section: SectionName
  coverage: 'full' | 'partial' | 'none'
  reason?: string
  collectedAt?: string
}

export type ContainerRuntime = 'kubernetes' | 'docker' | 'containerd'

// 자산 안의 컨테이너. 워크로드는 pod 템플릿의 컨테이너, 호스트는 그 호스트에서 도는 컨테이너.
// 이름이 자산 안에서의 식별자다. 배포로 다이제스트가 바뀌어도 같은 컨테이너다.
export interface AssetContainer {
  name: string
  imageRef: string
  imageDigest: string
  runtime: ContainerRuntime
  // 떠 있는 인스턴스 수. 워크로드는 pod 수, 호스트의 컨테이너는 1(실행 중) 또는 0(종료)
  instances: number
  coverage: Coverage
  coverageReason?: string
  startedAt?: string
}

export interface Asset {
  id: string
  name: string
  kind: AssetKind
  group: string
  tags: string[]
  os?: { family: 'linux' | 'windows'; name: string; version: string; kernel?: string; arch: string }
  address?: string
  method: CollectMethod
  coverage: Coverage
  coverageReason?: string
  privilege?: PrivilegeLevel
  sections: SectionCoverage[]
  agentId?: string
  clusterId?: string
  namespace?: string
  workloadKind?: string
  containers: AssetContainer[]
  firstSeen: string
  lastSeen: string
}

// ── 컴포넌트 ─────────────────────────────────────────

export type ComponentType = 'deb' | 'rpm' | 'apk' | 'maven' | 'golang' | 'binary' | 'windows' | 'middleware'
// distro: 배포판 패키지(배포판 권고로 판정) / third_party: 서드파티 저장소 패키지 / upstream: 패키지가 아닌 소프트웨어
export type ComponentOrigin = 'distro' | 'third_party' | 'upstream'
export type DetectMethod = 'package_db' | 'exec' | 'static' | 'manifest' | 'buildinfo'

export interface SoftwareComponent {
  id: string
  type: ComponentType
  name: string
  version: string
  purl: string
  cpe?: string
  sourceName?: string
  sourceVersion?: string
  distro?: string
  arch?: string
  vendor?: string
  origin: ComponentOrigin
}

// image: 이미지에 포함된 것(같은 다이제스트면 공유) / runtime: 컨테이너 실행 중에 추가·변경된 것
export type ComponentLayer = 'image' | 'runtime'

export interface AssetComponent {
  assetId: string
  componentId: string
  // 컨테이너 안에서 찾은 컴포넌트면 그 컨테이너 이름. 없으면 호스트 자체.
  container?: string
  layer?: ComponentLayer
  locations: string[]
  inUse: boolean
  method: DetectMethod
  versionCommand?: string
  versionRaw?: string
  firstSeen: string
  removedAt?: string
}

// ── 취약점 ───────────────────────────────────────────

export interface Vulnerability {
  id: string
  aliases: string[]
  title: string
  description: string
  severity: Severity
  cvss?: number
  epss?: number
  kev: boolean
  publishedAt: string
  modifiedAt: string
  sources: string[]
}

export type FixState = 'fixed_available' | 'not_fixed' | 'wont_fix'
export type MatchBasis = 'distro_advisory' | 'upstream_range' | 'msrc' | 'curated'

export interface ComponentVuln {
  componentId: string
  vulnId: string
  fixState: FixState
  fixedVersion?: string
  basis: MatchBasis
  advisoryId?: string
}

// restart_required: 패키지는 수정 버전이지만 구버전이 메모리에 남아 있음
export type FindingStatus = 'open' | 'restart_required' | 'accepted' | 'resolved'

export interface Finding {
  id: string
  assetId: string
  // 컨테이너 안의 컴포넌트에서 나온 것이면 그 컨테이너 이름
  container?: string
  componentId: string
  vulnId: string
  status: FindingStatus
  inUse: boolean
  exposed: boolean
  firstDetected: string
  resolvedAt?: string
  triageNote?: string
}

// ── 프로세스 ─────────────────────────────────────────

export type ExeState = 'normal' | 'replaced' | 'deleted' | 'memfd'

export interface ListenPort {
  proto: 'tcp' | 'udp'
  address: string
  port: number
}

export interface ProcessInfo {
  id: string
  assetId: string
  pid: number
  user: string
  exePath: string
  // cmdline: 권한이 없어 cmdline에서 추정한 경로
  exeSource: 'proc' | 'cmdline'
  sha256?: string
  cmdline: string
  startedAt: string
  exeState: ExeState
  deletedLibs: { path: string; state: 'replaced' | 'deleted' }[]
  listen: ListenPort[]
  // 컨테이너 안의 프로세스면 그 컨테이너 이름
  container?: string
  componentId?: string
}

// ── 컨테이너 / Kubernetes ────────────────────────────

export interface ContainerImage {
  digest: string
  repoTags: string[]
  os?: string
  arch: string
  sizeBytes: number
  firstSeen: string
}

export interface K8sFilter {
  nsInclude: string[]
  nsExclude: string[]
  labelInclude: string[]
  labelExclude: string[]
  annotationInclude: string[]
  annotationExclude: string[]
}

export interface K8sCluster {
  id: string
  name: string
  version: string
  scannerId: string
  connection: 'in_cluster' | 'kubeconfig'
  execEnabled: boolean
  filter: K8sFilter
  lastSync: string
}

export interface K8sWorkload {
  id: string
  clusterId: string
  namespace: string
  kind: 'Deployment' | 'StatefulSet' | 'DaemonSet' | 'CronJob' | 'Pod'
  name: string
  replicas: number
  assetId?: string
  excluded: boolean
  excludedBy?: string
}

export interface K8sPodContainer {
  name: string
  imageRef: string
  imageDigest: string
  coverage: Coverage
  coverageReason?: string
}

export interface K8sPod {
  id: string
  workloadId: string
  name: string
  node: string
  phase: 'Running' | 'Pending' | 'Succeeded' | 'Failed'
  containers: K8sPodContainer[]
}

// ── 에이전트 / 등록 / 업데이트 ───────────────────────

export type AgentStatus = 'online' | 'offline' | 'pending_approval' | 'revoked'
export type ConnMode = 'connect' | 'listen'
export type TlsMode = 'pinned' | 'system' | 'none'
export type UpdateState = 'up_to_date' | 'pending' | 'updating' | 'rolled_back'

export interface Agent {
  id: string
  kind: 'agent' | 'scanner'
  hostname: string
  assetId?: string
  version: string
  os: string
  arch: string
  status: AgentStatus
  connMode: ConnMode
  listenAddress?: string
  tlsMode: TlsMode
  // TLS가 중간에서 풀린 경우 관측된 발급자
  tlsInterceptedBy?: string
  privilege: PrivilegeLevel
  execHelper: boolean
  registerKeyId: string
  address: string
  certExpiresAt: string
  trustBundleSynced: boolean
  updateState: UpdateState
  enrolledAt: string
  lastSeen: string
}

export interface RegisterKey {
  id: string
  name: string
  target: 'agent' | 'scanner'
  expiresAt?: string
  allowedCidrs: string[]
  maxUses: number
  usedCount: number
  approval: 'auto' | 'manual'
  allowRelaxedTls: boolean
  defaultGroup: string
  defaultTags: string[]
  createdAt: string
  revokedAt?: string
}

export interface Release {
  version: string
  publishedAt: string
  source: 'online' | 'upload'
  verified: boolean
  notes: string
}

// 배포할 버전은 서버 전체에 하나다. Agent는 확인 주기마다 서버에 물어보고 자기 버전과 다르면 받는다.
export interface UpdateSettings {
  targetVersion: string
  checkIntervalMinutes: number
}

// ── 원격 수집 ────────────────────────────────────────

export interface ScanTarget {
  id: string
  name: string
  protocol: 'ssh' | 'winrm'
  address: string
  port: number
  credentialId: string
  scannerId: string
  sudo: boolean
  hostKeyPinned?: boolean
  schedule: string
  assetId?: string
  lastRun?: { at: string; result: 'ok' | 'partial' | 'failed'; message?: string; durationSec: number }
}

export interface Credential {
  id: string
  name: string
  kind: 'ssh_key' | 'ssh_password' | 'winrm' | 'kubeconfig'
  username?: string
  usedBy: number
  createdAt: string
}

// ── 설정 ─────────────────────────────────────────────

export interface Feed {
  id: string
  name: string
  covers: string
  mode: 'online' | 'offline'
  status: 'ok' | 'stale' | 'error'
  lastSync?: string
  advisories: number
  message?: string
}

// 서버 인증서 한 벌. auto는 내부 CA가 발급·갱신, manual은 관리자가 체인과 키를 올린다.
export interface TlsEndpoint {
  mode: 'auto' | 'manual'
  subject: string
  issuer: string
  names: string[]
  expiresAt: string
}

// Web/API TLS와 Agent TLS는 따로 설정한다. 인증서와 CA를 공유하지 않는다.
export interface TlsState {
  web: TlsEndpoint
  agent: TlsEndpoint
  // Agent TLS 신뢰 앵커의 SPKI 해시. 등록 문자열의 ca-hash
  anchorSpkiHash: string
  agentCaExpiresAt: string
  unsyncedAgents: number
}
