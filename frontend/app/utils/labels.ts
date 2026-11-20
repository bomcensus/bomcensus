import type {
  AgentStatus,
  AssetKind,
  ComponentLayer,
  ContainerRuntime,
  CollectMethod,
  ComponentOrigin,
  ComponentType,
  ConnMode,
  Coverage,
  DetectMethod,
  ExeState,
  FindingStatus,
  FixState,
  MatchBasis,
  PrivilegeLevel,
  SectionName,
  Severity,
  TlsMode,
  UpdateState,
} from '~/types'

export type Tone = 'ok' | 'warn' | 'danger' | 'info' | 'neutral'

export const severityLabel: Record<Severity, string> = {
  critical: '심각',
  high: '높음',
  medium: '중간',
  low: '낮음',
}

export const assetKindLabel: Record<AssetKind, string> = {
  host: '호스트',
  workload: '워크로드',
}

export const layerLabel: Record<ComponentLayer, string> = {
  image: '이미지',
  runtime: 'runtime',
}

export const runtimeLabel: Record<ContainerRuntime, string> = {
  kubernetes: 'Kubernetes',
  docker: 'docker',
  containerd: 'containerd',
}

export const methodLabel: Record<CollectMethod, string> = {
  agent: 'Agent',
  ssh: 'SSH',
  winrm: 'WinRM',
  k8s_exec: 'K8s exec',
  k8s_inventory: 'K8s 인벤토리',
}

export const coverageLabel: Record<Coverage, string> = {
  full: '전체',
  partial: '부분',
  process_only: '프로세스만',
  inventory_only: '인벤토리만',
  unsupported: '미지원',
  failed: '실패',
}

export const coverageTone: Record<Coverage, Tone> = {
  full: 'ok',
  partial: 'warn',
  process_only: 'warn',
  inventory_only: 'neutral',
  unsupported: 'neutral',
  failed: 'danger',
}

export const privilegeLabel: Record<PrivilegeLevel, string> = {
  privileged: 'privileged',
  non_root: 'non-root',
}

export const sectionLabel: Record<SectionName, string> = {
  host: 'OS',
  packages: '패키지',
  artifacts: '아티팩트',
  processes: '프로세스',
  containers: '컨테이너',
}

export const componentTypeLabel: Record<ComponentType, string> = {
  deb: 'deb',
  rpm: 'rpm',
  apk: 'apk',
  maven: 'Maven',
  golang: 'Go 모듈',
  binary: '바이너리',
  windows: 'Windows',
  middleware: '미들웨어',
}

export const originLabel: Record<ComponentOrigin, string> = {
  distro: '배포판',
  third_party: '서드파티',
  upstream: '업스트림',
}

export const detectMethodLabel: Record<DetectMethod, string> = {
  package_db: '패키지 DB',
  exec: '버전 명령 실행',
  static: '정적 추출',
  manifest: '매니페스트',
  buildinfo: 'Go buildinfo',
}

export const fixStateLabel: Record<FixState, string> = {
  fixed_available: '수정 버전 있음',
  not_fixed: '수정 없음',
  wont_fix: '수정 안 함',
}

export const matchBasisLabel: Record<MatchBasis, string> = {
  distro_advisory: '배포판 권고',
  upstream_range: '업스트림 버전 범위',
  msrc: 'MSRC',
  curated: '자체 권고 DB',
}

export const findingStatusLabel: Record<FindingStatus, string> = {
  open: '미해결',
  restart_required: '재시작 필요',
  accepted: '예외 처리',
  resolved: '해결',
}

export const findingStatusTone: Record<FindingStatus, Tone> = {
  open: 'danger',
  restart_required: 'warn',
  accepted: 'neutral',
  resolved: 'ok',
}

export const exeStateLabel: Record<ExeState, string> = {
  normal: '정상',
  replaced: '교체됨',
  deleted: '삭제됨',
  memfd: 'fileless 실행',
}

export const exeStateTone: Record<ExeState, Tone> = {
  normal: 'neutral',
  replaced: 'warn',
  deleted: 'danger',
  memfd: 'danger',
}

export const agentStatusLabel: Record<AgentStatus, string> = {
  online: '온라인',
  offline: '오프라인',
  pending_approval: '승인 대기',
  revoked: '폐기',
}

export const agentStatusTone: Record<AgentStatus, Tone> = {
  online: 'ok',
  offline: 'danger',
  pending_approval: 'warn',
  revoked: 'neutral',
}

export const connModeLabel: Record<ConnMode, string> = {
  connect: 'connect',
  listen: 'listen',
}

export const tlsModeLabel: Record<TlsMode, string> = {
  pinned: 'pinned',
  system: 'system',
  none: 'none',
}

export const tlsModeTone: Record<TlsMode, Tone> = {
  pinned: 'ok',
  system: 'warn',
  none: 'danger',
}

export const updateStateLabel: Record<UpdateState, string> = {
  up_to_date: '최신',
  pending: '대기',
  updating: '진행 중',
  rolled_back: '롤백됨',
}

export const updateStateTone: Record<UpdateState, Tone> = {
  up_to_date: 'ok',
  pending: 'neutral',
  updating: 'info',
  rolled_back: 'danger',
}
