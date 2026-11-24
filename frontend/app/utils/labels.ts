// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

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
  Exposure,
  FindingLayer,
  FixState,
  K8sPodPhase,
  PrivilegeLevel,
  SectionCoverageLevel,
  SectionName,
  Severity,
  TlsMode,
  TriageJustification,
  UpdateState,
} from '~/types'

export type Tone = 'ok' | 'warn' | 'danger' | 'info' | 'neutral'

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

export const podPhaseLabel: Record<K8sPodPhase, string> = {
  Running: '실행 중',
  Pending: '대기',
  Succeeded: '완료',
  Failed: '실패',
  Unknown: '알 수 없음',
}

export const podPhaseTone: Record<K8sPodPhase, Tone> = {
  Running: 'ok',
  Pending: 'warn',
  Succeeded: 'neutral',
  Failed: 'danger',
  Unknown: 'neutral',
}

export const sectionCoverageLabel: Record<SectionCoverageLevel, string> = {
  full: '전체',
  partial: '부분',
  none: '수집 안 함',
}

export const sectionCoverageTone: Record<SectionCoverageLevel, Tone> = {
  full: 'ok',
  partial: 'warn',
  none: 'danger',
}

/** Korean labels for the reason codes of scan results (internal/scanner/runner). */
export const scanReasonLabel: Record<string, string> = {
  partial_sections: '일부 섹션만 수집',
  host_key_changed: 'host key 변경됨',
  connect_failed: '연결 실패',
  auth_failed: '인증 실패',
  sudo_fallback: 'sudo 사용 불가',
  timeout: '시간 초과',
}

/**
 * Splits a "<code>: <detail>" scan message. `label` is set only for a known
 * code; unknown messages are returned untouched in `detail`.
 */
export function parseScanMessage(message: string): { label?: string; detail: string } {
  const m = /^([a-z][a-z0-9_]*)(?::\s*(.*))?$/s.exec(message.trim())
  const label = m ? scanReasonLabel[m[1]!] : undefined
  if (!m || !label) return { detail: message }
  return { label, detail: m[2] ?? '' }
}

export const severityLabel: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  none: 'None',
}

export const fixStateLabel: Record<FixState, string> = {
  fixed: '수정 버전 있음',
  not_fixed: '수정 없음',
  will_not_fix: '수정 안 함',
  under_investigation: '조사 중',
  unknown: '확인 안 됨',
}

// Exposure levels as the meter shows them: 4 bars for listening down to 1 for unknown.
export const exposureLevel: Record<Exposure, number> = {
  listening: 4,
  running: 3,
  installed: 2,
  unknown: 1,
}

export const exposureLabel: Record<Exposure, string> = {
  listening: 'listen ports',
  running: '실행',
  installed: '설치',
  unknown: '미확인',
}

export const findingLayerLabel: Record<FindingLayer, string> = {
  host: '호스트',
  runtime: '실행 중 추가',
  image: '이미지',
}

export const justificationLabel: Record<TriageJustification, string> = {
  code_not_present: '취약 코드 없음',
  code_not_reachable: '실행 경로 아님',
  requires_configuration: '설정 필요(미설정)',
  requires_environment: '환경 필요(해당 없음)',
  protected_at_runtime: '런타임 보호',
  protected_by_mitigating_control: '완화 조치 적용',
}
