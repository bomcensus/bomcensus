import type { ContainerImage, K8sCluster, K8sWorkload, K8sPod, K8sPodContainer } from '~/types'

const DIGEST = {
  apiServer: 'sha256:19492591a0be663e9683945d58533b2ea225faae20dc40d09a2f91a7895adca4',
  worker: 'sha256:91474db21f72107c93c226f5901af1bd222b78f677eae179393a1514d98098aa',
  postgres: 'sha256:08b3d02d5cf16ae95627529acc656dbf0c11542cfc28b5e455d2c333b27c483b',
  legacyApp: 'sha256:c2ebdcf6b29a3de6e0ab36a73f6a362671f64ba59c1141f20d0fe78d2524138b',
  webFrontend: 'sha256:66d70cf8b9c5631863acee1c6d8cf2750fbb48ce3f7da98b7fc087f9c721740f',
  orderApi: 'sha256:4a0e833ba3dc3b1eec1ed95982304d9d35a9204b2880f65da63d4c912ee58419',
  paymentGw: 'sha256:70caa2fa0a69435391b0f43786d4f252dcb5fcbd7de283374f74e70d01602001',
  redis: 'sha256:00cba43785167201ed8bfd2139cb82d93da84b1373b7380865ab227a0b7ec17c',
  authServer: 'sha256:a9e58f4bcaf800b765fb77f1c9c71e79502b0d3891dd389f0add7dca865fee58',
  metricsExporter: 'sha256:0b39ae3a0b95b5ea4cc6efe8b95b691af7515c015b3f287747eaf367bd895818',
  ingressProxy: 'sha256:7a21f6009f8314bc75ec633453a7809ff41e58ead202ab7fea7f8b28ae96f624',
  statusUi: 'sha256:834e1204f1057b2c6f487a8931f2e6cfb42525efaa283ad4311fa6a612a4a6f2',
  ciRunner: 'sha256:21a741eb011dae4d0121de73adbd3f4fec740fb790bf1eaf26e401ffff08db3d',
  logShipper: 'sha256:3a08376a23e426b4cab2076c569d9ed498e4fb6a573bc6f334fbc64441d66894',
  istioProxy: 'sha256:0a3a95819e2b8a96fe3947c4ff7a991ac76c63c1aa30508591955ac656a8c3f6',
  apiServerOld: 'sha256:b9042d4687b3cc530a6936e8660781f762e9ad77b9f3264892e60f002b26eab4',
  busybox: 'sha256:4b0c46f071e43c53da8cc702867fa31192a331c7f8c3914135c8ea9497a9da92',
  orderApiOld: 'sha256:2d914a4adb752b83256b6ecb78ecd87645137e6393063ebccd668c79c336e8a0',
}

const REG = 'registry.example.internal'

export const images: ContainerImage[] = [
  { digest: DIGEST.apiServer, repoTags: [`${REG}/dev/api-server:2.3.1`, `${REG}/dev/api-server:sandbox`], os: 'linux', arch: 'amd64', sizeBytes: 412_337_664, firstSeen: '2026-07-15T17:33:02+09:00' },
  { digest: DIGEST.worker, repoTags: [`${REG}/dev/worker:1.8.0`], os: 'linux', arch: 'amd64', sizeBytes: 38_912_512, firstSeen: '2026-04-02T10:12:45+09:00' },
  { digest: DIGEST.postgres, repoTags: ['docker.io/library/postgres:15.6-alpine'], os: 'linux', arch: 'amd64', sizeBytes: 243_220_480, firstSeen: '2026-02-26T14:50:31+09:00' },
  { digest: DIGEST.legacyApp, repoTags: [`${REG}/dev/legacy-app:0.9`], os: 'linux', arch: 'amd64', sizeBytes: 689_963_008, firstSeen: '2025-12-02T09:20:14+09:00' },
  { digest: DIGEST.webFrontend, repoTags: [`${REG}/shop/web-frontend:1.14.2`], os: 'linux', arch: 'amd64', sizeBytes: 201_326_592, firstSeen: '2026-11-11T16:18:40+09:00' },
  { digest: DIGEST.orderApi, repoTags: [`${REG}/shop/order-api:3.8.0`], os: 'linux', arch: 'amd64', sizeBytes: 318_767_104, firstSeen: '2026-08-25T15:08:12+09:00' },
  { digest: DIGEST.paymentGw, repoTags: [`${REG}/payment/payment-gw:2.1.4`], os: 'linux', arch: 'amd64', sizeBytes: 27_262_976, firstSeen: '2026-11-09T14:29:51+09:00' },
  { digest: DIGEST.redis, repoTags: ['docker.io/library/redis:7.2.4-alpine'], os: 'linux', arch: 'amd64', sizeBytes: 41_943_040, firstSeen: '2026-03-04T10:00:21+09:00' },
  { digest: DIGEST.authServer, repoTags: [`${REG}/auth/auth-server:5.2.0`], os: 'linux', arch: 'amd64', sizeBytes: 296_747_008, firstSeen: '2026-07-08T16:18:03+09:00' },
  { digest: DIGEST.metricsExporter, repoTags: [`${REG}/monitoring/metrics-exporter:0.7.1`], os: 'linux', arch: 'amd64', sizeBytes: 22_020_096, firstSeen: '2026-03-04T10:00:21+09:00' },
  { digest: DIGEST.ingressProxy, repoTags: [`${REG}/edge/ingress-proxy:1.26.1`], os: 'linux', arch: 'amd64', sizeBytes: 18_874_368, firstSeen: '2026-06-30T11:02:44+09:00' },
  { digest: DIGEST.statusUi, repoTags: [`${REG}/it/status-ui:4.1.0`], os: 'linux', arch: 'amd64', sizeBytes: 52_428_800, firstSeen: '2026-11-02T10:25:01+09:00' },
  { digest: DIGEST.ciRunner, repoTags: [`${REG}/ci/ci-runner:16.9.1`], os: 'linux', arch: 'amd64', sizeBytes: 377_487_360, firstSeen: '2026-06-10T15:20:33+09:00' },
  { digest: DIGEST.istioProxy, repoTags: ['docker.io/istio/proxyv2:1.20.3'], os: 'linux', arch: 'amd64', sizeBytes: 98_566_144, firstSeen: '2026-03-04T10:00:21+09:00' },
  { digest: DIGEST.apiServerOld, repoTags: [`${REG}/dev/api-server:2.3.0`], os: 'linux', arch: 'amd64', sizeBytes: 409_993_216, firstSeen: '2026-06-24T10:41:52+09:00' },
  { digest: DIGEST.busybox, repoTags: ['docker.io/library/busybox:1.36.1'], os: 'linux', arch: 'amd64', sizeBytes: 4_270_080, firstSeen: '2026-05-13T16:02:19+09:00' },
  { digest: DIGEST.orderApiOld, repoTags: [`${REG}/shop/order-api:3.7.2`], os: 'linux', arch: 'amd64', sizeBytes: 316_669_952, firstSeen: '2026-03-04T10:00:21+09:00' },
  { digest: DIGEST.logShipper, repoTags: [`${REG}/platform/log-shipper:2.2.0`], os: 'linux', arch: 'amd64', sizeBytes: 61_865_984, firstSeen: '2026-08-25T15:08:12+09:00' },
]

export const clusters: K8sCluster[] = [
  {
    id: 'k8s-0001',
    name: 'prd-cluster',
    version: 'v1.29.6',
    scannerId: 'agt-0017',
    connection: 'in_cluster',
    execEnabled: true,
    filter: {
      nsInclude: ['*'],
      nsExclude: ['kube-system', 'kube-public', 'kube-node-lease', 'cert-manager'],
      labelInclude: [],
      labelExclude: ['bomcensus.io/skip=true'],
      annotationInclude: [],
      annotationExclude: ['bomcensus.io/scan=false'],
    },
    lastSync: '2026-11-20T08:35:30+09:00',
  },
  {
    id: 'k8s-0002',
    name: 'dev-cluster',
    version: 'v1.30.2',
    scannerId: 'agt-0018',
    connection: 'kubeconfig',
    execEnabled: false,
    filter: {
      nsInclude: ['dev-*', 'sandbox'],
      nsExclude: ['dev-tmp-*'],
      labelInclude: ['team in (platform,api)'],
      labelExclude: [],
      annotationInclude: [],
      annotationExclude: ['bomcensus.io/scan=false'],
    },
    lastSync: '2026-11-20T07:10:00+09:00',
  },
]

export const workloads: K8sWorkload[] = [
  { id: 'wl-0001', clusterId: 'k8s-0001', namespace: 'shop', kind: 'Deployment', name: 'web-frontend', replicas: 3, assetId: 'ast-2001', excluded: false },
  { id: 'wl-0002', clusterId: 'k8s-0001', namespace: 'shop', kind: 'Deployment', name: 'order-api', replicas: 3, assetId: 'ast-2002', excluded: false },
  { id: 'wl-0003', clusterId: 'k8s-0001', namespace: 'payment', kind: 'Deployment', name: 'payment-gw', replicas: 3, assetId: 'ast-2003', excluded: false },
  { id: 'wl-0004', clusterId: 'k8s-0001', namespace: 'data', kind: 'StatefulSet', name: 'redis', replicas: 1, assetId: 'ast-2004', excluded: false },
  { id: 'wl-0005', clusterId: 'k8s-0001', namespace: 'auth', kind: 'Deployment', name: 'auth-server', replicas: 2, assetId: 'ast-2005', excluded: false },
  { id: 'wl-0006', clusterId: 'k8s-0001', namespace: 'monitoring', kind: 'DaemonSet', name: 'metrics-exporter', replicas: 4, assetId: 'ast-2006', excluded: false },
  { id: 'wl-0007', clusterId: 'k8s-0001', namespace: 'edge', kind: 'Deployment', name: 'ingress-proxy', replicas: 3, assetId: 'ast-2008', excluded: false },
  { id: 'wl-0008', clusterId: 'k8s-0001', namespace: 'kube-system', kind: 'Deployment', name: 'coredns', replicas: 2, excluded: true, excludedBy: 'namespace exclude: kube-system' },
  { id: 'wl-0009', clusterId: 'k8s-0001', namespace: 'shop', kind: 'CronJob', name: 'legacy-report', replicas: 1, excluded: true, excludedBy: 'annotation exclude: bomcensus.io/scan=false' },
  { id: 'wl-0010', clusterId: 'k8s-0001', namespace: 'cert-manager', kind: 'Deployment', name: 'cert-manager', replicas: 1, excluded: true, excludedBy: 'namespace exclude: cert-manager' },
  { id: 'wl-0011', clusterId: 'k8s-0002', namespace: 'dev-api', kind: 'Deployment', name: 'api-sandbox', replicas: 1, assetId: 'ast-2007', excluded: false },
  { id: 'wl-0012', clusterId: 'k8s-0002', namespace: 'dev-api', kind: 'Deployment', name: 'api-mock', replicas: 1, excluded: false },
  { id: 'wl-0013', clusterId: 'k8s-0002', namespace: 'sandbox', kind: 'Deployment', name: 'web-preview', replicas: 2, excluded: false },
  { id: 'wl-0014', clusterId: 'k8s-0002', namespace: 'dev-api', kind: 'CronJob', name: 'db-seed', replicas: 1, excluded: false },
]

const REPLICA = '같은 이미지의 다른 replica에서 전체 수집'
const EXEC_OFF = 'exec 수집 미사용'

function c(name: string, imageRef: string, imageDigest: string, coverage: K8sPodContainer['coverage'], coverageReason?: string): K8sPodContainer {
  return { name, imageRef, imageDigest, coverage, coverageReason }
}

const webFrontend = (coverage: K8sPodContainer['coverage'], reason?: string) => c('web-frontend', `${REG}/shop/web-frontend:1.14.2`, DIGEST.webFrontend, coverage, reason)
const orderApi = (coverage: K8sPodContainer['coverage'], reason?: string) => c('order-api', `${REG}/shop/order-api:3.8.0`, DIGEST.orderApi, coverage, reason)
const logShipper = (coverage: K8sPodContainer['coverage'], reason: string) => c('log-shipper', `${REG}/platform/log-shipper:2.2.0`, DIGEST.logShipper, coverage, reason)
const paymentGw = () => c('payment-gw', `${REG}/payment/payment-gw:2.1.4`, DIGEST.paymentGw, 'process_only', '정책: 결제 namespace는 프로세스만 수집')
const authServer = (coverage: K8sPodContainer['coverage'], reason?: string) => c('auth-server', `${REG}/auth/auth-server:5.2.0`, DIGEST.authServer, coverage, reason)
const metricsExporter = () => c('metrics-exporter', `${REG}/monitoring/metrics-exporter:0.7.1`, DIGEST.metricsExporter, 'unsupported', '셸이 없는 이미지')
const ingressProxy = (coverage: K8sPodContainer['coverage'], reason?: string) => c('ingress-proxy', `${REG}/edge/ingress-proxy:1.26.1`, DIGEST.ingressProxy, coverage, reason)
const istio = (coverage: K8sPodContainer['coverage'], reason?: string) => c('istio-proxy', 'docker.io/istio/proxyv2:1.20.3', DIGEST.istioProxy, coverage, reason)
const READONLY = '쓰기 가능한 경로 없음 (readOnlyRootFilesystem)'

export const pods: K8sPod[] = [
  { id: 'pod-0001', workloadId: 'wl-0001', name: 'web-frontend-7d9f8c6b5-2xkqp', node: 'prd-node-01', phase: 'Running', containers: [webFrontend('full'), istio('full')] },
  { id: 'pod-0002', workloadId: 'wl-0001', name: 'web-frontend-7d9f8c6b5-8hz4m', node: 'prd-node-02', phase: 'Running', containers: [webFrontend('process_only', REPLICA), istio('process_only', REPLICA)] },
  { id: 'pod-0003', workloadId: 'wl-0001', name: 'web-frontend-7d9f8c6b5-tq7wn', node: 'prd-node-03', phase: 'Running', containers: [webFrontend('process_only', REPLICA), istio('process_only', REPLICA)] },

  { id: 'pod-0004', workloadId: 'wl-0002', name: 'order-api-5c8b9d7f4-k2m9x', node: 'prd-node-02', phase: 'Running', containers: [orderApi('full'), logShipper('failed', READONLY)] },
  { id: 'pod-0005', workloadId: 'wl-0002', name: 'order-api-5c8b9d7f4-p7r4t', node: 'prd-node-03', phase: 'Running', containers: [orderApi('process_only', REPLICA), logShipper('failed', READONLY)] },
  {
    id: 'pod-0006',
    workloadId: 'wl-0002',
    name: 'order-api-5c8b9d7f4-zx8w2',
    node: 'prd-node-04',
    phase: 'Pending',
    containers: [orderApi('inventory_only', 'Pod가 실행 중이 아님'), logShipper('inventory_only', 'Pod가 실행 중이 아님')],
  },

  { id: 'pod-0007', workloadId: 'wl-0003', name: 'payment-gw-6f4d8c9b7-4hn2s', node: 'prd-node-01', phase: 'Running', containers: [paymentGw(), istio('process_only', '정책: 결제 namespace는 프로세스만 수집')] },
  { id: 'pod-0008', workloadId: 'wl-0003', name: 'payment-gw-6f4d8c9b7-9jq5m', node: 'prd-node-02', phase: 'Running', containers: [paymentGw(), istio('process_only', '정책: 결제 namespace는 프로세스만 수집')] },
  { id: 'pod-0009', workloadId: 'wl-0003', name: 'payment-gw-6f4d8c9b7-wb3k8', node: 'prd-node-04', phase: 'Running', containers: [paymentGw(), istio('process_only', '정책: 결제 namespace는 프로세스만 수집')] },

  {
    id: 'pod-0010',
    workloadId: 'wl-0004',
    name: 'redis-0',
    node: 'prd-node-03',
    phase: 'Running',
    containers: [c('redis', 'docker.io/library/redis:7.2.4-alpine', DIGEST.redis, 'full')],
  },

  { id: 'pod-0011', workloadId: 'wl-0005', name: 'auth-server-8b7c6d5f9-m4x2p', node: 'prd-node-01', phase: 'Running', containers: [authServer('full'), istio('full')] },
  { id: 'pod-0012', workloadId: 'wl-0005', name: 'auth-server-8b7c6d5f9-r9t6v', node: 'prd-node-04', phase: 'Running', containers: [authServer('process_only', REPLICA), istio('process_only', REPLICA)] },

  { id: 'pod-0013', workloadId: 'wl-0006', name: 'metrics-exporter-4kx7p', node: 'prd-node-01', phase: 'Running', containers: [metricsExporter()] },
  { id: 'pod-0014', workloadId: 'wl-0006', name: 'metrics-exporter-9mzq2', node: 'prd-node-02', phase: 'Running', containers: [metricsExporter()] },
  { id: 'pod-0015', workloadId: 'wl-0006', name: 'metrics-exporter-hv5t8', node: 'prd-node-03', phase: 'Running', containers: [metricsExporter()] },
  { id: 'pod-0016', workloadId: 'wl-0006', name: 'metrics-exporter-w2rn6', node: 'prd-node-04', phase: 'Running', containers: [metricsExporter()] },

  { id: 'pod-0017', workloadId: 'wl-0007', name: 'ingress-proxy-7f6d5c4b8-2kq9w', node: 'prd-node-01', phase: 'Running', containers: [ingressProxy('full')] },
  { id: 'pod-0018', workloadId: 'wl-0007', name: 'ingress-proxy-7f6d5c4b8-hx7n3', node: 'prd-node-02', phase: 'Running', containers: [ingressProxy('process_only', REPLICA)] },
  { id: 'pod-0019', workloadId: 'wl-0007', name: 'ingress-proxy-7f6d5c4b8-v5m8r', node: 'prd-node-03', phase: 'Running', containers: [ingressProxy('process_only', REPLICA)] },

  {
    id: 'pod-0020',
    workloadId: 'wl-0011',
    name: 'api-sandbox-6c5b4d8f7-qw2ex',
    node: 'dev-node-01',
    phase: 'Running',
    containers: [c('api-server', `${REG}/dev/api-server:sandbox`, DIGEST.apiServer, 'inventory_only', EXEC_OFF)],
  },
  {
    id: 'pod-0021',
    workloadId: 'wl-0012',
    name: 'api-mock-58d7f9c6b4-t8r2n',
    node: 'dev-node-02',
    phase: 'Running',
    containers: [c('api-mock', `${REG}/dev/api-server:2.3.1`, DIGEST.apiServer, 'inventory_only', EXEC_OFF)],
  },
  {
    id: 'pod-0022',
    workloadId: 'wl-0013',
    name: 'web-preview-7b9c8d6f5-k4p7m',
    node: 'dev-node-01',
    phase: 'Running',
    containers: [c('web-preview', `${REG}/shop/web-frontend:1.14.2`, DIGEST.webFrontend, 'inventory_only', EXEC_OFF)],
  },
  {
    id: 'pod-0023',
    workloadId: 'wl-0013',
    name: 'web-preview-7b9c8d6f5-n2v9q',
    node: 'dev-node-02',
    phase: 'Running',
    containers: [c('web-preview', `${REG}/shop/web-frontend:1.14.2`, DIGEST.webFrontend, 'inventory_only', EXEC_OFF)],
  },
  {
    id: 'pod-0024',
    workloadId: 'wl-0014',
    name: 'db-seed-29384410-x7k2p',
    node: 'dev-node-02',
    phase: 'Succeeded',
    containers: [c('db-seed', 'docker.io/library/postgres:15.6-alpine', DIGEST.postgres, 'inventory_only', EXEC_OFF)],
  },
]
