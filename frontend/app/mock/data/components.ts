import type { SoftwareComponent, AssetComponent, DetectMethod } from '~/types'

// ── 컴포넌트 ─────────────────────────────────────────

interface PkgSpec {
  id: string
  name: string
  version: string
  sourceName?: string
  sourceVersion?: string
  vendor: string
  origin?: 'distro' | 'third_party'
}

function splitEpoch(version: string): { epoch?: string; bare: string } {
  const i = version.indexOf(':')
  return i < 0 ? { bare: version } : { epoch: version.slice(0, i), bare: version.slice(i + 1) }
}

function deb(namespace: 'ubuntu' | 'debian', distro: string, p: PkgSpec): SoftwareComponent {
  const { epoch, bare } = splitEpoch(p.version)
  const qualifiers = `arch=amd64&distro=${distro}${epoch ? `&epoch=${epoch}` : ''}`
  return {
    id: p.id,
    type: 'deb',
    name: p.name,
    version: p.version,
    purl: `pkg:deb/${namespace}/${p.name}@${bare}?${qualifiers}`,
    sourceName: p.sourceName ?? p.name,
    sourceVersion: p.sourceVersion ?? p.version,
    distro,
    arch: 'amd64',
    vendor: p.vendor,
    origin: p.origin ?? 'distro',
  }
}

function rpm(namespace: string, distro: string, p: PkgSpec): SoftwareComponent {
  const { epoch, bare } = splitEpoch(p.version)
  const qualifiers = `arch=x86_64${epoch ? `&epoch=${epoch}` : ''}&distro=${distro}`
  return {
    id: p.id,
    type: 'rpm',
    name: p.name,
    version: p.version,
    purl: `pkg:rpm/${namespace}/${p.name}@${bare}?${qualifiers}`,
    sourceName: p.sourceName ?? p.name,
    sourceVersion: p.sourceVersion ?? bare,
    distro,
    arch: 'x86_64',
    vendor: p.vendor,
    origin: p.origin ?? 'distro',
  }
}

function apk(distro: string, p: Omit<PkgSpec, 'vendor'>): SoftwareComponent {
  return {
    id: p.id,
    type: 'apk',
    name: p.name,
    version: p.version,
    purl: `pkg:apk/alpine/${p.name}@${p.version}?arch=x86_64&distro=${distro}`,
    sourceName: p.sourceName ?? p.name,
    sourceVersion: p.sourceVersion ?? p.version,
    distro,
    arch: 'x86_64',
    vendor: 'Alpine Linux',
    origin: 'distro',
  }
}

function maven(id: string, group: string, artifact: string, version: string): SoftwareComponent {
  return {
    id,
    type: 'maven',
    name: `${group}:${artifact}`,
    version,
    purl: `pkg:maven/${group}/${artifact}@${version}`,
    origin: 'upstream',
  }
}

function gomod(id: string, name: string, version: string): SoftwareComponent {
  return { id, type: 'golang', name, version, purl: `pkg:golang/${name}@${version}`, origin: 'upstream' }
}

const U2404 = 'ubuntu-24.04'
const U2204 = 'ubuntu-22.04'
const D12 = 'debian-12'
const UBUNTU = 'Ubuntu Developers'
const DEBIAN = 'Debian'
const REDHAT = 'Red Hat, Inc.'

export const components: SoftwareComponent[] = [
  // Ubuntu 24.04
  deb('ubuntu', U2404, { id: 'cmp-0101', name: 'libssl3t64', version: '3.0.13-0ubuntu3.5', sourceName: 'openssl', vendor: UBUNTU }),
  deb('ubuntu', U2404, { id: 'cmp-0102', name: 'libssl3t64', version: '3.0.13-0ubuntu3.1', sourceName: 'openssl', vendor: UBUNTU }),
  deb('ubuntu', U2404, { id: 'cmp-0103', name: 'openssh-server', version: '1:9.6p1-3ubuntu13.5', sourceName: 'openssh', vendor: UBUNTU }),
  deb('ubuntu', U2404, { id: 'cmp-0104', name: 'nginx', version: '1.24.0-2ubuntu7.1', vendor: UBUNTU }),
  deb('ubuntu', U2404, { id: 'cmp-0105', name: 'nginx', version: '1.24.0-2ubuntu7', vendor: UBUNTU }),
  deb('ubuntu', U2404, { id: 'cmp-0106', name: 'libc6', version: '2.39-0ubuntu8.3', sourceName: 'glibc', vendor: UBUNTU }),
  deb('ubuntu', U2404, { id: 'cmp-0107', name: 'sudo', version: '1.9.15p5-3ubuntu5', vendor: UBUNTU }),

  // Ubuntu 22.04
  deb('ubuntu', U2204, { id: 'cmp-0111', name: 'libssl3', version: '3.0.2-0ubuntu1.12', sourceName: 'openssl', vendor: UBUNTU }),
  deb('ubuntu', U2204, { id: 'cmp-0112', name: 'openssh-server', version: '1:8.9p1-3ubuntu0.1', sourceName: 'openssh', vendor: UBUNTU }),
  deb('ubuntu', U2204, { id: 'cmp-0113', name: 'libc6', version: '2.35-0ubuntu3.8', sourceName: 'glibc', vendor: UBUNTU }),
  deb('ubuntu', U2204, { id: 'cmp-0114', name: 'sudo', version: '1.9.9-1ubuntu2.4', vendor: UBUNTU }),
  deb('ubuntu', U2204, { id: 'cmp-0115', name: 'curl', version: '7.81.0-1ubuntu1.13', vendor: UBUNTU }),
  deb('ubuntu', U2204, { id: 'cmp-0116', name: 'libc6', version: '2.35-0ubuntu3.1', sourceName: 'glibc', vendor: UBUNTU }),
  deb('ubuntu', U2204, { id: 'cmp-0117', name: 'libssl3', version: '3.0.2-0ubuntu1.8', sourceName: 'openssl', vendor: UBUNTU }),
  deb('ubuntu', U2204, { id: 'cmp-0118', name: 'zlib1g', version: '1:1.2.11.dfsg-2ubuntu9.2', sourceName: 'zlib', vendor: UBUNTU }),
  deb('ubuntu', U2204, { id: 'cmp-0119', name: 'ca-certificates', version: '20240203~22.04.1', vendor: UBUNTU }),

  // Debian 12
  deb('debian', D12, { id: 'cmp-0121', name: 'libssl3', version: '3.0.11-1~deb12u2', sourceName: 'openssl', vendor: DEBIAN }),
  deb('debian', D12, { id: 'cmp-0122', name: 'openssh-server', version: '1:9.2p1-2+deb12u2', sourceName: 'openssh', vendor: DEBIAN }),
  deb('debian', D12, { id: 'cmp-0123', name: 'libc6', version: '2.36-9+deb12u4', sourceName: 'glibc', vendor: DEBIAN }),
  deb('debian', D12, { id: 'cmp-0124', name: 'sudo', version: '1.9.13p3-1+deb12u1', vendor: DEBIAN }),
  deb('debian', D12, { id: 'cmp-0125', name: 'zlib1g', version: '1:1.2.13.dfsg-1', sourceName: 'zlib', vendor: DEBIAN }),
  deb('debian', D12, { id: 'cmp-0126', name: 'tzdata', version: '2024a-0+deb12u1', vendor: DEBIAN }),
  deb('debian', D12, { id: 'cmp-0127', name: 'ca-certificates', version: '20230311', vendor: DEBIAN }),
  deb('debian', D12, { id: 'cmp-0128', name: 'base-files', version: '12.4+deb12u5', vendor: DEBIAN }),
  deb('debian', D12, { id: 'cmp-0129', name: 'netbase', version: '6.4', vendor: DEBIAN }),

  // CentOS 7
  rpm('centos', 'centos-7', { id: 'cmp-0131', name: 'openssl-libs', version: '1:1.0.2k-25.el7_9', sourceName: 'openssl', vendor: 'CentOS' }),
  rpm('centos', 'centos-7', { id: 'cmp-0132', name: 'sudo', version: '1.8.23-10.el7', vendor: 'CentOS' }),
  rpm('centos', 'centos-7', { id: 'cmp-0133', name: 'openssh-server', version: '7.4p1-22.el7_9', sourceName: 'openssh', vendor: 'CentOS' }),
  rpm('centos', 'centos-7', { id: 'cmp-0134', name: 'glibc', version: '2.17-326.el7_9', vendor: 'CentOS' }),
  rpm('centos', 'centos-7', { id: 'cmp-0135', name: 'sudo', version: '1.8.23-10.el7_9.3', vendor: 'CentOS' }),

  // RHEL 8
  rpm('redhat', 'rhel-8', { id: 'cmp-0141', name: 'openssl-libs', version: '1:1.1.1k-5.el8_5', sourceName: 'openssl', vendor: REDHAT }),
  rpm('redhat', 'rhel-8', { id: 'cmp-0142', name: 'glibc', version: '2.28-225.el8', vendor: REDHAT }),
  rpm('redhat', 'rhel-8', { id: 'cmp-0143', name: 'openssh-server', version: '8.0p1-17.el8_7', sourceName: 'openssh', vendor: REDHAT }),

  // RHEL 9
  rpm('redhat', 'rhel-9', { id: 'cmp-0151', name: 'openssl-libs', version: '1:3.0.7-27.el9', sourceName: 'openssl', vendor: REDHAT }),
  rpm('redhat', 'rhel-9', { id: 'cmp-0152', name: 'openssl-libs', version: '1:3.0.7-24.el9', sourceName: 'openssl', vendor: REDHAT }),
  rpm('redhat', 'rhel-9', { id: 'cmp-0153', name: 'glibc', version: '2.34-60.el9', vendor: REDHAT }),
  rpm('redhat', 'rhel-9', { id: 'cmp-0154', name: 'openssh-server', version: '8.7p1-34.el9', sourceName: 'openssh', vendor: REDHAT }),

  // Rocky Linux 9
  rpm('rocky', 'rocky-9', { id: 'cmp-0161', name: 'openssh-server', version: '8.7p1-34.el9', sourceName: 'openssh', vendor: 'Rocky Enterprise Software Foundation' }),
  rpm('rocky', 'rocky-9', { id: 'cmp-0162', name: 'openssh-server', version: '8.7p1-38.el9_4.4', sourceName: 'openssh', vendor: 'Rocky Enterprise Software Foundation' }),
  rpm('rocky', 'rocky-9', { id: 'cmp-0163', name: 'glibc', version: '2.34-100.el9', vendor: 'Rocky Enterprise Software Foundation' }),
  rpm('rocky', 'rocky-9', { id: 'cmp-0164', name: 'openssl-libs', version: '1:3.0.7-27.el9', sourceName: 'openssl', vendor: 'Rocky Enterprise Software Foundation' }),

  // Amazon Linux 2023
  rpm('amazon', 'amzn-2023', { id: 'cmp-0171', name: 'glibc', version: '2.34-52.amzn2023.0.3', vendor: 'Amazon Linux' }),
  rpm('amazon', 'amzn-2023', { id: 'cmp-0172', name: 'glibc', version: '2.34-117.amzn2023.0.1', vendor: 'Amazon Linux' }),
  rpm('amazon', 'amzn-2023', { id: 'cmp-0173', name: 'openssl-libs', version: '1:3.0.8-1.amzn2023.0.9', sourceName: 'openssl', vendor: 'Amazon Linux' }),
  rpm('amazon', 'amzn-2023', { id: 'cmp-0174', name: 'openssh-server', version: '8.7p1-8.amzn2023.0.4', sourceName: 'openssh', vendor: 'Amazon Linux' }),
  rpm('amazon', 'amzn-2023', { id: 'cmp-0175', name: 'docker', version: '25.0.6-1.amzn2023.0.2', vendor: 'Amazon Linux' }),
  rpm('amazon', 'amzn-2023', { id: 'cmp-0176', name: 'containerd', version: '1.7.20-1.amzn2023.0.1', vendor: 'Amazon Linux' }),

  // Alpine 3.20
  apk('alpine-3.20', { id: 'cmp-0181', name: 'openssh-server', version: '9.7_p1-r3', sourceName: 'openssh' }),
  apk('alpine-3.20', { id: 'cmp-0182', name: 'libcrypto3', version: '3.3.1-r0', sourceName: 'openssl' }),
  apk('alpine-3.20', { id: 'cmp-0183', name: 'busybox', version: '1.36.1-r29' }),
  apk('alpine-3.20', { id: 'cmp-0184', name: 'musl', version: '1.2.5-r0' }),
  apk('alpine-3.20', { id: 'cmp-0185', name: 'nginx', version: '1.26.1-r0' }),
  apk('alpine-3.20', { id: 'cmp-0191', name: 'pcre2', version: '10.43-r0' }),
  apk('alpine-3.20', { id: 'cmp-0192', name: 'zlib', version: '1.3.1-r1' }),

  // Alpine 3.19 / edge
  apk('alpine-3.19', { id: 'cmp-0187', name: 'libcrypto3', version: '3.1.4-r5', sourceName: 'openssl' }),
  apk('alpine-3.19', { id: 'cmp-0188', name: 'busybox', version: '1.36.1-r15' }),
  apk('alpine-3.19', { id: 'cmp-0189', name: 'musl', version: '1.2.4_git20230717-r4' }),
  apk('alpine-3.19', { id: 'cmp-0190', name: 'ssl_client', version: '1.36.1-r15', sourceName: 'busybox' }),
  apk('alpine-3.19', { id: 'cmp-0194', name: 'icu-libs', version: '74.1-r0', sourceName: 'icu' }),
  apk('alpine-edge', { id: 'cmp-0186', name: 'xz', version: '5.6.1-r1' }),

  // 서드파티 저장소 패키지
  deb('ubuntu', U2404, { id: 'cmp-0201', name: 'nginx', version: '1.24.0-1~noble', vendor: 'NGINX Packaging', origin: 'third_party' }),
  deb('ubuntu', U2204, { id: 'cmp-0202', name: 'docker-ce', version: '5:24.0.5-1~ubuntu.22.04~jammy', sourceName: 'docker-ce', vendor: 'Docker', origin: 'third_party' }),
  deb('ubuntu', U2204, { id: 'cmp-0203', name: 'containerd.io', version: '1.6.21-1', vendor: 'Docker', origin: 'third_party' }),
  deb('debian', D12, { id: 'cmp-0204', name: 'docker-ce', version: '5:26.1.4-1~debian.12~bookworm', vendor: 'Docker', origin: 'third_party' }),
  deb('debian', D12, { id: 'cmp-0205', name: 'containerd.io', version: '1.7.19-1', vendor: 'Docker', origin: 'third_party' }),
  rpm('redhat', 'rhel-9', { id: 'cmp-0206', name: 'postgresql16-server', version: '16.2-1PGDG.rhel9', sourceName: 'postgresql16', vendor: 'PostgreSQL Global Development Group', origin: 'third_party' }),

  // Maven
  maven('cmp-0301', 'org.apache.logging.log4j', 'log4j-core', '2.14.1'),
  maven('cmp-0302', 'org.apache.logging.log4j', 'log4j-core', '2.17.0'),
  maven('cmp-0303', 'org.springframework', 'spring-core', '5.3.17'),
  maven('cmp-0304', 'org.springframework', 'spring-beans', '5.3.17'),
  maven('cmp-0305', 'org.springframework', 'spring-core', '6.1.5'),
  maven('cmp-0306', 'com.fasterxml.jackson.core', 'jackson-databind', '2.13.1'),
  maven('cmp-0307', 'com.fasterxml.jackson.core', 'jackson-databind', '2.15.4'),
  maven('cmp-0308', 'org.apache.tomcat.embed', 'tomcat-embed-core', '9.0.58'),
  maven('cmp-0309', 'org.apache.tomcat.embed', 'tomcat-embed-core', '10.1.19'),
  maven('cmp-0310', 'org.egovframe.rte', 'org.egovframe.rte.fdl.cmmn', '4.0.0'),
  maven('cmp-0311', 'org.yaml', 'snakeyaml', '1.30'),

  // Go
  gomod('cmp-0401', 'stdlib', '1.21.1'),
  gomod('cmp-0402', 'stdlib', '1.22.2'),
  gomod('cmp-0403', 'golang.org/x/crypto', 'v0.14.0'),
  gomod('cmp-0404', 'golang.org/x/net', 'v0.15.0'),
  gomod('cmp-0405', 'google.golang.org/grpc', 'v1.56.2'),
  gomod('cmp-0406', 'github.com/prometheus/client_golang', 'v1.17.0'),
  gomod('cmp-0407', 'github.com/golang-jwt/jwt/v4', 'v4.5.0'),

  // 패키지가 아닌 소프트웨어
  { id: 'cmp-0501', type: 'binary', name: 'openjdk', version: '17.0.8', purl: 'pkg:generic/openjdk@17.0.8', cpe: 'cpe:2.3:a:oracle:openjdk:17.0.8:*:*:*:*:*:*:*', origin: 'upstream' },
  { id: 'cmp-0502', type: 'binary', name: 'openjdk', version: '11.0.20', purl: 'pkg:generic/openjdk@11.0.20', cpe: 'cpe:2.3:a:oracle:openjdk:11.0.20:*:*:*:*:*:*:*', origin: 'upstream' },
  { id: 'cmp-0503', type: 'binary', name: 'node', version: '20.11.0', purl: 'pkg:generic/node@20.11.0', cpe: 'cpe:2.3:a:nodejs:node.js:20.11.0:*:*:*:*:*:*:*', origin: 'upstream' },
  { id: 'cmp-0504', type: 'binary', name: 'node', version: '18.19.0', purl: 'pkg:generic/node@18.19.0', cpe: 'cpe:2.3:a:nodejs:node.js:18.19.0:*:*:*:*:*:*:*', origin: 'upstream' },
  { id: 'cmp-0505', type: 'binary', name: 'php', version: '8.1.27', purl: 'pkg:generic/php@8.1.27', cpe: 'cpe:2.3:a:php:php:8.1.27:*:*:*:*:*:*:*', origin: 'upstream' },
  { id: 'cmp-0506', type: 'binary', name: 'redis-server', version: '7.2.4', purl: 'pkg:generic/redis@7.2.4', cpe: 'cpe:2.3:a:redis:redis:7.2.4:*:*:*:*:*:*:*', origin: 'upstream' },
  { id: 'cmp-0507', type: 'binary', name: 'postgres', version: '15.6', purl: 'pkg:generic/postgresql@15.6', cpe: 'cpe:2.3:a:postgresql:postgresql:15.6:*:*:*:*:*:*:*', origin: 'upstream' },
  { id: 'cmp-0509', type: 'binary', name: 'envoy', version: '1.28.1', purl: 'pkg:generic/envoy@1.28.1', cpe: 'cpe:2.3:a:envoyproxy:envoy:1.28.1:*:*:*:*:*:*:*', origin: 'upstream' },
  { id: 'cmp-0508', type: 'binary', name: 'nginx', version: '1.22.1', purl: 'pkg:generic/nginx@1.22.1', cpe: 'cpe:2.3:a:f5:nginx:1.22.1:*:*:*:*:*:*:*', origin: 'upstream' },

  // Windows
  { id: 'cmp-0601', type: 'windows', name: 'Microsoft SQL Server 2019', version: '15.0.4261.1', purl: 'pkg:generic/microsoft/sql-server-2019@15.0.4261.1', cpe: 'cpe:2.3:a:microsoft:sql_server_2019:15.0.4261.1:*:*:*:*:*:x64:*', vendor: 'Microsoft Corporation', origin: 'upstream' },
  { id: 'cmp-0602', type: 'windows', name: 'Microsoft Exchange Server 2019', version: '15.2.1258.12', purl: 'pkg:generic/microsoft/exchange-server-2019@15.2.1258.12', cpe: 'cpe:2.3:a:microsoft:exchange_server:2019:cumulative_update_13:*:*:*:*:*:*', vendor: 'Microsoft Corporation', origin: 'upstream' },
  { id: 'cmp-0603', type: 'windows', name: 'Internet Information Services', version: '10.0.17763.1', purl: 'pkg:generic/microsoft/iis@10.0.17763.1', cpe: 'cpe:2.3:a:microsoft:internet_information_services:10.0:*:*:*:*:*:*:*', vendor: 'Microsoft Corporation', origin: 'upstream' },
  { id: 'cmp-0604', type: 'windows', name: 'Microsoft .NET Runtime', version: '8.0.6', purl: 'pkg:generic/microsoft/dotnet-runtime@8.0.6', cpe: 'cpe:2.3:a:microsoft:.net:8.0.6:*:*:*:*:*:*:*', vendor: 'Microsoft Corporation', origin: 'upstream' },
  { id: 'cmp-0605', type: 'windows', name: 'Microsoft .NET Framework', version: '4.8.03761', purl: 'pkg:generic/microsoft/dotnet-framework@4.8.03761', vendor: 'Microsoft Corporation', origin: 'upstream' },
  { id: 'cmp-0606', type: 'windows', name: 'Microsoft Visual C++ 2015-2022 Redistributable (x64)', version: '14.38.33130', purl: 'pkg:generic/microsoft/vcredist-x64@14.38.33130', vendor: 'Microsoft Corporation', origin: 'upstream' },
  { id: 'cmp-0607', type: 'windows', name: 'PowerShell 7-x64', version: '7.4.1', purl: 'pkg:generic/microsoft/powershell@7.4.1', vendor: 'Microsoft Corporation', origin: 'upstream' },
  { id: 'cmp-0608', type: 'windows', name: 'Microsoft ODBC Driver 17 for SQL Server', version: '17.10.5.1', purl: 'pkg:generic/microsoft/msodbcsql17@17.10.5.1', vendor: 'Microsoft Corporation', origin: 'upstream' },

  // 국산 미들웨어
  { id: 'cmp-0701', type: 'middleware', name: 'JEUS', version: '8.5 Fix#1', purl: 'pkg:generic/tmaxsoft/jeus@8.5-fix1', vendor: 'TmaxSoft', origin: 'upstream' },
  { id: 'cmp-0702', type: 'middleware', name: 'WebtoB', version: '5.0 SP2 Fix#1', purl: 'pkg:generic/tmaxsoft/webtob@5.0-sp2-fix1', vendor: 'TmaxSoft', origin: 'upstream' },
  { id: 'cmp-0703', type: 'middleware', name: 'Tibero', version: '7 FS02', purl: 'pkg:generic/tmaxtibero/tibero@7-fs02', vendor: 'TmaxTibero', origin: 'upstream' },
]

// ── 자산별 컴포넌트 ──────────────────────────────────

const DPKG = '/var/lib/dpkg/status'
const RPMDB = '/var/lib/rpm/rpmdb.sqlite'
const RPMDB_BDB = '/var/lib/rpm/Packages'
const APKDB = '/lib/apk/db/installed'

interface RowOpts {
  inUse?: boolean
  removedAt?: string
}

function pkg(assetId: string, componentId: string, location: string, firstSeen: string, opts: RowOpts = {}): AssetComponent {
  return { assetId, componentId, locations: [location], inUse: opts.inUse ?? false, method: 'package_db', firstSeen, removedAt: opts.removedAt }
}

function jar(assetId: string, componentId: string, locations: string[], firstSeen: string, opts: RowOpts = {}): AssetComponent {
  return { assetId, componentId, locations, inUse: opts.inUse ?? false, method: 'manifest', firstSeen, removedAt: opts.removedAt }
}

function gobin(assetId: string, componentId: string, locations: string[], firstSeen: string, opts: RowOpts = {}): AssetComponent {
  return { assetId, componentId, locations, inUse: opts.inUse ?? false, method: 'buildinfo', firstSeen, removedAt: opts.removedAt }
}

function exec(assetId: string, componentId: string, location: string, versionCommand: string, versionRaw: string, firstSeen: string, opts: RowOpts = {}): AssetComponent {
  return { assetId, componentId, locations: [location], inUse: opts.inUse ?? false, method: 'exec', versionCommand, versionRaw, firstSeen, removedAt: opts.removedAt }
}

function stat(assetId: string, componentId: string, locations: string[], firstSeen: string, opts: RowOpts = {}): AssetComponent {
  return { assetId, componentId, locations, inUse: opts.inUse ?? false, method: 'static', firstSeen, removedAt: opts.removedAt }
}

const JAVA17_RAW = `openjdk version "17.0.8" 2023-07-18
OpenJDK Runtime Environment (build 17.0.8+7)
OpenJDK 64-Bit Server VM (build 17.0.8+7, mixed mode, sharing)`

const JAVA11_RAW = `openjdk version "11.0.20" 2023-07-18
OpenJDK Runtime Environment (build 11.0.20+8)
OpenJDK 64-Bit Server VM (build 11.0.20+8, mixed mode)`

const PHP_FPM_RAW = `PHP 8.1.27 (fpm-fcgi) (built: Jan 10 2024 14:22:31)
Copyright (c) The PHP Group
Zend Engine v4.1.27, Copyright (c) Zend Technologies
    with Zend OPcache v8.1.27, Copyright (c), by Zend Technologies`

const REDIS_RAW = 'Redis server v=7.2.4 sha=00000000:0 malloc=jemalloc-5.3.0 bits=64 build=7a42f7a1b1b3c0e1'
const POSTGRES_RAW = 'postgres (PostgreSQL) 15.6'
const NGINX_RAW = `nginx version: nginx/1.22.1
built by gcc 4.8.5 20150623 (Red Hat 4.8.5-44) (GCC)
built with OpenSSL 1.0.2k-fips  26 Jan 2017
TLS SNI support enabled`

const SHOP_WEB_JAR = '/srv/shop-web/shop-web.jar!/BOOT-INF/lib'
const PAY_WAR = '/home/jeus/jeus8/domains/pay_domain/servers/server1/webapps/pay.war!/WEB-INF/lib'
const PAY_WAR_2 = '/home/jeus/jeus8/domains/pay_domain/servers/server2/webapps/pay.war!/WEB-INF/lib'
const BATCH_JAR = '/home/batch/app/settlement-batch.jar!/BOOT-INF/lib'
const ORDER_JAR = '/app/order-api.jar!/BOOT-INF/lib'
const AUTH_JAR = '/app/auth-server.jar!/BOOT-INF/lib'

// ── 이미지 내용 ──────────────────────────────────────
// 같은 digest의 컨테이너는 이미지 층 컴포넌트가 같다. 컨테이너마다 다른 것은 실행 중 사용 여부뿐이다.

interface ImageEntry {
  componentId: string
  method: DetectMethod
  locations: string[]
  versionCommand?: string
  versionRaw?: string
}

const dpkgE = (componentId: string, location = DPKG): ImageEntry => ({ componentId, method: 'package_db', locations: [location] })
const apkE = (componentId: string): ImageEntry => ({ componentId, method: 'package_db', locations: [APKDB] })
const goE = (componentId: string, location: string): ImageEntry => ({ componentId, method: 'buildinfo', locations: [location] })
const jarE = (componentId: string, location: string): ImageEntry => ({ componentId, method: 'manifest', locations: [location] })
const execE = (componentId: string, location: string, versionCommand: string, versionRaw: string): ImageEntry => ({
  componentId,
  method: 'exec',
  locations: [location],
  versionCommand,
  versionRaw,
})

const DISTROLESS_DPKG = '/var/lib/dpkg/status.d'
const ENVOY_RAW = 'envoy  version: 2f9d4a1c6b8e0d7f3a5c9e1b4d6f8a0c2e4b6d8f/1.28.1/Clean/RELEASE/BoringSSL'
const ALPINE_319_BASE = ['cmp-0187', 'cmp-0188', 'cmp-0189', 'cmp-0190'].map(apkE)
const ALPINE_320_NGINX = ['cmp-0182', 'cmp-0183', 'cmp-0184', 'cmp-0185', 'cmp-0191', 'cmp-0192'].map(apkE)

const IMAGE = {
  apiServer: [
    ...['cmp-0111', 'cmp-0113', 'cmp-0115', 'cmp-0118', 'cmp-0119'].map((id) => dpkgE(id)),
    execE('cmp-0503', '/usr/local/bin/node', '/usr/local/bin/node --version', 'v20.11.0'),
  ],
  worker: [...ALPINE_319_BASE, apkE('cmp-0186'), goE('cmp-0402', '/app/worker'), goE('cmp-0406', '/app/worker')],
  postgres: [
    ...ALPINE_319_BASE,
    apkE('cmp-0194'),
    execE('cmp-0507', '/usr/local/bin/postgres', '/usr/local/bin/postgres --version', POSTGRES_RAW),
  ],
  redis: [
    ...ALPINE_319_BASE,
    execE('cmp-0506', '/usr/local/bin/redis-server', '/usr/local/bin/redis-server --version', REDIS_RAW),
    goE('cmp-0401', '/usr/local/bin/gosu'),
  ],
  webFrontend: [
    ...['cmp-0121', 'cmp-0123', 'cmp-0125', 'cmp-0126', 'cmp-0127'].map((id) => dpkgE(id)),
    execE('cmp-0504', '/usr/local/bin/node', '/usr/local/bin/node --version', 'v18.19.0'),
  ],
  orderApi: [
    ...['cmp-0111', 'cmp-0113', 'cmp-0118'].map((id) => dpkgE(id)),
    execE('cmp-0501', '/opt/java/openjdk/bin/java', '/opt/java/openjdk/bin/java -version', JAVA17_RAW),
    jarE('cmp-0303', `${ORDER_JAR}/spring-core-5.3.17.jar`),
    jarE('cmp-0304', `${ORDER_JAR}/spring-beans-5.3.17.jar`),
    jarE('cmp-0307', `${ORDER_JAR}/jackson-databind-2.15.4.jar`),
    jarE('cmp-0308', `${ORDER_JAR}/tomcat-embed-core-9.0.58.jar`),
    jarE('cmp-0302', `${ORDER_JAR}/log4j-core-2.17.0.jar`),
  ],
  paymentGw: ['cmp-0401', 'cmp-0403', 'cmp-0404', 'cmp-0405', 'cmp-0406', 'cmp-0407'].map((id) => goE(id, '/app/payment-gw')),
  authServer: [
    ...['cmp-0111', 'cmp-0113'].map((id) => dpkgE(id)),
    execE('cmp-0501', '/opt/java/openjdk/bin/java', '/opt/java/openjdk/bin/java -version', JAVA17_RAW),
    jarE('cmp-0302', `${AUTH_JAR}/log4j-core-2.17.0.jar`),
    jarE('cmp-0309', `${AUTH_JAR}/tomcat-embed-core-10.1.19.jar`),
    jarE('cmp-0305', `${AUTH_JAR}/spring-core-6.1.5.jar`),
    jarE('cmp-0307', `${AUTH_JAR}/jackson-databind-2.15.4.jar`),
  ],
  metricsExporter: [
    ...['cmp-0126', 'cmp-0128', 'cmp-0129'].map((id) => dpkgE(id, DISTROLESS_DPKG)),
    goE('cmp-0402', '/bin/metrics-exporter'),
    goE('cmp-0406', '/bin/metrics-exporter'),
  ],
  ingressProxy: ALPINE_320_NGINX,
  statusUi: ALPINE_320_NGINX,
  ciRunner: [
    ...['cmp-0111', 'cmp-0113', 'cmp-0115', 'cmp-0118'].map((id) => dpkgE(id)),
    goE('cmp-0401', '/usr/local/bin/ci-runner'),
    goE('cmp-0403', '/usr/local/bin/ci-runner'),
  ],
  istioProxy: [
    ...['cmp-0111', 'cmp-0113', 'cmp-0118'].map((id) => dpkgE(id)),
    execE('cmp-0509', '/usr/local/bin/envoy', '/usr/local/bin/envoy --version', ENVOY_RAW),
    goE('cmp-0402', '/usr/local/bin/pilot-agent'),
    goE('cmp-0404', '/usr/local/bin/pilot-agent'),
    goE('cmp-0405', '/usr/local/bin/pilot-agent'),
  ],
} satisfies Record<string, ImageEntry[]>

interface ContainerOpts {
  // 실행 중인 프로세스가 쓰는 컴포넌트
  inUse?: string[]
  // 이전 digest부터 있던 컴포넌트의 처음 발견 시각
  since?: Record<string, string>
}

function image(assetId: string, container: string, content: ImageEntry[], firstSeen: string, opts: ContainerOpts = {}): AssetComponent[] {
  return content.map((e) => ({
    assetId,
    componentId: e.componentId,
    container,
    layer: 'image',
    locations: e.locations,
    inUse: opts.inUse?.includes(e.componentId) ?? false,
    method: e.method,
    versionCommand: e.versionCommand,
    versionRaw: e.versionRaw,
    firstSeen: opts.since?.[e.componentId] ?? firstSeen,
  }))
}

function inContainer(row: AssetComponent, container: string, layer: 'image' | 'runtime'): AssetComponent {
  return { ...row, container, layer }
}

const ISTIO_IN_USE = ['cmp-0509', 'cmp-0402', 'cmp-0404', 'cmp-0405', 'cmp-0111', 'cmp-0113']

export const assetComponents: AssetComponent[] = [
  // ast-1001 web-prd-01
  pkg('ast-1001', 'cmp-0101', DPKG, '2026-09-05T03:12:44+09:00', { inUse: true }),
  pkg('ast-1001', 'cmp-0102', DPKG, '2025-12-08T14:20:41+09:00', { removedAt: '2026-09-05T03:12:44+09:00' }),
  pkg('ast-1001', 'cmp-0103', DPKG, '2025-12-08T14:20:41+09:00', { inUse: true }),
  pkg('ast-1001', 'cmp-0104', DPKG, '2026-05-12T03:05:18+09:00', { inUse: true }),
  pkg('ast-1001', 'cmp-0105', DPKG, '2025-12-08T14:20:41+09:00', { removedAt: '2026-05-12T03:05:18+09:00' }),
  pkg('ast-1001', 'cmp-0106', DPKG, '2025-12-08T14:20:41+09:00', { inUse: true }),
  pkg('ast-1001', 'cmp-0107', DPKG, '2025-12-08T14:20:41+09:00'),
  exec('ast-1001', 'cmp-0501', '/opt/jdk-17.0.8+7/bin/java', '/opt/jdk-17.0.8+7/bin/java -version', JAVA17_RAW, '2025-12-08T14:20:41+09:00', { inUse: true }),
  jar('ast-1001', 'cmp-0302', [`${SHOP_WEB_JAR}/log4j-core-2.17.0.jar`], '2025-12-08T14:20:41+09:00', { inUse: true }),
  jar('ast-1001', 'cmp-0305', [`${SHOP_WEB_JAR}/spring-core-6.1.5.jar`], '2026-04-14T21:30:02+09:00', { inUse: true }),
  jar('ast-1001', 'cmp-0309', [`${SHOP_WEB_JAR}/tomcat-embed-core-10.1.19.jar`], '2026-04-14T21:30:02+09:00', { inUse: true }),
  jar('ast-1001', 'cmp-0307', [`${SHOP_WEB_JAR}/jackson-databind-2.15.4.jar`], '2026-04-14T21:30:02+09:00', { inUse: true }),

  // ast-1002 web-prd-02
  pkg('ast-1002', 'cmp-0101', DPKG, '2026-09-05T03:20:11+09:00', { inUse: true }),
  pkg('ast-1002', 'cmp-0102', DPKG, '2025-12-08T14:31:09+09:00', { removedAt: '2026-09-05T03:20:11+09:00' }),
  pkg('ast-1002', 'cmp-0103', DPKG, '2025-12-08T14:31:09+09:00', { inUse: true }),
  pkg('ast-1002', 'cmp-0104', DPKG, '2026-05-12T03:11:40+09:00', { inUse: true }),
  pkg('ast-1002', 'cmp-0105', DPKG, '2025-12-08T14:31:09+09:00', { removedAt: '2026-05-12T03:11:40+09:00' }),
  pkg('ast-1002', 'cmp-0106', DPKG, '2025-12-08T14:31:09+09:00', { inUse: true }),
  pkg('ast-1002', 'cmp-0107', DPKG, '2025-12-08T14:31:09+09:00'),
  exec('ast-1002', 'cmp-0501', '/opt/jdk-17.0.8+7/bin/java', '/opt/jdk-17.0.8+7/bin/java -version', JAVA17_RAW, '2025-12-08T14:31:09+09:00', { inUse: true }),
  jar('ast-1002', 'cmp-0302', [`${SHOP_WEB_JAR}/log4j-core-2.17.0.jar`], '2025-12-08T14:31:09+09:00', { inUse: true }),
  jar('ast-1002', 'cmp-0305', [`${SHOP_WEB_JAR}/spring-core-6.1.5.jar`], '2026-04-14T21:42:17+09:00', { inUse: true }),
  jar('ast-1002', 'cmp-0309', [`${SHOP_WEB_JAR}/tomcat-embed-core-10.1.19.jar`], '2026-04-14T21:42:17+09:00', { inUse: true }),
  jar('ast-1002', 'cmp-0307', [`${SHOP_WEB_JAR}/jackson-databind-2.15.4.jar`], '2026-04-14T21:42:17+09:00', { inUse: true }),

  // ast-1003 dmz-proxy-01
  pkg('ast-1003', 'cmp-0101', DPKG, '2026-09-06T03:05:29+09:00', { inUse: true }),
  pkg('ast-1003', 'cmp-0102', DPKG, '2026-01-14T10:05:22+09:00', { removedAt: '2026-09-06T03:05:29+09:00' }),
  pkg('ast-1003', 'cmp-0103', DPKG, '2026-01-14T10:05:22+09:00', { inUse: true }),
  pkg('ast-1003', 'cmp-0106', DPKG, '2026-01-14T10:05:22+09:00', { inUse: true }),
  pkg('ast-1003', 'cmp-0107', DPKG, '2026-01-14T10:05:22+09:00'),
  pkg('ast-1003', 'cmp-0201', DPKG, '2026-01-14T10:05:22+09:00', { inUse: true }),
  gobin('ast-1003', 'cmp-0401', ['/usr/local/bin/metrics-agent'], '2026-01-14T10:05:22+09:00', { removedAt: '2026-08-21T14:40:03+09:00' }),
  gobin('ast-1003', 'cmp-0402', ['/usr/local/bin/metrics-agent'], '2026-08-21T14:40:03+09:00', { inUse: true }),
  gobin('ast-1003', 'cmp-0406', ['/usr/local/bin/metrics-agent'], '2026-01-14T10:05:22+09:00', { inUse: true }),

  // ast-1004 db-prd-01
  pkg('ast-1004', 'cmp-0151', RPMDB, '2026-10-14T22:31:50+09:00', { inUse: true }),
  pkg('ast-1004', 'cmp-0152', RPMDB, '2025-12-09T09:12:00+09:00', { removedAt: '2026-10-14T22:31:50+09:00' }),
  pkg('ast-1004', 'cmp-0153', RPMDB, '2025-12-09T09:12:00+09:00', { inUse: true }),
  pkg('ast-1004', 'cmp-0154', RPMDB, '2025-12-09T09:12:00+09:00', { inUse: true }),
  pkg('ast-1004', 'cmp-0206', RPMDB, '2025-12-09T09:12:00+09:00', { inUse: true }),
  gobin('ast-1004', 'cmp-0402', ['/usr/local/bin/postgres_exporter'], '2026-05-07T11:20:36+09:00', { inUse: true }),
  gobin('ast-1004', 'cmp-0406', ['/usr/local/bin/postgres_exporter'], '2026-05-07T11:20:36+09:00', { inUse: true }),

  // ast-1005 db-prd-02
  pkg('ast-1005', 'cmp-0161', RPMDB, '2025-12-09T09:40:31+09:00', { removedAt: '2026-10-14T22:48:05+09:00' }),
  pkg('ast-1005', 'cmp-0162', RPMDB, '2026-10-14T22:48:05+09:00', { inUse: true }),
  pkg('ast-1005', 'cmp-0163', RPMDB, '2025-12-09T09:40:31+09:00', { inUse: true }),
  pkg('ast-1005', 'cmp-0164', RPMDB, '2025-12-09T09:40:31+09:00', { inUse: true }),
  exec('ast-1005', 'cmp-0506', '/opt/redis/bin/redis-server', '/opt/redis/bin/redis-server --version', REDIS_RAW, '2025-12-09T09:40:31+09:00', { inUse: true }),
  gobin('ast-1005', 'cmp-0402', ['/usr/local/bin/redis_exporter'], '2026-05-07T11:31:12+09:00'),
  gobin('ast-1005', 'cmp-0406', ['/usr/local/bin/redis_exporter'], '2026-05-07T11:31:12+09:00'),

  // ast-1006 pay-was-01
  pkg('ast-1006', 'cmp-0141', RPMDB_BDB, '2026-02-03T16:22:10+09:00', { inUse: true }),
  pkg('ast-1006', 'cmp-0142', RPMDB_BDB, '2026-02-03T16:22:10+09:00', { inUse: true }),
  pkg('ast-1006', 'cmp-0143', RPMDB_BDB, '2026-02-03T16:22:10+09:00', { inUse: true }),
  exec('ast-1006', 'cmp-0502', '/home/jeus/jdk-11.0.20+8/bin/java', '/home/jeus/jdk-11.0.20+8/bin/java -version', JAVA11_RAW, '2026-02-03T16:22:10+09:00', { inUse: true }),
  jar('ast-1006', 'cmp-0701', ['/home/jeus/jeus8/lib/system/jeus.jar'], '2026-02-03T16:22:10+09:00', { inUse: true }),
  stat('ast-1006', 'cmp-0702', ['/home/webtob/webtob/bin/wsm'], '2026-02-03T16:22:10+09:00', { inUse: true }),
  jar('ast-1006', 'cmp-0301', [`${PAY_WAR}/log4j-core-2.14.1.jar`], '2026-02-03T16:22:10+09:00', { inUse: true }),
  jar('ast-1006', 'cmp-0303', [`${PAY_WAR}/spring-core-5.3.17.jar`], '2026-02-03T16:22:10+09:00', { inUse: true }),
  jar('ast-1006', 'cmp-0304', [`${PAY_WAR}/spring-beans-5.3.17.jar`], '2026-02-03T16:22:10+09:00', { inUse: true }),
  jar('ast-1006', 'cmp-0310', [`${PAY_WAR}/org.egovframe.rte.fdl.cmmn-4.0.0.jar`], '2026-02-03T16:22:10+09:00', { inUse: true }),
  jar('ast-1006', 'cmp-0306', [`${PAY_WAR}/jackson-databind-2.13.1.jar`], '2026-02-03T16:22:10+09:00', { inUse: true }),

  // ast-1007 pay-was-02
  pkg('ast-1007', 'cmp-0141', RPMDB_BDB, '2026-02-03T16:40:52+09:00', { inUse: true }),
  pkg('ast-1007', 'cmp-0142', RPMDB_BDB, '2026-02-03T16:40:52+09:00', { inUse: true }),
  pkg('ast-1007', 'cmp-0143', RPMDB_BDB, '2026-02-03T16:40:52+09:00', { inUse: true }),
  exec('ast-1007', 'cmp-0502', '/home/jeus/jdk-11.0.20+8/bin/java', '/home/jeus/jdk-11.0.20+8/bin/java -version', JAVA11_RAW, '2026-02-03T16:40:52+09:00', { inUse: true }),
  jar('ast-1007', 'cmp-0701', ['/home/jeus/jeus8/lib/system/jeus.jar'], '2026-02-03T16:40:52+09:00', { inUse: true }),
  stat('ast-1007', 'cmp-0702', ['/home/webtob/webtob/bin/wsm'], '2026-02-03T16:40:52+09:00', { inUse: true }),
  jar('ast-1007', 'cmp-0301', [`${PAY_WAR_2}/log4j-core-2.14.1.jar`], '2026-02-03T16:40:52+09:00', { removedAt: '2026-06-18T23:40:27+09:00' }),
  jar('ast-1007', 'cmp-0302', [`${PAY_WAR_2}/log4j-core-2.17.0.jar`], '2026-06-18T23:40:27+09:00', { inUse: true }),
  jar('ast-1007', 'cmp-0303', [`${PAY_WAR_2}/spring-core-5.3.17.jar`], '2026-02-03T16:40:52+09:00', { inUse: true }),
  jar('ast-1007', 'cmp-0304', [`${PAY_WAR_2}/spring-beans-5.3.17.jar`], '2026-02-03T16:40:52+09:00', { inUse: true }),
  jar('ast-1007', 'cmp-0310', [`${PAY_WAR_2}/org.egovframe.rte.fdl.cmmn-4.0.0.jar`], '2026-02-03T16:40:52+09:00', { inUse: true }),
  jar('ast-1007', 'cmp-0306', [`${PAY_WAR_2}/jackson-databind-2.13.1.jar`], '2026-02-03T16:40:52+09:00', { inUse: true }),

  // ast-1008 pay-db-01
  pkg('ast-1008', 'cmp-0141', RPMDB_BDB, '2026-02-04T11:03:27+09:00', { inUse: true }),
  pkg('ast-1008', 'cmp-0142', RPMDB_BDB, '2026-02-04T11:03:27+09:00', { inUse: true }),
  pkg('ast-1008', 'cmp-0143', RPMDB_BDB, '2026-02-04T11:03:27+09:00', { inUse: true }),
  stat('ast-1008', 'cmp-0703', ['/home/tibero/tibero7/bin/tbsvr', '/home/tibero/tibero7/bin/tbboot'], '2026-02-04T11:03:27+09:00', { inUse: true }),
  gobin('ast-1008', 'cmp-0402', ['/usr/local/bin/node_exporter'], '2026-05-07T11:44:50+09:00'),
  gobin('ast-1008', 'cmp-0406', ['/usr/local/bin/node_exporter'], '2026-05-07T11:44:50+09:00'),

  // ast-1009 dev-docker-01
  pkg('ast-1009', 'cmp-0111', DPKG, '2026-02-18T06:25:13+09:00', { inUse: true }),
  pkg('ast-1009', 'cmp-0112', DPKG, '2025-11-26T15:48:00+09:00', { inUse: true }),
  pkg('ast-1009', 'cmp-0113', DPKG, '2026-02-18T06:25:13+09:00', { inUse: true }),
  pkg('ast-1009', 'cmp-0114', DPKG, '2025-11-26T15:48:00+09:00'),
  pkg('ast-1009', 'cmp-0115', DPKG, '2025-11-26T15:48:00+09:00'),
  pkg('ast-1009', 'cmp-0116', DPKG, '2025-11-26T15:48:00+09:00', { removedAt: '2026-02-18T06:25:13+09:00' }),
  pkg('ast-1009', 'cmp-0117', DPKG, '2025-11-26T15:48:00+09:00', { removedAt: '2026-02-18T06:25:13+09:00' }),
  pkg('ast-1009', 'cmp-0202', DPKG, '2025-11-26T15:48:00+09:00', { inUse: true }),
  pkg('ast-1009', 'cmp-0203', DPKG, '2025-11-26T15:48:00+09:00', { inUse: true }),
  exec('ast-1009', 'cmp-0503', '/usr/local/bin/node', '/usr/local/bin/node --version', 'v20.11.0', '2026-01-29T10:14:52+09:00', { inUse: true }),
  gobin('ast-1009', 'cmp-0401', ['/usr/local/bin/deployctl'], '2025-11-26T15:48:00+09:00'),
  gobin('ast-1009', 'cmp-0403', ['/usr/local/bin/deployctl'], '2025-11-26T15:48:00+09:00'),
  gobin('ast-1009', 'cmp-0404', ['/usr/local/bin/deployctl'], '2025-11-26T15:48:00+09:00'),
  ...image('ast-1009', 'api-server', IMAGE.apiServer, '2026-07-15T17:33:02+09:00', { inUse: ['cmp-0503', 'cmp-0111', 'cmp-0113'] }),
  inContainer(gobin('ast-1009', 'cmp-0401', ['/tmp/grpcurl'], '2026-11-10T15:32:08+09:00'), 'api-server', 'runtime'),
  ...image('ast-1009', 'worker-1', IMAGE.worker, '2026-04-02T10:12:45+09:00', { inUse: ['cmp-0402', 'cmp-0406', 'cmp-0189'] }),
  ...image('ast-1009', 'worker-2', IMAGE.worker, '2026-04-02T10:12:45+09:00', { inUse: ['cmp-0402', 'cmp-0406', 'cmp-0189'] }),
  ...image('ast-1009', 'postgres-dev', IMAGE.postgres, '2026-02-26T14:50:31+09:00', { inUse: ['cmp-0507', 'cmp-0187', 'cmp-0189'] }),
  ...image('ast-1009', 'redis-dev', IMAGE.redis, '2026-10-02T09:15:39+09:00', { inUse: ['cmp-0506', 'cmp-0189'] }),

  // ast-1010 dev-build-01
  pkg('ast-1010', 'cmp-0121', DPKG, '2025-11-26T16:10:44+09:00', { inUse: true }),
  pkg('ast-1010', 'cmp-0122', DPKG, '2025-11-26T16:10:44+09:00', { inUse: true }),
  pkg('ast-1010', 'cmp-0123', DPKG, '2025-11-26T16:10:44+09:00', { inUse: true }),
  pkg('ast-1010', 'cmp-0124', DPKG, '2025-11-26T16:10:44+09:00'),
  pkg('ast-1010', 'cmp-0204', DPKG, '2026-06-10T15:02:31+09:00'),
  pkg('ast-1010', 'cmp-0205', DPKG, '2026-06-10T15:02:31+09:00', { inUse: true }),
  gobin('ast-1010', 'cmp-0401', ['/usr/local/bin/build-runner'], '2025-11-26T16:10:44+09:00', { inUse: true }),
  gobin('ast-1010', 'cmp-0403', ['/usr/local/bin/build-runner'], '2025-11-26T16:10:44+09:00', { inUse: true }),
  gobin('ast-1010', 'cmp-0405', ['/usr/local/bin/build-runner'], '2025-11-26T16:10:44+09:00', { inUse: true }),
  ...image('ast-1010', 'ci-runner-1', IMAGE.ciRunner, '2026-06-10T15:20:33+09:00', { inUse: ['cmp-0401', 'cmp-0403', 'cmp-0113'] }),
  inContainer(gobin('ast-1010', 'cmp-0405', ['/builds/.cache/bin/protoc-gen-go-grpc'], '2026-11-12T10:41:27+09:00'), 'ci-runner-1', 'runtime'),
  ...image('ast-1010', 'ci-runner-2', IMAGE.ciRunner, '2026-06-10T15:20:33+09:00', { inUse: ['cmp-0401', 'cmp-0403', 'cmp-0113'] }),
  ...image('ast-1010', 'ci-cache', IMAGE.redis, '2026-11-03T09:00:58+09:00', { inUse: ['cmp-0506', 'cmp-0189'] }),

  // ast-1011 it-wiki-01
  pkg('ast-1011', 'cmp-0131', RPMDB_BDB, '2025-12-15T10:31:18+09:00', { inUse: true }),
  pkg('ast-1011', 'cmp-0132', RPMDB_BDB, '2025-12-15T10:31:18+09:00'),
  pkg('ast-1011', 'cmp-0133', RPMDB_BDB, '2025-12-15T10:31:18+09:00', { inUse: true }),
  pkg('ast-1011', 'cmp-0134', RPMDB_BDB, '2025-12-15T10:31:18+09:00', { inUse: true }),
  exec('ast-1011', 'cmp-0505', '/usr/local/php/sbin/php-fpm', '/usr/local/php/sbin/php-fpm -v', PHP_FPM_RAW, '2025-12-15T10:31:18+09:00', { inUse: true }),
  exec('ast-1011', 'cmp-0506', '/usr/local/bin/redis-server', '/usr/local/bin/redis-server --version', REDIS_RAW, '2026-03-20T19:05:44+09:00', { inUse: true }),
  exec('ast-1011', 'cmp-0508', '/usr/local/nginx/sbin/nginx', '/usr/local/nginx/sbin/nginx -v', NGINX_RAW, '2025-12-15T10:31:18+09:00', { inUse: true }),

  // ast-1012 it-mon-01
  pkg('ast-1012', 'cmp-0171', RPMDB, '2025-12-15T11:02:55+09:00', { removedAt: '2026-11-02T10:22:16+09:00' }),
  pkg('ast-1012', 'cmp-0172', RPMDB, '2026-11-02T10:22:16+09:00', { inUse: true }),
  pkg('ast-1012', 'cmp-0173', RPMDB, '2025-12-15T11:02:55+09:00', { inUse: true }),
  pkg('ast-1012', 'cmp-0174', RPMDB, '2025-12-15T11:02:55+09:00', { inUse: true }),
  pkg('ast-1012', 'cmp-0175', RPMDB, '2026-08-27T16:48:30+09:00', { inUse: true }),
  pkg('ast-1012', 'cmp-0176', RPMDB, '2026-08-27T16:48:30+09:00', { inUse: true }),
  exec('ast-1012', 'cmp-0504', '/opt/node-v18.19.0-linux-x64/bin/node', '/opt/node-v18.19.0-linux-x64/bin/node --version', 'v18.19.0', '2025-12-15T11:02:55+09:00', { inUse: true }),
  gobin('ast-1012', 'cmp-0402', ['/usr/local/bin/metrics-gateway'], '2026-05-07T12:02:09+09:00', { inUse: true }),
  gobin('ast-1012', 'cmp-0406', ['/usr/local/bin/metrics-gateway'], '2026-05-07T12:02:09+09:00', { inUse: true }),
  ...image('ast-1012', 'metrics-exporter', IMAGE.metricsExporter, '2026-11-02T10:25:08+09:00', { inUse: ['cmp-0402', 'cmp-0406'] }),
  ...image('ast-1012', 'status-ui', IMAGE.statusUi, '2026-11-02T10:25:10+09:00', { inUse: ['cmp-0182', 'cmp-0184', 'cmp-0185', 'cmp-0191', 'cmp-0192'] }),
  ...image('ast-1012', 'alert-relay', IMAGE.worker, '2026-11-02T10:25:11+09:00', { inUse: ['cmp-0402', 'cmp-0406', 'cmp-0189'] }),

  // ast-1013 dev-api-01 (non-root)
  pkg('ast-1013', 'cmp-0111', DPKG, '2026-04-08T06:40:51+09:00'),
  pkg('ast-1013', 'cmp-0112', DPKG, '2026-03-11T13:27:40+09:00', { inUse: true }),
  pkg('ast-1013', 'cmp-0113', DPKG, '2026-04-08T06:40:51+09:00', { inUse: true }),
  pkg('ast-1013', 'cmp-0114', DPKG, '2026-03-11T13:27:40+09:00'),
  pkg('ast-1013', 'cmp-0115', DPKG, '2026-03-11T13:27:40+09:00'),
  pkg('ast-1013', 'cmp-0116', DPKG, '2026-03-11T13:27:40+09:00', { removedAt: '2026-04-08T06:40:51+09:00' }),
  pkg('ast-1013', 'cmp-0117', DPKG, '2026-03-11T13:27:40+09:00', { removedAt: '2026-04-08T06:40:51+09:00' }),
  exec('ast-1013', 'cmp-0503', '/home/svc-api/.local/node-v20.11.0/bin/node', '/home/svc-api/.local/node-v20.11.0/bin/node --version', 'v20.11.0', '2026-03-11T13:27:40+09:00', { inUse: true }),

  // ast-1014 pay-batch-01 (non-root)
  pkg('ast-1014', 'cmp-0151', RPMDB, '2026-04-22T10:15:09+09:00'),
  pkg('ast-1014', 'cmp-0153', RPMDB, '2026-04-22T10:15:09+09:00', { inUse: true }),
  pkg('ast-1014', 'cmp-0154', RPMDB, '2026-04-22T10:15:09+09:00', { inUse: true }),
  exec('ast-1014', 'cmp-0501', '/home/batch/jdk-17.0.8+7/bin/java', '/home/batch/jdk-17.0.8+7/bin/java -version', JAVA17_RAW, '2026-04-22T10:15:09+09:00', { inUse: true }),
  jar('ast-1014', 'cmp-0303', [`${BATCH_JAR}/spring-core-5.3.17.jar`], '2026-04-22T10:15:09+09:00', { inUse: true }),
  jar('ast-1014', 'cmp-0304', [`${BATCH_JAR}/spring-beans-5.3.17.jar`], '2026-04-22T10:15:09+09:00', { inUse: true }),
  jar('ast-1014', 'cmp-0306', [`${BATCH_JAR}/jackson-databind-2.13.1.jar`], '2026-04-22T10:15:09+09:00', { inUse: true }),
  jar('ast-1014', 'cmp-0302', [`${BATCH_JAR}/log4j-core-2.17.0.jar`], '2026-04-22T10:15:09+09:00', { inUse: true }),

  // ast-1015 dmz-relay-01
  pkg('ast-1015', 'cmp-0181', APKDB, '2026-05-19T15:40:12+09:00', { inUse: true }),
  pkg('ast-1015', 'cmp-0182', APKDB, '2026-05-19T15:40:12+09:00', { inUse: true }),
  pkg('ast-1015', 'cmp-0183', APKDB, '2026-05-19T15:40:12+09:00', { inUse: true }),
  pkg('ast-1015', 'cmp-0184', APKDB, '2026-05-19T15:40:12+09:00', { inUse: true }),
  pkg('ast-1015', 'cmp-0185', APKDB, '2026-06-30T10:12:48+09:00', { inUse: true }),
  gobin('ast-1015', 'cmp-0402', ['/usr/local/bin/metrics-agent'], '2026-08-21T14:52:20+09:00'),

  // ast-1016 legacy-erp-01 (SSH)
  pkg('ast-1016', 'cmp-0131', RPMDB_BDB, '2026-01-07T03:05:10+09:00', { inUse: true }),
  pkg('ast-1016', 'cmp-0132', RPMDB_BDB, '2026-01-07T03:05:10+09:00', { removedAt: '2026-03-02T03:05:22+09:00' }),
  pkg('ast-1016', 'cmp-0135', RPMDB_BDB, '2026-03-02T03:05:22+09:00'),
  pkg('ast-1016', 'cmp-0133', RPMDB_BDB, '2026-01-07T03:05:10+09:00', { inUse: true }),
  pkg('ast-1016', 'cmp-0134', RPMDB_BDB, '2026-01-07T03:05:10+09:00', { inUse: true }),
  exec('ast-1016', 'cmp-0502', '/opt/java/jdk-11.0.20+8/bin/java', '/opt/java/jdk-11.0.20+8/bin/java -version', JAVA11_RAW, '2026-01-07T03:05:10+09:00', { inUse: true }),
  jar('ast-1016', 'cmp-0301', ['/opt/erp/lib/log4j-core-2.14.1.jar'], '2026-01-07T03:05:10+09:00', { inUse: true }),

  // ast-1017 dmz-ftp-01 (SSH, sudo 없음)
  pkg('ast-1017', 'cmp-0121', DPKG, '2026-06-02T02:30:44+09:00'),
  pkg('ast-1017', 'cmp-0122', DPKG, '2026-06-02T02:30:44+09:00', { inUse: true }),
  pkg('ast-1017', 'cmp-0123', DPKG, '2026-06-02T02:30:44+09:00', { inUse: true }),
  pkg('ast-1017', 'cmp-0124', DPKG, '2026-06-02T02:30:44+09:00'),
  gobin('ast-1017', 'cmp-0401', ['/opt/sftpgw/bin/sftpgw'], '2026-06-02T02:30:44+09:00', { inUse: true }),
  gobin('ast-1017', 'cmp-0403', ['/opt/sftpgw/bin/sftpgw'], '2026-06-02T02:30:44+09:00', { inUse: true }),

  // ast-1019 it-exch-01 (WinRM)
  pkg('ast-1019', 'cmp-0602', 'C:\\Program Files\\Microsoft\\Exchange Server\\V15\\Bin\\ExSetup.exe', '2026-01-21T04:06:40+09:00', { inUse: true }),
  pkg('ast-1019', 'cmp-0603', 'HKLM\\SOFTWARE\\Microsoft\\InetStp', '2026-01-21T04:06:40+09:00', { inUse: true }),
  pkg('ast-1019', 'cmp-0604', 'C:\\Program Files\\dotnet\\shared\\Microsoft.NETCore.App\\8.0.6', '2026-01-21T04:06:40+09:00'),
  pkg('ast-1019', 'cmp-0605', 'HKLM\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full', '2026-01-21T04:06:40+09:00', { inUse: true }),
  pkg('ast-1019', 'cmp-0606', 'HKLM\\SOFTWARE\\Microsoft\\VisualStudio\\14.0\\VC\\Runtimes\\x64', '2026-01-21T04:06:40+09:00', { inUse: true }),
  pkg('ast-1019', 'cmp-0607', 'C:\\Program Files\\PowerShell\\7\\pwsh.exe', '2026-01-21T04:06:40+09:00'),

  // ast-1020 pay-mssql-01 (WinRM)
  pkg('ast-1020', 'cmp-0601', 'HKLM\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\MSSQL15.MSSQLSERVER\\Setup', '2026-02-10T04:14:18+09:00', { inUse: true }),
  pkg('ast-1020', 'cmp-0604', 'C:\\Program Files\\dotnet\\shared\\Microsoft.NETCore.App\\8.0.6', '2026-02-10T04:14:18+09:00'),
  pkg('ast-1020', 'cmp-0605', 'HKLM\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full', '2026-02-10T04:14:18+09:00', { inUse: true }),
  pkg('ast-1020', 'cmp-0606', 'HKLM\\SOFTWARE\\Microsoft\\VisualStudio\\14.0\\VC\\Runtimes\\x64', '2026-02-10T04:14:18+09:00', { inUse: true }),
  pkg('ast-1020', 'cmp-0607', 'C:\\Program Files\\PowerShell\\7\\pwsh.exe', '2026-02-10T04:14:18+09:00'),
  pkg('ast-1020', 'cmp-0608', 'HKLM\\SOFTWARE\\ODBC\\ODBCINST.INI\\ODBC Driver 17 for SQL Server', '2026-02-10T04:14:18+09:00', { inUse: true }),

  // ast-2001 shop/web-frontend
  ...image('ast-2001', 'web-frontend', IMAGE.webFrontend, '2026-03-04T10:00:21+09:00', { inUse: ['cmp-0123', 'cmp-0125', 'cmp-0504'] }),
  ...image('ast-2001', 'istio-proxy', IMAGE.istioProxy, '2026-03-04T10:00:21+09:00', { inUse: ISTIO_IN_USE }),

  // ast-2002 shop/order-api
  ...image('ast-2002', 'order-api', IMAGE.orderApi, '2026-03-04T10:00:21+09:00', {
    inUse: ['cmp-0113', 'cmp-0118', 'cmp-0501', 'cmp-0303', 'cmp-0304', 'cmp-0307', 'cmp-0308', 'cmp-0302'],
    since: { 'cmp-0111': '2026-08-25T15:10:37+09:00', 'cmp-0113': '2026-08-25T15:10:37+09:00', 'cmp-0307': '2026-08-25T15:10:37+09:00' },
  }),
  inContainer(pkg('ast-2002', 'cmp-0116', DPKG, '2026-03-04T10:00:21+09:00', { removedAt: '2026-08-25T15:10:37+09:00' }), 'order-api', 'image'),
  inContainer(pkg('ast-2002', 'cmp-0117', DPKG, '2026-03-04T10:00:21+09:00', { removedAt: '2026-08-25T15:10:37+09:00' }), 'order-api', 'image'),
  inContainer(jar('ast-2002', 'cmp-0306', [`${ORDER_JAR}/jackson-databind-2.13.1.jar`], '2026-03-04T10:00:21+09:00', { removedAt: '2026-08-25T15:10:37+09:00' }), 'order-api', 'image'),
  inContainer(jar('ast-2002', 'cmp-0311', ['/app/plugins/legacy-report-plugin.jar!/lib/snakeyaml-1.30.jar'], '2026-09-03T11:20:16+09:00', { inUse: true }), 'order-api', 'runtime'),

  // ast-2003 payment/payment-gw (프로세스만)
  ...image('ast-2003', 'payment-gw', IMAGE.paymentGw, '2026-03-04T10:00:21+09:00', { inUse: IMAGE.paymentGw.map((e) => e.componentId) }),
  ...image('ast-2003', 'istio-proxy', IMAGE.istioProxy, '2026-03-04T10:00:21+09:00', { inUse: ISTIO_IN_USE }),

  // ast-2004 data/redis
  ...image('ast-2004', 'redis', IMAGE.redis, '2026-03-04T10:00:21+09:00', { inUse: ['cmp-0189', 'cmp-0506'] }),

  // ast-2005 auth/auth-server
  ...image('ast-2005', 'auth-server', IMAGE.authServer, '2026-03-04T10:00:21+09:00', {
    inUse: ['cmp-0113', 'cmp-0501', 'cmp-0302', 'cmp-0309', 'cmp-0305', 'cmp-0307'],
    since: { 'cmp-0111': '2026-07-08T16:20:44+09:00', 'cmp-0113': '2026-07-08T16:20:44+09:00', 'cmp-0302': '2026-07-08T16:20:44+09:00' },
  }),
  inContainer(pkg('ast-2005', 'cmp-0116', DPKG, '2026-03-04T10:00:21+09:00', { removedAt: '2026-07-08T16:20:44+09:00' }), 'auth-server', 'image'),
  inContainer(pkg('ast-2005', 'cmp-0117', DPKG, '2026-03-04T10:00:21+09:00', { removedAt: '2026-07-08T16:20:44+09:00' }), 'auth-server', 'image'),
  inContainer(jar('ast-2005', 'cmp-0301', [`${AUTH_JAR}/log4j-core-2.14.1.jar`], '2026-03-04T10:00:21+09:00', { removedAt: '2026-07-08T16:20:44+09:00' }), 'auth-server', 'image'),
  inContainer(jar('ast-2005', 'cmp-0306', ['/app/ext/audit-appender.jar!/lib/jackson-databind-2.13.1.jar'], '2026-08-12T14:05:33+09:00', { inUse: true }), 'auth-server', 'runtime'),
  ...image('ast-2005', 'istio-proxy', IMAGE.istioProxy, '2026-03-04T10:00:21+09:00', { inUse: ISTIO_IN_USE }),

  // ast-2006 monitoring/metrics-exporter: 셸이 없어 수집하지 못함. 같은 digest를 it-mon-01에서 수집한 내용
  ...image('ast-2006', 'metrics-exporter', IMAGE.metricsExporter, '2026-11-02T10:25:08+09:00'),

  // ast-2007 dev-api/api-sandbox: exec 수집 미사용. 같은 digest를 dev-docker-01에서 수집한 내용
  ...image('ast-2007', 'api-server', IMAGE.apiServer, '2026-07-16T11:20:00+09:00'),

  // ast-2008 edge/ingress-proxy
  ...image('ast-2008', 'ingress-proxy', IMAGE.ingressProxy, '2026-05-27T09:45:13+09:00', {
    inUse: ['cmp-0182', 'cmp-0184', 'cmp-0185', 'cmp-0191', 'cmp-0192'],
    since: { 'cmp-0185': '2026-06-30T11:05:12+09:00' },
  }),
]
