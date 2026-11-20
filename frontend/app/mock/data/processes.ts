import type { ProcessInfo, ListenPort } from '~/types'

const SHA = {
  sshdNoble: '9280257b8dd750b54ad5cdd14784f94cc71d3a2c7304f2ab399b5dca9dce05e9',
  nginxNoble: '9b0ec2d9d63443234079d6382daa05c152f5c6487c527a7b45890ad3dc11d4c0',
  nginxOrg: '10ab4259955aa231a40c160807f7134956a0a2dc8db68503ae84307f88f812b2',
  java17: '892204995b498a87fb411f5422731b87ce3e2ed1f3eb88374fe0e730c4b32f2a',
  agent0100: 'cd9a67366398e2a5b58a72dabd3bc3f398fb1e33085225f4ac9b5f5194947806',
  metricsAgent: '1f679c61662502843dc03510cf380ab98caa88f62dba627c78a17be1bcdba163',
  sshdEl9: 'd214913b1a3b2cd32141fc49ad3f842fff2ded223350abf57ebe6ad36c501780',
  postgres16: 'a40c3388af9ffdf9b5d3437ddd779b3f16dce09996264c55a085784dc87f6d3a',
  pgExporter: '2f684218cb919de5fbe93b033a128d086ef07165d740aaed30f37865f0af41ad',
  sshdRockyOld: 'c4a62bfb0addc8e47b5b1c44441566899f9eea6326185b1b321e57392ea17f02',
  redis724: 'ddb2d6b131cf4421df0f062dae69aebcf279f7d662d6a5ad47ca3a068be5fe8a',
  sshdEl8: '21c11d2591d2eaa1e163a1a99340bad3af5178d0047a0648353b97f71c288cd5',
  java11: 'b574966b69d9852434bd464b43c721e4239ef2d28e1559e1f52c36b3222cbc91',
  wsm: 'f788fdb3dda0eb2bd939f889ae949b49bd7b44151bc80730846f75cb80bd1d77',
  tbsvr: '7e63e302deee3d5621658862cc3a7c0aadb7b41e700833daa1402737f9b1b3b0',
  sshdJammy: '077330820527bcabab8c77b84276ed8767a1b9785536d818ce4a5f8ca243e267',
  dockerd24: '354230799bd5463f8f24410dcc5a719f41972701fc9b008e2f4ed2332af6412c',
  containerd16: '9a9e379090eaedcce22cd0b4c39f11d314172944950b81d6e21de6174ccfe3a1',
  node20: '06a3e4ecbf610676184ca3ba63ca31c54402db0853120b7eb2be65e42409563e',
  kworker: '285adfb68bcf18777d4f7d83d914c30dcee40d169604fdd646dbadae217d0aac',
  workerGo: '28253c871720c15336ea0be4f103228cb9071b081c249987942d1fc693ae99fc',
  ciRunner: '851e25e0058f96294298acb5e1a87f185ad111bada950d76fcbf329a58238a8d',
  buildRunner: 'c5739fd1af14606e8507d2ab7c684236d04bd779c743fca9cc53decf5bb5c456',
  containerd17: 'e1d46da5eb09d8ced9cd09f08b268a68acd21086d756995307dcfad22c7ee1e9',
  sshdDeb12: '55c73d59da22b068a7674032788fb433f122c356e9fc71e323bf2d2a714cbe36',
  memfdPayload: '576aefee0fe006a61a3e7641efaee4996b64cc7350aa2cf807bee9e238b7f7c4',
  sshdEl7: 'a8e8144ea8e4f46ad181722bc08bf7701f0a147b2b46701f26827960d233d4a0',
  phpFpm: '87f612478138e8ec0d47fad87634481e88cb16ff3a1de27c17b297cdbaa062cd',
  nginx1221: '4a8dea1232f52cafe7cd0ac33f91c2bf6739d671cac3f498edc114b122870684',
  dbusHelper: '02153bdaff160285f7c26dcbceaffb6a86d8912f4a473bef2ed2da5a1b48d5be',
  crondEl7: '2551e074b6317fc3f024abb3c00378a7bfd60ce26ce3406ecd9fbe12d21feeaf',
  sshdAl2023: 'e7f282844ee40ba1880b9433e62cdde348de23b5aac72ed4ffdb317e33b2d1d1',
  node18: '626fe876672898f699a0e669c7ddeb7847e3ecf5d4784dba7c7ead85b8f52eb2',
  metricsGateway: '1721fcfa39f36f1f386e66e6b4af01a5243609880d5d47598e7847015cc655c3',
  dockerdAl: 'ddb5f3c73069cb977a9ec64b785e7fc434e6b8908de52aac762ed45b61b6b1a6',
  containerdAl: '46e7e16662a3a25734f5397d71d6a2ac734e72f36af14602a0f14c9a343b41f3',
  monitorUi: '31df522d652bf97d9cd8a25c4f5a74bc66b30bc47feecf4c3a3eda63a6f0eda7',
  sshdAlpine: 'f75b884619951b90aa450c18d867c26edade9672b5c119454fada0f5f7cab233',
  nginxAlpine: 'f14bd9d4b7fe8e931de5b0482036a7f9ab07d8470ad2d7f9d73c34c1ce935b3c',
  w3wp: '9d3ab4a257b6561029a9ef8178d791da0f746620aedf2a2158222e9054651576',
  exFrontend: 'b50b3a92fba9425a44517cab90862e24d5149e1ef93ae6efba701a66122b327b',
  edgeTransport: '8cbaa9ca5b991bc7345bfa66e511e0a98ea8aa551f0e0a42c0c8bfefe1f17c36',
  sqlservr: '752252d2fb7e303ca5c12d1cb47bcdac098378e82b627f07be7f7f5d5d33cdc8',
  sqlagent: '3cc3ad6f4d8a6916addd3e4e3ae7136e9c3042b0f904f45c3f3a290f9c512efc',
  node18Img: 'e95e96d8f89cbd66e60a5eb5b4386f50e6563d7fc0cdf703236cc07c2e22b073',
  java17Img: '0d7615d072c9403e6c6c5dea64b79924d2e88f9a97b8b4a574988f9a321e6847',
  paymentGw: 'a60205c7660dfd90cfe9687f22d3528a47737c06f7414f0c775db2fd22ea2095',
  redisImg: '63c76f48929ca265112a0ff3e7e663c1b419459c181882f52758f6e1111b181f',
  nginxAlpineImg: '1a1e64420ea50520d0d47cb6d206b375f00924e7d62e44add877eb95db21c9c8',
  node20Img: '0bfbe35113f7bb9c7f7802f1c667453970326be6e6333631e578e3f72339284a',
  postgres156: '7ad6621941a5941f6e1e999f49f8d38176262999eb2fac407bc8e02421418e37',
  envoy: 'eb57224ca2781abb637414069fc5edfa498d3d6dd05703f8495c40003cf14af6',
  metricsExporter: 'f5b7dfc6f8d2b64f2cc48ed57e329e7a5a2a39f57c5735599f9f7e2084b57cf6',
}

const tcp = (address: string, port: number): ListenPort => ({ proto: 'tcp', address, port })
const SSH_LISTEN = [tcp('0.0.0.0', 22), tcp('::', 22)]
const SSHD_CMD = 'sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups'

type Rest = Partial<Pick<ProcessInfo, 'sha256' | 'exeState' | 'deletedLibs' | 'listen' | 'container' | 'componentId' | 'exeSource'>>

function p(id: string, assetId: string, pid: number, user: string, exePath: string, cmdline: string, startedAt: string, rest: Rest = {}): ProcessInfo {
  return {
    id,
    assetId,
    pid,
    user,
    exePath,
    exeSource: rest.exeSource ?? 'proc',
    sha256: rest.sha256,
    cmdline,
    startedAt,
    exeState: rest.exeState ?? 'normal',
    deletedLibs: rest.deletedLibs ?? [],
    listen: rest.listen ?? [],
    container: rest.container,
    componentId: rest.componentId,
  }
}

// 권한이 없어 /proc/<pid>/exe를 읽지 못한 다른 사용자의 프로세스
function seen(id: string, assetId: string, pid: number, user: string, exePath: string, cmdline: string, startedAt: string, componentId?: string): ProcessInfo {
  return p(id, assetId, pid, user, exePath, cmdline, startedAt, { exeSource: 'cmdline', componentId })
}

const NOBLE_SSL_REPLACED: ProcessInfo['deletedLibs'] = [
  { path: '/usr/lib/x86_64-linux-gnu/libssl.so.3', state: 'replaced' },
  { path: '/usr/lib/x86_64-linux-gnu/libcrypto.so.3', state: 'replaced' },
]

export const processes: ProcessInfo[] = [
  // ast-1001 web-prd-01
  p('prc-0001', 'ast-1001', 1123, 'root', '/usr/sbin/sshd', SSHD_CMD, '2026-09-10T04:02:11+09:00', { sha256: SHA.sshdNoble, listen: SSH_LISTEN, componentId: 'cmp-0103' }),
  p('prc-0002', 'ast-1001', 1388, 'root', '/usr/sbin/nginx', 'nginx: master process /usr/sbin/nginx -g daemon on; master_process on;', '2026-08-14T02:10:05+09:00', {
    sha256: SHA.nginxNoble,
    deletedLibs: NOBLE_SSL_REPLACED,
    listen: [tcp('0.0.0.0', 80), tcp('0.0.0.0', 443), tcp('::', 443)],
    componentId: 'cmp-0104',
  }),
  p('prc-0003', 'ast-1001', 1390, 'www-data', '/usr/sbin/nginx', 'nginx: worker process', '2026-08-14T02:10:05+09:00', { sha256: SHA.nginxNoble, deletedLibs: NOBLE_SSL_REPLACED, componentId: 'cmp-0104' }),
  p('prc-0004', 'ast-1001', 2211, 'appuser', '/opt/jdk-17.0.8+7/bin/java', '/opt/jdk-17.0.8+7/bin/java -Xms2g -Xmx2g -jar /srv/shop-web/shop-web.jar --spring.profiles.active=prod --spring.datasource.password=****', '2026-10-30T21:15:44+09:00', {
    sha256: SHA.java17,
    listen: [tcp('127.0.0.1', 8080), tcp('127.0.0.1', 8081)],
    componentId: 'cmp-0501',
  }),
  p('prc-0005', 'ast-1001', 902, 'bomcensus', '/opt/bomcensus/bin/bomcensus-agent', '/opt/bomcensus/bin/bomcensus-agent --config /etc/bomcensus/agent.yaml', '2026-11-12T03:30:02+09:00', { sha256: SHA.agent0100 }),

  // ast-1002 web-prd-02
  p('prc-0006', 'ast-1002', 1104, 'root', '/usr/sbin/sshd', SSHD_CMD, '2026-09-10T04:05:37+09:00', { sha256: SHA.sshdNoble, listen: SSH_LISTEN, componentId: 'cmp-0103' }),
  p('prc-0007', 'ast-1002', 1402, 'root', '/usr/sbin/nginx', 'nginx: master process /usr/sbin/nginx -g daemon on; master_process on;', '2026-07-30T03:00:12+09:00', {
    sha256: SHA.nginxNoble,
    deletedLibs: NOBLE_SSL_REPLACED,
    listen: [tcp('0.0.0.0', 80), tcp('0.0.0.0', 443), tcp('::', 443)],
    componentId: 'cmp-0104',
  }),
  p('prc-0008', 'ast-1002', 2245, 'appuser', '/opt/jdk-17.0.8+7/bin/java', '/opt/jdk-17.0.8+7/bin/java -Xms2g -Xmx2g -jar /srv/shop-web/shop-web.jar --spring.profiles.active=prod --spring.datasource.password=****', '2026-10-30T21:22:09+09:00', {
    sha256: SHA.java17,
    listen: [tcp('127.0.0.1', 8080), tcp('127.0.0.1', 8081)],
    componentId: 'cmp-0501',
  }),

  // ast-1003 dmz-proxy-01
  p('prc-0009', 'ast-1003', 998, 'root', '/usr/sbin/sshd', SSHD_CMD, '2026-09-06T03:10:44+09:00', { sha256: SHA.sshdNoble, listen: [tcp('172.16.10.21', 22)], componentId: 'cmp-0103' }),
  p('prc-0010', 'ast-1003', 1530, 'root', '/usr/sbin/nginx', 'nginx: master process /usr/sbin/nginx -c /etc/nginx/nginx.conf', '2026-08-21T14:45:30+09:00', {
    sha256: SHA.nginxOrg,
    deletedLibs: NOBLE_SSL_REPLACED,
    listen: [tcp('0.0.0.0', 80), tcp('0.0.0.0', 443), tcp('::', 443)],
    componentId: 'cmp-0201',
  }),
  p('prc-0011', 'ast-1003', 1488, 'nobody', '/usr/local/bin/metrics-agent', '/usr/local/bin/metrics-agent --listen=:9100 --collector.systemd', '2026-08-21T14:40:09+09:00', {
    sha256: SHA.metricsAgent,
    listen: [tcp('::', 9100)],
    componentId: 'cmp-0402',
  }),

  // ast-1004 db-prd-01
  p('prc-0012', 'ast-1004', 40211, 'root', '/usr/sbin/sshd', SSHD_CMD, '2026-10-14T22:40:18+09:00', { sha256: SHA.sshdEl9, listen: SSH_LISTEN, componentId: 'cmp-0154' }),
  p('prc-0013', 'ast-1004', 1877, 'postgres', '/usr/pgsql-16/bin/postgres', '/usr/pgsql-16/bin/postgres -D /var/lib/pgsql/16/data/', '2026-06-02T05:12:31+09:00', {
    sha256: SHA.postgres16,
    deletedLibs: [
      { path: '/usr/lib64/libssl.so.3.0.7', state: 'replaced' },
      { path: '/usr/lib64/libcrypto.so.3.0.7', state: 'replaced' },
    ],
    listen: [tcp('0.0.0.0', 5432), tcp('::', 5432)],
    componentId: 'cmp-0206',
  }),
  p('prc-0014', 'ast-1004', 40388, 'postgres_exporter', '/usr/local/bin/postgres_exporter', '/usr/local/bin/postgres_exporter --web.listen-address=127.0.0.1:9187 --extend.query-path=/etc/postgres_exporter/queries.yaml', '2026-10-14T22:41:02+09:00', {
    sha256: SHA.pgExporter,
    listen: [tcp('127.0.0.1', 9187)],
    componentId: 'cmp-0402',
  }),

  // ast-1005 db-prd-02
  p('prc-0015', 'ast-1005', 1052, 'root', '/usr/sbin/sshd', SSHD_CMD, '2026-04-11T08:20:15+09:00', {
    sha256: SHA.sshdRockyOld,
    exeState: 'replaced',
    listen: SSH_LISTEN,
    componentId: 'cmp-0161',
  }),
  p('prc-0016', 'ast-1005', 1320, 'redis', '/opt/redis/bin/redis-server', '/opt/redis/bin/redis-server 10.20.1.12:6379', '2026-03-28T19:40:00+09:00', {
    sha256: SHA.redis724,
    listen: [tcp('10.20.1.12', 6379)],
    componentId: 'cmp-0506',
  }),

  // ast-1006 pay-was-01
  p('prc-0017', 'ast-1006', 1201, 'root', '/usr/sbin/sshd', SSHD_CMD, '2026-02-03T15:58:40+09:00', { sha256: SHA.sshdEl8, listen: SSH_LISTEN, componentId: 'cmp-0143' }),
  p('prc-0018', 'ast-1006', 30112, 'jeus', '/home/jeus/jdk-11.0.20+8/bin/java', '/home/jeus/jdk-11.0.20+8/bin/java -server -Xms1g -Xmx1g -Djeus.home=/home/jeus/jeus8 -Djeus.domain.name=pay_domain -Djeus.server.name=adminServer jeus.server.admin.DomainAdminServerBootstrapper -u administrator -p ****', '2026-10-25T06:10:41+09:00', {
    sha256: SHA.java11,
    listen: [tcp('0.0.0.0', 9736)],
    componentId: 'cmp-0502',
  }),
  p('prc-0019', 'ast-1006', 30455, 'jeus', '/home/jeus/jdk-11.0.20+8/bin/java', '/home/jeus/jdk-11.0.20+8/bin/java -server -Xms4g -Xmx4g -Djeus.home=/home/jeus/jeus8 -Djeus.domain.name=pay_domain -Djeus.server.name=server1 jeus.server.ServerBootstrapper -u administrator -p ****', '2026-10-25T06:12:03+09:00', {
    sha256: SHA.java11,
    listen: [tcp('0.0.0.0', 8088), tcp('0.0.0.0', 9741)],
    componentId: 'cmp-0502',
  }),
  p('prc-0020', 'ast-1006', 29870, 'webtob', '/home/webtob/webtob/bin/wsm', 'wsm -l /home/webtob/webtob/config/wsconfig', '2026-10-25T06:05:12+09:00', {
    sha256: SHA.wsm,
    listen: [tcp('0.0.0.0', 80), tcp('0.0.0.0', 443), tcp('0.0.0.0', 9999)],
    componentId: 'cmp-0702',
  }),

  // ast-1007 pay-was-02
  p('prc-0021', 'ast-1007', 1188, 'root', '/usr/sbin/sshd', SSHD_CMD, '2026-02-03T16:31:22+09:00', { sha256: SHA.sshdEl8, listen: SSH_LISTEN, componentId: 'cmp-0143' }),
  p('prc-0022', 'ast-1007', 41877, 'jeus', '/home/jeus/jdk-11.0.20+8/bin/java', '/home/jeus/jdk-11.0.20+8/bin/java -server -Xms4g -Xmx4g -Djeus.home=/home/jeus/jeus8 -Djeus.domain.name=pay_domain -Djeus.server.name=server2 jeus.server.ServerBootstrapper -u administrator -p ****', '2026-06-18T23:45:10+09:00', {
    sha256: SHA.java11,
    listen: [tcp('0.0.0.0', 8088), tcp('0.0.0.0', 9741)],
    componentId: 'cmp-0502',
  }),
  p('prc-0023', 'ast-1007', 41502, 'webtob', '/home/webtob/webtob/bin/wsm', 'wsm -l /home/webtob/webtob/config/wsconfig', '2026-06-18T23:42:55+09:00', {
    sha256: SHA.wsm,
    listen: [tcp('0.0.0.0', 80), tcp('0.0.0.0', 443), tcp('0.0.0.0', 9999)],
    componentId: 'cmp-0702',
  }),

  // ast-1008 pay-db-01
  p('prc-0024', 'ast-1008', 1166, 'root', '/usr/sbin/sshd', SSHD_CMD, '2026-02-04T10:50:09+09:00', { sha256: SHA.sshdEl8, listen: SSH_LISTEN, componentId: 'cmp-0143' }),
  p('prc-0025', 'ast-1008', 5120, 'tibero', '/home/tibero/tibero7/bin/tbsvr', 'tbsvr -t NORMAL -SVR_SID tibero', '2026-09-27T02:00:31+09:00', {
    sha256: SHA.tbsvr,
    listen: [tcp('0.0.0.0', 8629)],
    componentId: 'cmp-0703',
  }),
  p('prc-0026', 'ast-1008', 5133, 'tibero', '/home/tibero/tibero7/bin/tbsvr', 'tbsvr_FGWP000 -t NORMAL -SVR_SID tibero', '2026-09-27T02:00:33+09:00', { sha256: SHA.tbsvr, componentId: 'cmp-0703' }),

  // ast-1009 dev-docker-01
  p('prc-0027', 'ast-1009', 1012, 'root', '/usr/sbin/sshd', SSHD_CMD, '2026-02-18T06:30:02+09:00', { sha256: SHA.sshdJammy, listen: SSH_LISTEN, componentId: 'cmp-0112' }),
  p('prc-0028', 'ast-1009', 1240, 'root', '/usr/bin/dockerd', '/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock', '2026-02-18T06:30:15+09:00', { sha256: SHA.dockerd24, componentId: 'cmp-0202' }),
  p('prc-0029', 'ast-1009', 1105, 'root', '/usr/bin/containerd', '/usr/bin/containerd', '2026-02-18T06:30:08+09:00', { sha256: SHA.containerd16, componentId: 'cmp-0203' }),
  p('prc-0030', 'ast-1009', 88410, 'dev', '/usr/local/bin/node', 'node /home/dev/tools/mock-server.js --port 3000', '2026-11-14T10:22:47+09:00', {
    sha256: SHA.node20,
    listen: [tcp('0.0.0.0', 3000)],
    componentId: 'cmp-0503',
  }),
  p('prc-0031', 'ast-1009', 97733, 'nobody', '/tmp/.x/kworker', '[kworker/0:2-events]', '2026-11-18T02:14:55+09:00', { sha256: SHA.kworker, exeState: 'deleted' }),
  p('prc-0032', 'ast-1009', 15520, 'node', '/usr/local/bin/node', 'node dist/server.js', '2026-11-04T13:40:18+09:00', { sha256: SHA.node20Img, listen: [tcp('0.0.0.0', 8080)], container: 'api-server', componentId: 'cmp-0503' }),
  p('prc-0033', 'ast-1009', 15802, 'app', '/app/worker', '/app/worker --queue=jobs --concurrency=4', '2026-11-04T13:40:22+09:00', { sha256: SHA.workerGo, container: 'worker-1', componentId: 'cmp-0402' }),
  p('prc-0034', 'ast-1009', 15911, 'postgres', '/usr/local/bin/postgres', 'postgres', '2026-10-02T09:15:40+09:00', { sha256: SHA.postgres156, listen: [tcp('0.0.0.0', 5432)], container: 'postgres-dev', componentId: 'cmp-0507' }),

  p('prc-0080', 'ast-1009', 15805, 'app', '/app/worker', '/app/worker --queue=jobs --concurrency=4', '2026-11-04T13:40:23+09:00', { sha256: SHA.workerGo, container: 'worker-2', componentId: 'cmp-0402' }),
  p('prc-0081', 'ast-1009', 15930, 'redis', '/usr/local/bin/redis-server', 'redis-server *:6379', '2026-10-02T09:15:41+09:00', {
    sha256: SHA.redisImg,
    listen: [tcp('0.0.0.0', 6379)],
    container: 'redis-dev',
    componentId: 'cmp-0506',
  }),

  // ast-1010 dev-build-01
  p('prc-0035', 'ast-1010', 788, 'root', '/usr/sbin/sshd', SSHD_CMD, '2026-06-10T15:10:00+09:00', { sha256: SHA.sshdDeb12, listen: SSH_LISTEN, componentId: 'cmp-0122' }),
  p('prc-0036', 'ast-1010', 802, 'root', '/usr/bin/containerd', '/usr/bin/containerd', '2026-06-10T15:10:02+09:00', { sha256: SHA.containerd17, componentId: 'cmp-0205' }),
  p('prc-0037', 'ast-1010', 1350, 'ci', '/usr/local/bin/build-runner', '/usr/local/bin/build-runner serve --listen=0.0.0.0:7070 --token=****', '2026-11-03T09:00:12+09:00', {
    sha256: SHA.buildRunner,
    listen: [tcp('0.0.0.0', 7070)],
    componentId: 'cmp-0401',
  }),
  p('prc-0038', 'ast-1010', 22410, 'root', '/usr/local/bin/ci-runner', 'ci-runner run --working-directory=/builds --config=/etc/ci-runner/config.toml', '2026-11-03T09:01:44+09:00', { sha256: SHA.ciRunner, container: 'ci-runner-1', componentId: 'cmp-0401' }),
  p('prc-0039', 'ast-1010', 61208, 'ci', '/memfd:x (deleted)', 'kdevtmpfsi', '2026-11-19T23:41:07+09:00', { sha256: SHA.memfdPayload, exeState: 'memfd' }),

  p('prc-0082', 'ast-1010', 22433, 'root', '/usr/local/bin/ci-runner', 'ci-runner run --working-directory=/builds --config=/etc/ci-runner/config.toml', '2026-11-03T09:01:45+09:00', { sha256: SHA.ciRunner, container: 'ci-runner-2', componentId: 'cmp-0401' }),
  p('prc-0083', 'ast-1010', 22105, 'redis', '/usr/local/bin/redis-server', 'redis-server *:6379 --maxmemory 2gb', '2026-11-03T09:01:00+09:00', {
    sha256: SHA.redisImg,
    listen: [tcp('0.0.0.0', 6379)],
    container: 'ci-cache',
    componentId: 'cmp-0506',
  }),

  // ast-1011 it-wiki-01
  p('prc-0040', 'ast-1011', 1090, 'root', '/usr/sbin/sshd', '/usr/sbin/sshd -D', '2026-01-12T22:05:31+09:00', { sha256: SHA.sshdEl7, listen: SSH_LISTEN, componentId: 'cmp-0133' }),
  p('prc-0041', 'ast-1011', 1302, 'root', '/usr/local/nginx/sbin/nginx', 'nginx: master process /usr/local/nginx/sbin/nginx -c /usr/local/nginx/conf/nginx.conf', '2026-01-12T22:05:40+09:00', {
    sha256: SHA.nginx1221,
    listen: [tcp('0.0.0.0', 80), tcp('0.0.0.0', 443)],
    componentId: 'cmp-0508',
  }),
  p('prc-0042', 'ast-1011', 1288, 'root', '/usr/local/php/sbin/php-fpm', 'php-fpm: master process (/usr/local/php/etc/php-fpm.conf)', '2026-01-12T22:05:38+09:00', {
    sha256: SHA.phpFpm,
    listen: [tcp('127.0.0.1', 9000)],
    componentId: 'cmp-0505',
  }),
  p('prc-0043', 'ast-1011', 1291, 'nobody', '/usr/local/php/sbin/php-fpm', 'php-fpm: pool www', '2026-01-12T22:05:38+09:00', { sha256: SHA.phpFpm, componentId: 'cmp-0505' }),
  p('prc-0044', 'ast-1011', 1155, 'redis', '/usr/local/bin/redis-server', '/usr/local/bin/redis-server 127.0.0.1:6379', '2026-03-20T19:06:02+09:00', {
    sha256: SHA.redis724,
    listen: [tcp('127.0.0.1', 6379)],
    componentId: 'cmp-0506',
  }),
  p('prc-0045', 'ast-1011', 24817, 'nobody', '/var/tmp/.cache/dbus-helper', '/var/tmp/.cache/dbus-helper -c /var/tmp/.cache/config.json -B', '2026-10-21T03:33:18+09:00', { sha256: SHA.dbusHelper, exeState: 'deleted' }),
  p('prc-0046', 'ast-1011', 24850, 'root', '/usr/sbin/crond', 'crond -n', '2026-10-21T03:35:02+09:00', {
    sha256: SHA.crondEl7,
    deletedLibs: [{ path: '/dev/shm/.l/libsystem.so', state: 'deleted' }],
  }),

  // ast-1012 it-mon-01
  p('prc-0047', 'ast-1012', 51022, 'root', '/usr/sbin/sshd', SSHD_CMD, '2026-11-02T10:30:14+09:00', { sha256: SHA.sshdAl2023, listen: SSH_LISTEN, componentId: 'cmp-0174' }),
  p('prc-0048', 'ast-1012', 3318, 'svc-mon', '/opt/node-v18.19.0-linux-x64/bin/node', 'node /srv/status-board/server.js --port=8443', '2026-09-18T14:05:51+09:00', {
    sha256: SHA.node18,
    deletedLibs: [
      { path: '/usr/lib64/libc.so.6', state: 'replaced' },
      { path: '/usr/lib64/libm.so.6', state: 'replaced' },
    ],
    listen: [tcp('0.0.0.0', 8443)],
    componentId: 'cmp-0504',
  }),
  p('prc-0049', 'ast-1012', 51130, 'nobody', '/usr/local/bin/metrics-gateway', '/usr/local/bin/metrics-gateway --web.listen-address=:9091', '2026-11-02T10:31:05+09:00', {
    sha256: SHA.metricsGateway,
    listen: [tcp('::', 9091)],
    componentId: 'cmp-0402',
  }),
  p('prc-0050', 'ast-1012', 50990, 'root', '/usr/bin/dockerd', '/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock', '2026-11-02T10:24:40+09:00', { sha256: SHA.dockerdAl, componentId: 'cmp-0175' }),
  p('prc-0051', 'ast-1012', 50961, 'root', '/usr/bin/containerd', '/usr/bin/containerd', '2026-11-02T10:24:31+09:00', { sha256: SHA.containerdAl, componentId: 'cmp-0176' }),
  p('prc-0052', 'ast-1012', 51402, 'root', '/usr/sbin/nginx', 'nginx: master process nginx -g daemon off;', '2026-11-02T10:25:12+09:00', { sha256: SHA.monitorUi, listen: [tcp('0.0.0.0', 8080)], container: 'status-ui', componentId: 'cmp-0185' }),

  p('prc-0084', 'ast-1012', 51410, 'nonroot', '/bin/metrics-exporter', '/bin/metrics-exporter --web.listen-address=:9100', '2026-11-02T10:25:09+09:00', {
    sha256: SHA.metricsExporter,
    listen: [tcp('0.0.0.0', 9100)],
    container: 'metrics-exporter',
    componentId: 'cmp-0402',
  }),
  p('prc-0085', 'ast-1012', 51425, 'app', '/app/worker', '/app/worker --queue=alerts --concurrency=1', '2026-11-02T10:25:12+09:00', { sha256: SHA.workerGo, container: 'alert-relay', componentId: 'cmp-0402' }),

  // ast-1013 dev-api-01 (non-root, svc-api)
  seen('prc-0053', 'ast-1013', 1021, 'root', '/usr/sbin/sshd', SSHD_CMD, '2026-04-08T06:45:10+09:00', 'cmp-0112'),
  seen('prc-0054', 'ast-1013', 1003, 'root', '/usr/sbin/cron', '/usr/sbin/cron -f -P', '2026-04-08T06:45:02+09:00'),
  seen('prc-0055', 'ast-1013', 1410, 'postgres', '/usr/lib/postgresql/14/bin/postgres', '/usr/lib/postgresql/14/bin/postgres -D /var/lib/postgresql/14/main -c config_file=/etc/postgresql/14/main/postgresql.conf', '2026-04-08T06:45:20+09:00'),
  p('prc-0056', 'ast-1013', 7762, 'svc-api', '/home/svc-api/.local/node-v20.11.0/bin/node', 'node /home/svc-api/app/dist/main.js', '2026-11-16T11:03:29+09:00', {
    sha256: SHA.node20,
    listen: [tcp('0.0.0.0', 3000)],
    componentId: 'cmp-0503',
  }),
  p('prc-0057', 'ast-1013', 7540, 'svc-api', '/home/svc-api/.local/bomcensus/bin/bomcensus-agent', '/home/svc-api/.local/bomcensus/bin/bomcensus-agent --config /home/svc-api/.config/bomcensus/agent.yaml', '2026-11-12T03:31:40+09:00', { sha256: SHA.agent0100 }),

  // ast-1014 pay-batch-01 (non-root, batch)
  seen('prc-0058', 'ast-1014', 1077, 'root', '/usr/sbin/sshd', SSHD_CMD, '2026-04-22T09:58:12+09:00', 'cmp-0154'),
  seen('prc-0059', 'ast-1014', 1060, 'root', '/usr/sbin/crond', '/usr/sbin/crond -n', '2026-04-22T09:58:05+09:00'),
  p('prc-0060', 'ast-1014', 66120, 'batch', '/home/batch/jdk-17.0.8+7/bin/java', '/home/batch/jdk-17.0.8+7/bin/java -Xmx3g -jar /home/batch/app/settlement-batch.jar --job.name=dailySettlement --db.password=****', '2026-11-17T22:00:01+09:00', {
    sha256: SHA.java17,
    componentId: 'cmp-0501',
  }),

  // ast-1015 dmz-relay-01
  p('prc-0061', 'ast-1015', 2210, 'root', '/usr/sbin/sshd', 'sshd: /usr/sbin/sshd [listener] 0 of 10-100 startups', '2026-06-30T10:15:22+09:00', { sha256: SHA.sshdAlpine, listen: [tcp('172.16.10.31', 22)], componentId: 'cmp-0181' }),
  p('prc-0062', 'ast-1015', 2302, 'root', '/usr/sbin/nginx', 'nginx: master process /usr/sbin/nginx -c /etc/nginx/nginx.conf', '2026-06-30T10:15:30+09:00', {
    sha256: SHA.nginxAlpine,
    listen: [tcp('0.0.0.0', 443), tcp('::', 443)],
    componentId: 'cmp-0185',
  }),
  p('prc-0063', 'ast-1015', 2303, 'nginx', '/usr/sbin/nginx', 'nginx: worker process', '2026-06-30T10:15:30+09:00', { sha256: SHA.nginxAlpine, componentId: 'cmp-0185' }),

  // ast-1016 legacy-erp-01 (SSH)
  p('prc-0064', 'ast-1016', 1131, 'root', '/usr/sbin/sshd', '/usr/sbin/sshd -D', '2026-03-02T03:20:11+09:00', { sha256: SHA.sshdEl7, listen: SSH_LISTEN, componentId: 'cmp-0133' }),
  p('prc-0065', 'ast-1016', 2877, 'erp', '/opt/java/jdk-11.0.20+8/bin/java', '/opt/java/jdk-11.0.20+8/bin/java -Xmx6g -Dlog4j.configurationFile=/opt/erp/conf/log4j2.xml -jar /opt/erp/erp-server.jar --db.password=****', '2026-03-02T03:22:47+09:00', {
    sha256: SHA.java11,
    listen: [tcp('0.0.0.0', 8443)],
    componentId: 'cmp-0502',
  }),

  // ast-1017 dmz-ftp-01 (SSH, sudo 없음)
  seen('prc-0066', 'ast-1017', 655, 'root', '/usr/sbin/sshd', SSHD_CMD, '2026-08-11T02:40:00+09:00', 'cmp-0122'),
  seen('prc-0067', 'ast-1017', 1402, 'sftpgw', '/opt/sftpgw/bin/sftpgw', '/opt/sftpgw/bin/sftpgw --config /etc/sftpgw/sftpgw.yaml', '2026-08-11T02:40:12+09:00', 'cmp-0401'),

  // ast-1019 it-exch-01 (WinRM)
  p('prc-0068', 'ast-1019', 7412, 'IIS APPPOOL\\MSExchangeOWAAppPool', 'C:\\Windows\\System32\\inetsrv\\w3wp.exe', 'c:\\windows\\system32\\inetsrv\\w3wp.exe -ap "MSExchangeOWAAppPool" -v "v4.0" -h "C:\\inetpub\\temp\\apppools\\MSExchangeOWAAppPool\\MSExchangeOWAAppPool.config"', '2026-11-16T04:12:40+09:00', {
    sha256: SHA.w3wp,
    listen: [tcp('0.0.0.0', 443), tcp('::', 443)],
    componentId: 'cmp-0603',
  }),
  p('prc-0069', 'ast-1019', 3304, 'NT AUTHORITY\\NETWORK SERVICE', 'C:\\Program Files\\Microsoft\\Exchange Server\\V15\\Bin\\MSExchangeFrontendTransport.exe', '"C:\\Program Files\\Microsoft\\Exchange Server\\V15\\Bin\\MSExchangeFrontendTransport.exe"', '2026-11-16T04:05:18+09:00', {
    sha256: SHA.exFrontend,
    listen: [tcp('0.0.0.0', 25)],
    componentId: 'cmp-0602',
  }),
  p('prc-0070', 'ast-1019', 5120, 'NT AUTHORITY\\NETWORK SERVICE', 'C:\\Program Files\\Microsoft\\Exchange Server\\V15\\Bin\\EdgeTransport.exe', '"C:\\Program Files\\Microsoft\\Exchange Server\\V15\\Bin\\EdgeTransport.exe"', '2026-11-16T04:06:02+09:00', {
    sha256: SHA.edgeTransport,
    listen: [tcp('0.0.0.0', 2525)],
    componentId: 'cmp-0602',
  }),

  // ast-1020 pay-mssql-01 (WinRM)
  p('prc-0071', 'ast-1020', 4188, 'NT Service\\MSSQLSERVER', 'C:\\Program Files\\Microsoft SQL Server\\MSSQL15.MSSQLSERVER\\MSSQL\\Binn\\sqlservr.exe', '"C:\\Program Files\\Microsoft SQL Server\\MSSQL15.MSSQLSERVER\\MSSQL\\Binn\\sqlservr.exe" -sMSSQLSERVER', '2026-10-11T03:40:05+09:00', {
    sha256: SHA.sqlservr,
    listen: [tcp('0.0.0.0', 1433), tcp('::', 1433)],
    componentId: 'cmp-0601',
  }),
  p('prc-0072', 'ast-1020', 4920, 'NT Service\\SQLSERVERAGENT', 'C:\\Program Files\\Microsoft SQL Server\\MSSQL15.MSSQLSERVER\\MSSQL\\Binn\\SQLAGENT.EXE', '"C:\\Program Files\\Microsoft SQL Server\\MSSQL15.MSSQLSERVER\\MSSQL\\Binn\\SQLAGENT.EXE" -i MSSQLSERVER', '2026-10-11T03:40:31+09:00', {
    sha256: SHA.sqlagent,
    componentId: 'cmp-0601',
  }),

  // Kubernetes 워크로드 (exec 수집)
  p('prc-0073', 'ast-2001', 1, 'node', '/usr/local/bin/node', 'node server.js', '2026-11-11T16:20:05+09:00', { sha256: SHA.node18Img, listen: [tcp('0.0.0.0', 3000)], container: 'web-frontend', componentId: 'cmp-0504' }),
  p('prc-0074', 'ast-2002', 1, 'app', '/opt/java/openjdk/bin/java', '/opt/java/openjdk/bin/java -XX:MaxRAMPercentage=75.0 -jar /app/order-api.jar --spring.datasource.password=****', '2026-11-13T10:02:41+09:00', {
    sha256: SHA.java17Img,
    listen: [tcp('0.0.0.0', 8080)],
    container: 'order-api', componentId: 'cmp-0501',
  }),
  p('prc-0075', 'ast-2003', 1, '65532', '/app/payment-gw', '/app/payment-gw --config=/etc/payment-gw/config.yaml', '2026-11-09T14:31:12+09:00', {
    sha256: SHA.paymentGw,
    listen: [tcp('0.0.0.0', 8443), tcp('0.0.0.0', 9090)],
    container: 'payment-gw', componentId: 'cmp-0401',
  }),
  p('prc-0076', 'ast-2004', 1, 'redis', '/usr/local/bin/redis-server', 'redis-server *:6379', '2026-09-30T02:11:48+09:00', {
    sha256: SHA.redisImg,
    listen: [tcp('0.0.0.0', 6379), tcp('::', 6379)],
    container: 'redis', componentId: 'cmp-0506',
  }),
  p('prc-0077', 'ast-2005', 1, 'app', '/opt/java/openjdk/bin/java', '/opt/java/openjdk/bin/java -XX:MaxRAMPercentage=75.0 -jar /app/auth-server.jar --jwt.signing-key=****', '2026-11-05T19:44:20+09:00', {
    sha256: SHA.java17Img,
    listen: [tcp('0.0.0.0', 8080)],
    container: 'auth-server', componentId: 'cmp-0501',
  }),
  p('prc-0078', 'ast-2008', 1, 'root', '/usr/sbin/nginx', 'nginx: master process /usr/sbin/nginx -g daemon off;', '2026-11-18T09:12:30+09:00', {
    sha256: SHA.nginxAlpineImg,
    listen: [tcp('0.0.0.0', 8080), tcp('0.0.0.0', 8443)],
    container: 'ingress-proxy', componentId: 'cmp-0185',
  }),
  p('prc-0079', 'ast-2008', 21, 'nginx', '/usr/sbin/nginx', 'nginx: worker process', '2026-11-18T09:12:30+09:00', { sha256: SHA.nginxAlpineImg, container: 'ingress-proxy', componentId: 'cmp-0185' }),
  p('prc-0086', 'ast-2001', 14, 'istio-proxy', '/usr/local/bin/envoy', '/usr/local/bin/envoy -c etc/istio/proxy/envoy-rev.json --drain-time-s 45 --local-address-ip-version v4', '2026-11-11T16:20:03+09:00', {
    sha256: SHA.envoy,
    listen: [tcp('0.0.0.0', 15001), tcp('0.0.0.0', 15006), tcp('0.0.0.0', 15090)],
    container: 'istio-proxy',
    componentId: 'cmp-0509',
  }),
  p('prc-0087', 'ast-2003', 14, 'istio-proxy', '/usr/local/bin/envoy', '/usr/local/bin/envoy -c etc/istio/proxy/envoy-rev.json --drain-time-s 45 --local-address-ip-version v4', '2026-11-09T14:31:10+09:00', {
    sha256: SHA.envoy,
    listen: [tcp('0.0.0.0', 15001), tcp('0.0.0.0', 15006), tcp('0.0.0.0', 15090)],
    container: 'istio-proxy',
    componentId: 'cmp-0509',
  }),
  p('prc-0088', 'ast-2005', 14, 'istio-proxy', '/usr/local/bin/envoy', '/usr/local/bin/envoy -c etc/istio/proxy/envoy-rev.json --drain-time-s 45 --local-address-ip-version v4', '2026-11-05T19:44:18+09:00', {
    sha256: SHA.envoy,
    listen: [tcp('0.0.0.0', 15001), tcp('0.0.0.0', 15006), tcp('0.0.0.0', 15090)],
    container: 'istio-proxy',
    componentId: 'cmp-0509',
  }),
]
