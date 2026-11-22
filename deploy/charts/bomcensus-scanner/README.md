# bomcensus-scanner

Helm chart for the bomcensus remote scanner in a Kubernetes cluster. The scanner reads the cluster through the Kubernetes API with its ServiceAccount (inventory of namespaces, workloads, pods, images) and, when allowed, collects inside running containers by piping the probe through `pods/exec`. Only the scanner pod needs network access to the bomcensus server. There is one scanner per cluster; no DaemonSet is used.

The chart can be installed on its own (scanner in another cluster than the server) or as a dependency of `bomcensus-manager` (`scanner.enabled=true`), which then wires the server address and the enrollment string.

## Install

1. Create a Register Key of kind *scanner* in the console and copy the enrollment string (`bc1.…`).
2. Store it in a Secret and install the chart:

```sh
kubectl create namespace bomcensus
kubectl -n bomcensus create secret generic scanner-enrollment --from-literal=token='bc1.…'
helm install scanner oci://ghcr.io/bomcensus/bomcensus/charts/bomcensus-scanner --version VERSION -n bomcensus \
  --set server.url=https://bomcensus.example.com:8443 \
  --set enrollment.existingSecret.name=scanner-enrollment
```

3. In the console, register the cluster (Kubernetes) with this scanner and the in-cluster connection.

The host in `server.url` (or `server.name`) must be one of the names in the server's Agent TLS certificate (`BOMCENSUS_AGENT_SERVER_NAMES`; `agent.extraServerNames` in the manager chart).

## How it runs

- A StatefulSet with one replica. The init container `enroll` runs `bomcensus-scanner enroll --if-not-enrolled …`: on the first start it enrolls (and waits for approval if the key requires it); later starts find the identity in the state directory and do nothing. The container `scanner` then runs `bomcensus-scanner run`.
- The enrollment string reaches the init container through the environment variable `BOMCENSUS_TOKEN` from the Secret, never through the command line.
- The state directory (identity key, certificate, trust bundle, HPKE key) is `/var/lib/bomcensus-scanner/state` on a PersistentVolumeClaim of 64Mi. With `persistence.enabled=false` it is an `emptyDir`: every new pod enrolls again as a new scanner, which uses up Register Key uses and leaves the previous scanner in the console.
- The pod runs as UID/GID 65532, non-root, read-only root file system, no capabilities, `RuntimeDefault` seccomp profile, no privilege escalation. `/tmp` is an `emptyDir`.

## RBAC

| Setting | Grants |
|---|---|
| always (`rbac.create=true`) | ClusterRole: `get`, `list` on `namespaces`, `nodes`, `pods`; `apps` `deployments`, `replicasets`, `statefulsets`, `daemonsets`; `batch` `jobs`, `cronjobs` |
| `rbac.exec=true` | `create`, `get` on `pods/exec` in the ClusterRole (`get` is needed for WebSocket exec before Kubernetes 1.35) |
| `rbac.exec=true` and `rbac.namespaces=[…]` | `pods/exec` only through a Role and RoleBinding in each listed namespace; reading stays cluster-wide |

`pods/exec` is a strong permission and exec calls show in the audit log and may trigger runtime security alerts; add an exception for the scanner's ServiceAccount. Without it only the image inventory is collected. Cluster-scoped objects are named `<namespace>-<fullname>`.

## NetworkPolicy

With `networkPolicy.enabled=true` the pod accepts no connections and may only reach DNS, the server's agent port and the API server. `networkPolicy.apiServer.cidrs` must hold the endpoint addresses of the API server (`kubectl get endpoints kubernetes -n default`), because policies see the address after the Service translation. In a bundled install the server pods of the release are selected automatically; otherwise set `networkPolicy.server.podSelector`/`namespaceSelector` or `cidrs`.

## Values

| Key | Default | Description |
|---|---|---|
| `image.repository` | `bomcensus/scanner` | Image. Published charts: `ghcr.io/bomcensus/bomcensus/scanner` |
| `image.tag` | `""` (appVersion) | Image tag |
| `image.pullPolicy` | `IfNotPresent` | |
| `imagePullSecrets` | `[]` | |
| `nameOverride`, `fullnameOverride` | `""` | |
| `server.url` | `""` | Agent listener, `https://HOST:PORT` (required unless bundled) |
| `server.name` | `""` | Name the server certificate must carry; default the host of `server.url` |
| `server.tlsVerify` | `pinned` | `pinned`, `system` or `none` |
| `bundled` | `false` | Set by `bomcensus-manager`; defaults the URL and Secret to that release |
| `enrollment.token` | `""` | Enrollment string; stored in a Secret of the chart |
| `enrollment.existingSecret.name` | `""` | Secret with the enrollment string |
| `enrollment.existingSecret.key` | `token` | Key in that Secret |
| `logLevel` | `info` | `debug`, `info`, `warn`, `error` |
| `workers` | `4` | Scan jobs run at the same time |
| `backlog` | `64` | Scan jobs waiting for a worker |
| `extraArgs` | `[]` | Additional arguments of `run` |
| `extraEnv` | `[]` | Additional environment variables |
| `persistence.enabled` | `true` | PVC for the state directory |
| `persistence.size` | `64Mi` | |
| `persistence.storageClass` | `""` | Default StorageClass when empty |
| `persistence.accessModes` | `[ReadWriteOnce]` | |
| `persistence.annotations` | `{}` | |
| `serviceAccount.create` | `true` | |
| `serviceAccount.name` | `""` | Default: the full name |
| `serviceAccount.annotations` | `{}` | |
| `rbac.create` | `true` | ClusterRole and binding |
| `rbac.exec` | `false` | Allow `pods/exec` |
| `rbac.namespaces` | `[]` | Limit `pods/exec` to these namespaces |
| `podSecurityContext` | non-root 65532, `fsGroup` 65532, `RuntimeDefault` | |
| `securityContext` | read-only root, drop `ALL`, no privilege escalation | |
| `resources` | requests 50m/64Mi, limit 512Mi | |
| `podAnnotations`, `podLabels` | `{}` | |
| `priorityClassName` | `""` | |
| `nodeSelector`, `tolerations`, `affinity` | empty | |
| `networkPolicy.enabled` | `false` | |
| `networkPolicy.server.port` | `8443` | Agent port of the server |
| `networkPolicy.server.podSelector`, `namespaceSelector` | `{}` | Server peers |
| `networkPolicy.server.cidrs` | `[]` | Server addresses |
| `networkPolicy.apiServer.cidrs` | `[]` | API server endpoint addresses (required when enabled) |
| `networkPolicy.apiServer.ports` | `[443, 6443]` | |
| `networkPolicy.dns.enabled` | `true` | Allow DNS to the cluster DNS pods |
| `networkPolicy.dns.namespaceSelector`, `podSelector` | `kube-system` / `k8s-app: kube-dns` | |
