# bomcensus-scanner

Helm chart for the bomcensus remote scanner in a Kubernetes cluster. The scanner reads the cluster through the Kubernetes API with its ServiceAccount (inventory of namespaces, workloads, pods, images) and, when allowed, collects inside running containers by piping the probe through `pods/exec`. Only the scanner pod needs network access to the bomcensus server. There is one scanner per cluster. Optionally the chart also runs the host agent on every node as a DaemonSet (`nodeAgent.enabled`, see [Node agent](#node-agent)).

The chart can be installed on its own (scanner in another cluster than the server) or as a dependency of `bomcensus-manager` (`scanner.enabled=true`), which then wires the server address and the enrollment string.

## Install

1. Create a Register Key of kind *scanner* in the console and copy the enrollment string (`bc1.…`).
2. Store it in a Secret and install the chart:

```sh
kubectl create namespace bomcensus
kubectl -n bomcensus create secret generic scanner-enrollment --from-literal=token='bc1.…'
helm install scanner oci://ghcr.io/bomcensus/charts/bomcensus-scanner --version VERSION -n bomcensus \
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

## Node agent

With `nodeAgent.enabled=true` the chart also installs a DaemonSet that runs the host agent on every selected node. It collects the node itself as the systemd agent does (OS packages, processes and their listening ports, files with version commands, the node's containers and their image content), and every node enrolls as an agent of its own. It does not need the scanner's RBAC and does not talk to the Kubernetes API.

Requirements: Kubernetes 1.29 or later (the probe is a native sidecar container), Linux nodes, and a namespace that admits privileged pods (`pod-security.kubernetes.io/enforce=privileged`). Create a Register Key of kind *agent* with at least as many uses as there are nodes:

```sh
kubectl label namespace bomcensus pod-security.kubernetes.io/enforce=privileged
kubectl -n bomcensus create secret generic node-agent-enrollment --from-literal=token='bc1.…'
helm upgrade --install scanner oci://ghcr.io/bomcensus/charts/bomcensus-scanner --version VERSION -n bomcensus \
  --reuse-values --set nodeAgent.enabled=true --set nodeAgent.enrollment.existingSecret.name=node-agent-enrollment
```

The pod mirrors the split of the systemd units:

| Container | Runs as | Does |
|---|---|---|
| `init-state` (init) | root, `CHOWN` and `FOWNER` only | Hands the node directory `nodeAgent.stateHostPath` to the agent's uid, mode 0700 |
| `probe` (native sidecar) | root, `DAC_READ_SEARCH` `SYS_PTRACE` `SYS_CHROOT` `SETUID` `SETGID` `SETPCAP`, AppArmor unconfined | `bomcensus-probe serve`: one `collect --host-root /host` per connection. Each collection changes its root to the node's file system (mounted read-only at `/host`), drops to uid 65534 with `DAC_READ_SEARCH` and `SYS_PTRACE` only, sets no_new_privs and its seccomp filter (no writes, no network sockets, no ptrace) before it reads the request, and refuses to collect otherwise. The listener itself keeps no effective capabilities and runs under the same filter. Only the agent's uid may connect |
| `enroll` (init) | `nodeAgent.runAsUser`, no capabilities | Enrolls once, with the node's host facts from the probe |
| `agent` | `nodeAgent.runAsUser`, no capabilities | Talks to the server and asks the probe over the socket; never starts a probe itself. Automatic updates are off: the image is the update unit |

The pod uses the node's network namespace (`hostNetwork`): the probe reports the node's hostname and the agent connects from the node, like the systemd agent. It does not use the node's PID namespace; the probe reads processes through the node's `/proc` under `/host`. NetworkPolicies do not apply to host-network pods. On Kubernetes 1.31 and later the node mount is recursively read-only where the runtime supports it. On nodes that enforce SELinux set `nodeAgent.probe.seLinuxOptions.type=spc_t`.

The identity of a node lives in `nodeAgent.stateHostPath` on the node and survives pod restarts, upgrades and uninstalls; delete the directory on the node to enroll it again. Nodes with taints (control plane nodes, for example) need `nodeAgent.tolerations`.

Anyone who can change the DaemonSet, create pods in its namespace or exec into its pods can read every file of every selected node: restrict access to the namespace. See `docs/SECURITY.md` for the comparison with the systemd installation.

## Values

| Key | Default | Description |
|---|---|---|
| `image.repository` | `ghcr.io/bomcensus/bomcensus/scanner` | Image. Published charts use the repository they were released from |
| `image.tag` | `""` (appVersion; `latest` in the checkout) | Image tag |
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
| `nodeAgent.enabled` | `false` | Install the node agent DaemonSet |
| `nodeAgent.image.repository` | `ghcr.io/bomcensus/bomcensus/node-agent` | Image of all the node agent's containers |
| `nodeAgent.image.tag` | `""` (appVersion) | |
| `nodeAgent.image.pullPolicy` | `IfNotPresent` | |
| `nodeAgent.enrollment.token` | `""` | Enrollment string of a Register Key of kind agent |
| `nodeAgent.enrollment.existingSecret.name`, `key` | `""`, `token` | Secret with that string (required unless `token` is set) |
| `nodeAgent.stateHostPath` | `/var/lib/bomcensus/node-agent` | Node directory holding the node's agent identity |
| `nodeAgent.runAsUser`, `runAsGroup` | `65532` | User of the agent; the only peer the probe accepts |
| `nodeAgent.logLevel` | `""` (`logLevel`) | |
| `nodeAgent.extraArgs`, `extraEnv` | `[]` | Additional arguments of `bomcensus-agent run`; environment of the agent containers |
| `nodeAgent.probe.maxRuntime` | `20m` | A collection is killed after this time |
| `nodeAgent.probe.seLinuxOptions` | `{}` | SELinux label of the probe container (`type: spc_t` on SELinux nodes) |
| `nodeAgent.probe.resources` | requests 20m/64Mi, limits 500m/1Gi | |
| `nodeAgent.resources` | requests 10m/32Mi, limit 256Mi | Agent and enroll containers |
| `nodeAgent.updateStrategy` | `RollingUpdate`, `maxUnavailable: 1` | |
| `nodeAgent.podAnnotations`, `podLabels`, `priorityClassName` | empty | |
| `nodeAgent.nodeSelector` | `kubernetes.io/os: linux` | |
| `nodeAgent.tolerations`, `affinity` | empty | |
