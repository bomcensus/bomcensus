# Deployment

This document describes how to build and run bomcensus. Each installation method has its own chapter; the configuration reference at the end applies to all of them.

- [Quick install](#quick-install)
- [1. Components and ports](#1-components-and-ports)
- [2. Docker Compose](#2-docker-compose)
- [3. Helm](#3-helm)
- [4. systemd](#4-systemd)
- [5. Windows services](#5-windows-services)
- [6. Configuration reference](#6-configuration-reference)

## Quick install

`install.sh` installs the latest release of the server (Docker Compose, chapter 2) or of the Linux host agent (systemd, chapter 4) with one command. It is a release asset, so `releases/latest/download` always serves the script of the latest stable release:

```sh
# Server: PostgreSQL and the server from the released images, in /opt/bomcensus-server
# (~/bomcensus-server when not root). The console password is asked on the terminal.
curl -fsSL https://github.com/bomcensus/bomcensus/releases/latest/download/install.sh \
    | bash -s -- server --env AGENT_SERVER_NAMES=bomcensus.example.com

# Agent, as root, with the enrollment string of a Register Key:
curl -fsSL https://github.com/bomcensus/bomcensus/releases/latest/download/install.sh \
    | sudo BOMCENSUS_TOKEN=bc1.… bash -s -- agent --server https://bomcensus.example.com:8443
```

| Option | Meaning |
|---|---|
| `--rc` | Also consider pre-releases (`vX.Y.Z-rc.N`). The highest version of all releases is installed, so `v1.3.0-rc.2` is chosen over `v1.2.0`, and `v1.3.0` over `v1.3.0-rc.2`. Without it only stable releases are used. A script from a pre-release is not served by `releases/latest`; get it from the repository (`https://raw.githubusercontent.com/bomcensus/bomcensus/main/scripts/install.sh`) or from the release page. |
| `--version X.Y.Z[-PRE]` | Install this version instead of the latest. |
| `--attest prefer\|required\|disabled` | Verifies the build provenance of the downloads (and of the server image) with `gh attestation verify`, against this repository's `release.yml` and the release tag. `prefer` (default) verifies when `gh` is installed and logged in (`gh auth login` or `GH_TOKEN`; the command needs a login even for public repositories) and otherwise prints a warning and goes on. `required` stops when `gh` cannot verify. `disabled` skips the check. A verification that fails stops the installation in every mode. |

Downloads are always checked against the release's `SHA256SUMS`; that detects a damaged download, not a tampered release, which is what the attestation is for. Attestation matters most for the agent: the installer runs as root, and the first updater is taken from the bundle (4.2).

Server options: `--dir DIR`, `--admin-user NAME`, `--admin-password-file FILE` (first line; needed without a terminal), `--env NAME=VALUE` (any variable of `.env`, repeatable), `--no-start`. The script pulls the image (checked by digest), runs `init.sh` (2.4) and `docker compose up -d --wait`. Running it again upgrades the installation in `--dir` to the latest version (2.5): back up first (2.6). It refuses to upgrade an installation whose `.env` points to other images than the released ones, for example a local build with its own release keys.

Agent options are those of the systemd installer (4.2): `--server`, `--token`, `--connect-mode`, `--listen`, `--server-name`, `--tls-verify`, `--unit-dir`, `--no-start`. Use `BOMCENSUS_TOKEN` instead of `--token` to keep the token out of the process list; with `sudo` it must be set on the `sudo` command line as above.

## 1. Components and ports

| Component | Runs on | Purpose |
|---|---|---|
| `bomcensus-server` | server host or cluster | console, admin API, agent gateway, embedded scanner. All state is in PostgreSQL |
| PostgreSQL | server side | the only data store |
| `bomcensus-agent` (+ `bomcensus-probe`, `bomcensus-updater`) | each collected host | host inventory, automatic updates |
| `bomcensus-scanner` | optional, near remote targets | SSH and Kubernetes collection where the embedded scanner cannot reach |

The server has two listeners.

| Port | Listener | What may sit in front |
|---|---|---|
| 8080 | console and admin API (`/api/v1`), health endpoints `/healthz` and `/readyz` | Anything. A reverse proxy or ingress may terminate TLS; then set `BOMCENSUS_WEB_TLS=off` and, if it sets `X-Forwarded-*`, `BOMCENSUS_TRUST_PROXY=true` |
| 8443 | agent and scanner gateway (`/agent/v1`) | Only an L4 (TCP) pass-through. TLS must end in the server: agents pin the server's CA and authenticate with client certificates, so a proxy that terminates TLS breaks enrollment and every later request |

Register Keys can restrict enrollment to source address ranges. The server checks the TCP peer address on port 8443, so behind a load balancer or NAT it sees the address of that device, not of the agent.

## 2. Docker Compose

`deploy/docker/` contains a Compose setup for a single host: PostgreSQL and the server. `deploy/demo/` is a separate, self-contained demo with example data (2.9); it is for trying the product only.

### 2.1 Prerequisites

- Docker Engine with BuildKit and the buildx and compose plugins (Docker 25 or later; tested with Docker 29, buildx 0.37, Compose 5.5).
- About 4 GB of free disk space for the build. The build pulls Node, Go, Debian, distroless and PostgreSQL images.
- Free host ports 8080 and 8443, or other ports set in `.env` (`WEB_PORT`, `AGENT_PORT`).

### 2.2 Images

| Image | Base | Content |
|---|---|---|
| `bomcensus/server:VERSION` | `gcr.io/distroless/static-debian13:nonroot` | `bomcensus-server` with the console built in, the release bundle in `/usr/share/bomcensus/releases` (`BOMCENSUS_RELEASE_DIR`). Runs as uid 65532 |
| `bomcensus/scanner:VERSION` | `gcr.io/distroless/static-debian13:nonroot` | `bomcensus-scanner`, state in `/var/lib/bomcensus/scanner`. Runs as uid 65532 |
| `bomcensus/node-agent:VERSION` | `gcr.io/distroless/static-debian13:nonroot` | `bomcensus-agent` and `bomcensus-probe` in `/usr/local/bin`, mode 0755. Both containers of the scanner chart's node agent DaemonSet (3.7); no shell, no update layout |
| `bomcensus/agent:VERSION` | `debian:trixie-slim` | the agent laid out as on a host (see 2.8). For trying the product and for tests |

Released images are published as `ghcr.io/bomcensus/bomcensus/{server,scanner,node-agent,agent}:VERSION` for linux/amd64 and linux/arm64, signed and attested ([RELEASING.md](RELEASING.md)). To use them instead of a local build, set `BOMCENSUS_REPO=ghcr.io/bomcensus/bomcensus` and `BOMCENSUS_VERSION` in `.env`.

The server image has no shell. Its healthcheck is `bomcensus-server healthcheck`, which requests `/readyz` on the loopback address of `BOMCENSUS_WEB_LISTEN`, over HTTP when `BOMCENSUS_WEB_TLS=off` and HTTPS otherwise (5.1).

### 2.3 Building

From the repository root:

```sh
make docker-build                      # all three images, tagged bomcensus/<name>:$(VERSION)
make docker-build VERSION=1.2.0
make docker-build DOCKER_TARGETS="server agent"
```

`docker-build` runs `docker buildx bake -f deploy/docker/docker-bake.hcl`. The build:

1. builds the console (`pnpm install --frozen-lockfile`, `nuxt generate`) and copies it into `internal/server/console/dist`;
2. runs `make release-dev` with the release keys: every command for linux/amd64 and linux/arm64 with the trust compiled in, and the agent, probe, updater and scanner also for windows/amd64 and windows/arm64; those four are signed (AuthentiELF for Linux, Authenticode for Windows) and packed into `bomcensus-VERSION.tar`, which is then verified;
3. assembles the images for the target platform (Linux only; there are no Windows images).

Steps 1 and 2 run on the build platform and cross-compile, so building for the other architecture needs no emulation for them:

```sh
make docker-build DOCKER_TARGETS=server DOCKER_PLATFORM=linux/arm64 DOCKER_OUTPUT=
```

`DOCKER_OUTPUT=` keeps the result in the build cache. To get an image, push it (`DOCKER_OUTPUT=--push` with `DOCKER_REPO` set to your registry) or use an image store that holds foreign platforms. The agent image runs a few commands in its own stage and needs QEMU (binfmt) for a foreign platform; the server and scanner images do not.

**Release keys.** Binaries trust only the manifest key and code-signing roots compiled into them (see [SECURITY.md](SECURITY.md) §5).

- Without keys, the build generates throwaway keys inside the build step and discards them. The build log says so (`release keys: NO release_keys SECRET GIVEN ...`). Images from such a build accept only bundles from the same build, so all images must come from one `docker-build` run. A later build has other keys: agents installed from an earlier build cannot verify its updates.
- For anything you intend to keep and upgrade, create keys once and pass them in:

  ```sh
  go run ./cmd/bomcensus-release keygen --out /secure/keys --name "Example Corp"
  tar -C /secure/keys -cf /secure/keys.tar .
  make docker-build VERSION=1.2.0 RELEASE_KEYS=/secure/keys.tar
  ```

  The tar is passed as the BuildKit secret `release_keys`. It is unpacked on a tmpfs inside the build step and is not stored in any layer or in the build cache. Because BuildKit does not include secrets in the cache key, `make` also passes the SHA-256 of `manifest.pub` as the build argument `RELEASE_KEYS_ID`; the build fails if the two do not match. When building with `docker buildx build` directly, pass `--secret id=release_keys,src=keys.tar --build-arg RELEASE_KEYS_ID=$(sha256sum < /secure/keys/manifest.pub | cut -c1-64)`.

  The private keys should not live on a build machine longer than needed. A release pipeline with an HSM or KMS is outside the scope of this chapter.

### 2.4 First start

All commands below run in `deploy/docker/` unless noted.

1. Build the images (from the repository root): `make docker-build`.

2. Create `.env`:

   ```sh
   ./init.sh
   ```

   It copies `.env.example` to `.env` (mode 0600), writes a random master key and PostgreSQL password, asks for the admin password twice and stores its argon2id hash, made by `bomcensus-server hash-password` in the server image. Nothing secret is printed. Without a terminal it reads the password from the first line of stdin. `ADMIN_USER=name ./init.sh` sets another user name. It refuses to overwrite an existing `.env`.

   Check `WEB_SERVER_NAMES` and `AGENT_SERVER_NAMES` in `.env`: agents on other machines must reach port 8443 under one of the `AGENT_SERVER_NAMES`. The default `localhost,server` covers the host itself and containers on the Compose network.

3. Start PostgreSQL and the server:

   ```sh
   docker compose up -d --wait        # or, from the repository root: make docker-up
   ```

   The server applies the database migrations, creates the internal CAs and imports the bundle from `BOMCENSUS_RELEASE_DIR`. `--wait` returns when it is healthy. Check:

   ```sh
   curl -k https://localhost:8080/healthz
   curl -k https://localhost:8080/readyz
   ```

4. Open `https://localhost:8080`. The certificate comes from the internal web CA, so the browser warns until you trust that CA or upload a certificate under `/settings/tls`. Log in with `ADMIN_USER` and the password from step 2.

   The admin API takes the same session. Requests other than GET must carry `X-Requested-With: bomcensus`:

   ```sh
   curl -k -c cookies -H 'Content-Type: application/json' -H 'X-Requested-With: bomcensus' \
        --data '{"username":"admin","password":"..."}' https://localhost:8080/api/v1/auth/login
   ```

5. Create a Register Key under `/register-keys` (target: agent). The enrollment string `bc1.…` is shown once.

   With the API:

   ```sh
   curl -k -b cookies -H 'Content-Type: application/json' -H 'X-Requested-With: bomcensus' \
        --data '{"name":"web servers","target":"agent","approval":"manual"}' \
        https://localhost:8080/api/v1/register-keys
   ```

   The `enrollment` field of the response is the string. Install agents with it on the hosts to inventory (chapter 4), or add agentless targets under `/scans`.

Stop with `docker compose down` (or `make docker-down`). `docker compose down -v` also deletes the database.

### 2.5 Upgrading

1. Build or pull the images of the new version, with the **same release keys** as before (2.3).
2. Set `BOMCENSUS_VERSION` in `.env`.
3. Back up the database (2.6).
4. `docker compose up -d --wait`. The server applies new migrations at start (`bomcensus-server migrate` runs them alone) and imports the new bundle from the image.
5. Agents are updated through the server's update settings (`/updates`); each agent verifies the bundle itself and rolls back when the new version does not come up.

### 2.6 Backup

The database holds everything: inventory, agents, Register Keys, credentials, release bundles and the whole PKI (CA keys and certificates). CA private keys and credentials are encrypted with the master key.

- Back up the database, for example `docker compose exec -T postgres pg_dump -U bomcensus -Fc bomcensus > bomcensus.dump`, or with your usual PostgreSQL tooling.
- Back up `.env` separately and keep it secret: `BOMCENSUS_MASTER_KEY` is in it. **A database backup without the master key is of limited use**: the CA keys and stored credentials cannot be decrypted, so the server cannot sign for the existing CAs, and every agent would have to be enrolled again.
- Anyone with the master key and a database copy can impersonate the server to every agent. Store the two apart.
- Values in `.env` reach the containers as environment variables and are visible to anyone who can run `docker inspect`. Access to the Docker socket is equivalent to root on the host.

### 2.7 Remote scanner container

The scanner image is not part of `compose.yaml`. Create a Register Key with target scanner, then:

```sh
docker volume create bomcensus-scanner
docker run --rm -v bomcensus-scanner:/var/lib/bomcensus/scanner -e BOMCENSUS_TOKEN='bc1.…' \
    bomcensus/scanner:VERSION enroll --if-not-enrolled --server https://HOST:8443
docker run -d --restart unless-stopped -v bomcensus-scanner:/var/lib/bomcensus/scanner \
    bomcensus/scanner:VERSION run
```

`HOST` must be one of the server's `AGENT_SERVER_NAMES`. The volume holds the scanner identity and its HPKE key. With `--if-not-enrolled` the enroll step can be repeated safely, for example before every start.

### 2.8 Agent image layout

```
/opt/bomcensus/versions/VERSION/{bomcensus-agent,bomcensus-probe,bomcensus-updater}
/opt/bomcensus/current -> versions/VERSION
/var/lib/bomcensus/agent/          state (a volume)
/var/lib/bomcensus/update-spool/   downloaded releases
```

Users `bomcensus` (990), `bomcensus-probe` (991) and `bomcensus-update` (992) exist as on a host. There is no systemd in the container: the agent starts the probe (`bomcensus-probe collect`) and the updater as its own children, so all three run as `bomcensus`, and `bomcensus` owns `/opt/bomcensus` so that the updater can install. The separation of [SECURITY.md](SECURITY.md) §6.1 is therefore not in effect in this image.

When `BOMCENSUS_SERVER` and `BOMCENSUS_TOKEN` (or `BOMCENSUS_TOKEN_FILE`) are set, the entry point runs `bomcensus-agent enroll --if-not-enrolled`, which does nothing for an approved enrollment and resumes a pending one. It then removes the token from the environment and runs `bomcensus-agent run`. Other commands are passed to the agent (`docker run --rm bomcensus/agent:VERSION version`). Variables: see 5.3.

### 2.9 Demo

`deploy/demo/` starts a server with example data in one step. From the repository root:

```sh
make demo-up        # builds the server and agent images, then starts deploy/demo/compose.yaml
```

Open `http://localhost:8080` and log in as `admin` / `demo`. The stack contains:

| Service | Role |
|---|---|
| `server`, `postgres` | the server, console on plain HTTP bound to 127.0.0.1 |
| `setup` | one-shot: creates a Register Key for the agent, an SSH password credential and one scan target per SSH target, and starts a first scan. It reuses objects that already exist, so it runs again on every start without duplicating them |
| `agent` | an agent container (2.8) that enrolls with the key from `setup` and inventories its own file system |
| `ssh-debian`, `ssh-alpine`, `ssh-alma` | SSH targets with dpkg, apk and rpm packages for the embedded scanner |

Within about a minute four hosts appear under `/assets`. They show partial coverage because the agent and the SSH logins run without privileges.

Stop and delete everything with `make demo-down`. `docker compose up -d --build --wait` and `docker compose down -v` in `deploy/demo/` do the same; `docker compose build` builds the server and agent separately, so prefer `make demo-up` (2.3, release keys). `WEB_PORT` and `AGENT_PORT` change the host ports.

**The demo is not a deployment:** its master key, database password and admin password are fixed in `compose.yaml`, the console has no TLS, and the SSH targets accept the password `demo`. For a console in development, `BOMCENSUS_API=http://localhost:8080 pnpm dev` in `frontend/` uses the demo server.

## 3. Helm

Two charts are in `deploy/charts/`:

| Chart | Deploys |
|---|---|
| `bomcensus-manager` | `bomcensus-server` (Deployment, Services `web` and `agent`, optional Ingress for the console), its Secrets, optionally a CloudNativePG database, optionally the in-cluster scanner |
| `bomcensus-scanner` | one scanner (StatefulSet with one replica) that collects the cluster it runs in through the Kubernetes API; optionally the host agent on every node (DaemonSet, 3.7) |

Each chart has a README with all values. `make helm-lint` checks both charts and renders every database mode; `make helm-package` writes the packages to `dist/charts`.

### 3.1 Quick start

With the [CloudNativePG](https://cloudnative-pg.io) operator installed, this creates a PostgreSQL cluster, the server and the in-cluster scanner:

```sh
printf '%s\n' 'the password' | docker run --rm -i ghcr.io/bomcensus/bomcensus/server:VERSION hash-password > hash.txt
cat > values.local.yaml <<EOV
admin:
  passwordHash: '$(cat hash.txt)'
cnpg:
  cluster:
    create: true
scanner:
  enabled: true
EOV
helm install bomcensus oci://ghcr.io/bomcensus/charts/bomcensus-manager --version VERSION \
    -n bomcensus --create-namespace -f values.local.yaml --wait --timeout 15m
kubectl -n bomcensus port-forward svc/bomcensus-web 8080
```

The published charts use the published images ([RELEASING.md](RELEASING.md)). To install from the checkout instead, run `helm dependency build deploy/charts/bomcensus-manager` and pass `deploy/charts/bomcensus-manager` as the chart; its default images are `ghcr.io/bomcensus/bomcensus/{server,scanner}:latest`; for a local `make docker-build` image, set `image.repository`, `image.tag` and `scanner.image.*`.

Then open `https://localhost:8080/` and, under Kubernetes, register the cluster with the scanner and the in-cluster connection.

The chart cannot compute an argon2id hash; `hash-password` of the server image produces it. Pass it in a values file: with `--set` the commas in `m=65536,t=3,p=4` split the value (escape them as `\,` if `--set-string` must be used).

### 3.2 Database

Exactly one mode is configured; the chart fails otherwise.

| Mode | Values | Notes |
|---|---|---|
| URL | `database.url` or `database.existingSecret.name` | any PostgreSQL |
| New CloudNativePG Cluster | `cnpg.cluster.create=true` | the server reads the `uri` key of the Secret `<cluster>-app` that the operator generates for the `initdb` owner |
| Database in an existing CloudNativePG Cluster | `cnpg.database.create=true`, `cnpg.database.cluster`, `cnpg.database.namespace` | the chart creates a `DatabaseRole`, a `Database` and the role's password Secret in the Cluster's namespace, and a URL Secret in the release namespace |

`DatabaseRole` exists from CloudNativePG 1.30. With an older operator set `cnpg.database.createRole=false` and declare the role in the Cluster's `spec.managed.roles`; NOTES.txt prints the stanza. The CloudNativePG templates check that the CRDs are installed and fail with a message otherwise. On a first install the server restarts until the database accepts connections.

### 3.3 Master key and console user

The master key encrypts the CA keys and the stored credentials. **Losing it loses the PKI and all credentials: every agent and scanner has to enroll again.** Give it as `masterKey.existingSecret` (recommended) or `masterKey.value`; otherwise the chart generates one on the first install, keeps it on upgrades, and the Secret `<release>-master-key` carries `helm.sh/resource-policy: keep`, so `helm uninstall` does not delete it. Back it up after the first install.

The console user is `admin.user` with `admin.passwordHash`, or both from `admin.existingSecret`.

### 3.4 Exposure

- Console: Service `<release>-web` (8080). With `ingress.enabled=true` the ingress terminates TLS and the chart sets `BOMCENSUS_WEB_TLS=off` and `BOMCENSUS_TRUST_PROXY=true`; without it the server serves HTTPS (`web.tls`, default `auto`).
- Agents: Service `<release>-agent` (8443), `ClusterIP`, `NodePort` or `LoadBalancer`. Never put an Ingress or a TLS-terminating proxy in front of it (see section 1). For agents outside the cluster, expose it as `LoadBalancer` or `NodePort` and add the address they use to `agent.extraServerNames`; `externalTrafficPolicy: Local` keeps the client address for Register Key source ranges.
- `BOMCENSUS_AGENT_SERVER_NAMES` is computed from the agent Service DNS names and `agent.extraServerNames`, identical on all replicas.

### 3.5 In-cluster scanner

The scanner needs an enrollment string, and that string contains the hash of the Agent TLS trust anchor, which exists only after the server has started. With `scanner.enabled=true` and no enrollment string given, the manager chart therefore runs a Job, `bomcensus-server bootstrap-scanner`:

1. it connects to the database with the server's configuration and waits until the server has created the PKI;
2. it creates a Register Key of kind scanner with automatic approval (`scannerBootstrap.keyName`, `scannerBootstrap.maxUses`, default 1);
3. it writes the enrollment string into the Secret `<release>-scanner-enrollment` (key `token`). Its ServiceAccount may create Secrets in the namespace and get/update only that Secret.

The scanner pod waits for the Secret. Its init container runs `bomcensus-scanner enroll --if-not-enrolled`, which does nothing once the state directory (a 64Mi PersistentVolumeClaim) holds the identity; then `bomcensus-scanner run`. The Job runs again on every upgrade and keeps the stored string while its key can still enroll or is used up by a scanner that is still enrolled; otherwise it creates a new key. After `helm uninstall` the enrollment Secret and the Register Key remain; delete the Secret and revoke the key in the console.

The Job is a plain Job and not a Helm hook, because `helm install --wait` runs post-install hooks only after all resources are ready, which the scanner cannot be before the Job has run.

`bootstrap-scanner` flags: `--secret-name` (required), `--secret-namespace` (default: the pod's namespace), `--secret-key` (`token`), `--key-name`, `--max-uses` (1), `--timeout` (10m), `--kubeconfig` (default: in-cluster configuration).

With `scanner.nodeAgent.enabled=true` (3.7) the same Job also creates a Register Key of kind agent, with automatic approval and unlimited uses (`scannerBootstrap.nodeAgentKeyName`, `scannerBootstrap.nodeAgentMaxUses`), and writes its enrollment string into the Secret `<release>-node-agent-enrollment`, unless `scanner.nodeAgent.enrollment.token` or `.existingSecret.name` is set. The node agent pods wait for that Secret like the scanner pod. The Job keeps and replaces the string by the same rules. Flags: `--node-agent-secret-name` (without it no node agent key is made), `--node-agent-secret-key` (`token`), `--node-agent-key-name`, `--node-agent-max-uses` (0). `--secret-name` may then be left out, for a scanner with its own enrollment string. The node agents' string is a credential that approves automatically: whoever can read the Secret can enroll agents, so restrict access to the namespace (3.7), or bound the key with `scannerBootstrap.nodeAgentMaxUses`.

For a scanner in another cluster than the server, install `bomcensus-scanner` alone with `server.url` and an enrollment string from the console in `enrollment.existingSecret`.

RBAC of the scanner: a ClusterRole with `get`/`list` on namespaces, nodes, pods and the `apps`/`batch` controllers; `rbac.exec=true` adds `pods/exec` (`create`, `get`), cluster-wide or, with `rbac.namespaces`, through Roles in those namespaces only (SECURITY.md §7.3). Without it only the image inventory is collected. `networkPolicy.enabled=true` restricts the scanner to DNS, the server's agent port and the API server.

### 3.6 Security context

Server, scanner and Job run as UID/GID 65532, non-root, with a read-only root file system, all capabilities dropped, no privilege escalation and the `RuntimeDefault` seccomp profile. `/tmp` and the scanner state are the only writable paths. The node agent (3.7) is the exception: its probe container runs as root with read capabilities.

### 3.7 Node agent

`nodeAgent.enabled=true` in the `bomcensus-scanner` chart adds a DaemonSet that runs the host agent on every selected node. It collects the node as the systemd installation (section 4) does, and each node enrolls as an agent with a Register Key of kind agent (`nodeAgent.enrollment`). Installed with the manager chart (`scanner.nodeAgent.enabled=true`) the key is made by its bootstrap Job (3.5) and the nodes enroll without further steps; with the scanner chart alone, create the key in the console and give it as `nodeAgent.enrollment.existingSecret.name`. Requirements: Kubernetes 1.29 or later, Linux nodes, and a namespace with Pod Security level `privileged`.

The pod reproduces the split of the systemd units (SECURITY.md §6.7):

| Container | Like | Runs as | Command |
|---|---|---|---|
| `init-state` (init) | `StateDirectory=` | root, `CHOWN` `FOWNER` | `bomcensus-agent init-state --dir /var/lib/bomcensus-agent --owner UID:GID` |
| `probe` (native sidecar) | `bomcensus-probe.socket`, `bomcensus-probe@.service` | root, `DAC_READ_SEARCH` `SYS_PTRACE` `SYS_CHROOT` `SETUID` `SETGID` `SETPCAP`, AppArmor unconfined | `bomcensus-probe serve --socket /run/bomcensus/probe.sock --host-root /host --allow-uid UID` |
| `enroll` (init) | `install.sh` enrollment | `nodeAgent.runAsUser`, no capabilities | `bomcensus-agent enroll --if-not-enrolled --probe-socket …` |
| `agent` | `bomcensus-agent.service` | `nodeAgent.runAsUser`, no capabilities | `bomcensus-agent run --require-probe-socket --disable-updates …` |

- The node's root file system is mounted read-only at `/host` with `mountPropagation: None` and, from Kubernetes 1.31, `recursiveReadOnly: IfPossible`. Each collection changes its root to `/host`, so paths, `/proc`, the hash cache and version commands are those of the node. Mounts made on the node after the pod started are not seen until the pod restarts.
- `hostNetwork: true` (with `dnsPolicy: ClusterFirstWithHostNet`) gives the probe the node's hostname and the agent the node's network. `hostPID` is not used: processes are read through the node's `/proc` under `/host`.
- The socket is in a memory `emptyDir` shared by the probe (read-write) and the agent containers (read-only); it is mode 0666 and the probe accepts only the peer uid `nodeAgent.runAsUser` (`SO_PEERCRED`).
- The identity lives on the node in `nodeAgent.stateHostPath` (default `/var/lib/bomcensus/node-agent`, mounted at `/var/lib/bomcensus-agent`, state in its subdirectory `state`). It survives pod restarts, upgrades and `helm uninstall`; delete the directory on the node to enroll the node again. A node that also has the systemd agent installed is enrolled twice.
- Updates: the agent's update flow is off; upgrade the chart or the image tag. Pin the image by digest and verify its signature at admission where possible (SECURITY.md §6.7).
- On SELinux nodes set `nodeAgent.probe.seLinuxOptions.type=spc_t`; the default container type cannot read host files.
- The ServiceAccount token is not mounted; nothing in the pod uses the Kubernetes API. NetworkPolicies do not apply to host-network pods.

## 4. systemd

The Linux host agent is installed as separate components with separate users (SECURITY section 6.1). The files are in `deploy/systemd/`.

| File | Purpose |
|---|---|
| `bomcensus-agent.service` | Resident agent, user `bomcensus`, no capabilities, network allowed. |
| `bomcensus-probe.socket`, `bomcensus-probe@.service` | Probe, started per connection with the socket as stdin and stdout. User `bomcensus-probe`, exactly `CAP_DAC_READ_SEARCH` and `CAP_SYS_PTRACE`, read-only. |
| `bomcensus-updater.path`, `bomcensus-updater.service` | Watches the update spool and runs `bomcensus-updater apply`. User `bomcensus-update`, no network. |
| `bomcensus-boot-check.service` | Runs `bomcensus-updater boot-check` before every agent start. |
| `install.sh`, `uninstall.sh` | Installer and remover, POSIX sh, run as root. |

The exec helper has no units yet.

### 4.1 Layout and permissions

```
/opt/bomcensus/                      bomcensus-update:bomcensus-update  0755
  versions/<version>/{bomcensus-agent,bomcensus-probe,bomcensus-updater}   same owner, 0755
  current -> versions/<version>
  state.json                         written by the updater, readable by everyone
/var/lib/bomcensus/                  root:root                          0755
  agent/                             bomcensus:bomcensus                0700
  update-spool/                      bomcensus:bomcensus-update         2770 (setgid)
/run/bomcensus/probe.sock            bomcensus:bomcensus                0600
```

- Only `bomcensus-update` can write the install directory. The agent and the probe user can read and execute it but not change it, so a compromised agent cannot replace the binary that gets the probe's capabilities. The cost is that the updater user can replace the probe; it is the component that verifies and installs code, and it has no network.
- The spool is owned by the agent user and has the updater's group with the setgid bit. Files the agent creates get the group `bomcensus-update`, and the agent unit sets `UMask=0027`, so they are `rw-r-----` and the updater can read them. The group has write permission on the directory, so the updater can delete what it has processed. No other user has access. The agent has no write access to `/opt/bomcensus`, and the updater has no access to the agent's state directory.
- The agent should write a bundle under a name that does not match `bomcensus-<version>.tar` (for example `.bomcensus-<version>.tar.part`) and rename it when it is complete. The path unit fires on every change of the directory, including the deletions the updater makes itself, so one extra (empty) updater run follows each update.
- Files already in the spool when the host boots are not picked up until the directory changes again. The agent writes there on its next check.

### 4.2 Install

Run as root from a checkout or a release directory that contains the unit files next to `install.sh`.

```sh
# From a release bundle: the updater verifies and installs it (first install included).
sh install.sh dist/bomcensus-<version>.tar

# From a directory with bomcensus-agent, bomcensus-probe and bomcensus-updater
# (or a directory holding linux-<arch>/ with them). Not verified by the script.
sh install.sh build/release/bundle/linux-amd64

# With enrollment (the agent is started only when enrolled):
sh install.sh dist/bomcensus-<version>.tar --server https://HOST:8443 --token bc1.… \
    [--connect-mode connect|listen] [--listen :7443 --server-name NAME] [--tls-verify pinned|system|none]
```

`install.sh` is idempotent: running it again keeps users, state and the installed version, refreshes the unit files, and does not enroll again when `/var/lib/bomcensus/agent/enrollment.json` exists. The token can also be passed in `BOMCENSUS_TOKEN` (section 6.3). For `--connect-mode listen` the port must be above 1023, because the agent has no capabilities.

How a bundle is installed: the script does not check signatures itself. It copies the bundle into a private spool under `/opt/bomcensus` (not the shared spool, which the agent user can write), runs the `bomcensus-updater` taken from the bundle once as `bomcensus-update` on it (there is no installed updater yet), and the updater verifies the manifest signature, the hashes and the code signatures and installs into `versions/<version>/` the normal way. Because that first updater comes from the bundle, check where the bundle came from before you run the script; later updates are checked by the installed updater. A bundle that fails verification is rejected and deleted by the updater and the script stops.

A directory of binaries is copied as it is into `versions/<version>/` (the version comes from `bomcensus-updater version`) and the `current` link is created if it is missing. The updater adopts that version the first time it runs if the binaries pass the code signature check, so that a rollback to it is possible. Use this for development builds and for hosts where a bundle is not at hand.

### 4.3 Remove

`uninstall.sh` stops and removes the units and `/opt/bomcensus`. The state directory `/var/lib/bomcensus/agent` (identity key, certificate, trust bundle) and the users are kept, so a later `install.sh` continues with the same identity. `uninstall.sh --purge` removes the state and the three users as well. Revoke the agent in the console either way.

### 4.4 Design notes

- **Agent.** `ProtectSystem=strict`, with `StateDirectory=bomcensus/agent` and the spool as the only writable paths. `PrivateUsers` is not used, so that the group of the spool and the owner of the probe socket keep their meaning. `MemoryDenyWriteExecute` and a `SystemCallFilter` of `@system-service` without `@privileged` are set; the agent never needs them. `Restart=always` with `RestartSec=5s` growing to 5 minutes (`RestartSteps`, systemd 254 and later). The agent requires and is ordered after `bomcensus-boot-check.service`. That unit is not `RemainAfterExit`, so it runs again on each restart and counts starts of a pending version. If the boot check itself fails, the agent does not start. A revoked agent logs the revocation and exits with status 1. After a restart it waits 5 minutes, doubling per restart up to 1 hour, before it asks the server again. To bring the host back, remove the state directory (`uninstall.sh --purge` or delete `/var/lib/bomcensus/agent`) and enroll again.
- **Probe.** The unit restricts what the probe may do, and the probe also applies its own seccomp filter and `no_new_privs`. Things that are deliberately not set, because the probe must see the real host:
  - `PrivateTmp`: it scans the host `/tmp`.
  - `ProtectHome=yes`: `read-only` is used so that home directories can be read.
  - `ProtectProc` and `ProcSubset`: it must see every process.
  - `PrivateNetwork`: it reads the host's interfaces and addresses, and a private network namespace would replace them with an empty one. The network is closed with `RestrictAddressFamilies=AF_UNIX AF_NETLINK` and `IPAddressDeny=any` instead.
  - `PrivateDevices`: `DevicePolicy=closed` limits device access.
  - `MemoryDenyWriteExecute`: version commands such as `java -version` inherit it and need writable and executable memory.
- `SystemCallFilter=@system-service @sandbox memfd_create capset` for the probe. `@sandbox` is required: without it the probe's own `seccomp(2)` call fails with `EPERM` and the probe runs without its filter (logged as `step=seccomp status=failed`). `memfd_create` is used for the containerd `meta.db` copy and for re-execution from a sealed memfd.
- **Limits for one probe run.** `MemoryMax=1G`, `MemorySwapMax=0`, `TasksMax=256`, `CPUQuota=50%`, `CPUWeight=20`, `IOWeight=20`, `Nice=10`, idle I/O class, `RuntimeMaxSec=20min` (the probe stops itself after 15 minutes). A full first run on a large host takes minutes; raise `RuntimeMaxSec` and `MemoryMax` with a drop-in (`systemctl edit bomcensus-probe@.service`) if the host needs it. The socket accepts at most 4 connections.
- **Updater and boot check.** Writable paths are `/opt/bomcensus` and, for the updater, the spool. `PrivateNetwork=yes`, no capabilities, `AF_UNIX` only.

`systemd-analyze security` exposure (systemd 255): agent 1.4, updater 0.5, boot check 0.5, probe 2.2. What remains in the probe is the cost of its job (two capabilities, netlink, `/proc` and `/tmp` visibility).

### 4.5 Checking an installation

```sh
systemctl status bomcensus-agent bomcensus-probe.socket bomcensus-updater.path
journalctl -u bomcensus-agent -u 'bomcensus-probe@*' -u bomcensus-updater -u bomcensus-boot-check
/opt/bomcensus/current/bomcensus-probe self-test   # as root: shows what the sandbox applied
```

Each probe run logs `sandbox step=...` lines. `seccomp status=applied` and `capabilities kept as given: CAP_DAC_READ_SEARCH,CAP_SYS_PTRACE` are the expected result. A probe that is started by the unit as `bomcensus-probe` does not switch users; the unit provides the user and the two capabilities.

### 4.6 Without systemd, or without root

The agent does not need any of the units. As an ordinary user (flags and environment variables: section 6.3):

```sh
bomcensus-agent enroll --server https://HOST:8443 --token bc1.… --state-dir ~/.bomcensus/agent
bomcensus-agent run --state-dir ~/.bomcensus/agent --install-dir ~/.bomcensus
```

The binaries (agent and probe in the same directory) can be anywhere. The agent starts `bomcensus-probe collect` as a child, runs the updater itself when it is present, and runs the boot check at start (SECURITY section 6.5). Use `--state-dir` and `--update-spool` to point at directories you can write; without the units there is no socket, so the agent falls back to the child probe by itself.

Coverage in this mode is what the user can read: files and processes of that user, and nothing under other users' `/proc/<pid>/{exe,maps,fd,root}`. Each report states the privilege level it was collected with and the coverage of every section, the console shows the asset as limited visibility, and items that vanished only because of reduced coverage are not treated as removed. Run it under a service manager of your own (an init script, a user unit, a container) if it should stay up. For full coverage use the units, or run the probe as root through SSH collection.

## 5. Windows services

The Windows host agent runs as Windows services with separate accounts (SECURITY section 6.4). The files are in `deploy/windows/`. On Windows the probe collects the host section only; the other sections are reported as not collected.

| Service or file | Purpose |
|---|---|
| `bomcensus-updater` | `bomcensus-updater service`, LocalSystem, blocked from the network by firewall rules. Runs the boot check at start, installs releases from the update spool and restarts the agent after a version change. |
| `bomcensus-agent` | `bomcensus-agent run`, virtual account `NT SERVICE\bomcensus-agent`, no administrative rights. Depends on the updater. Starts the probe as a child process. |
| `bomcensus-scanner` | optional (`-Scanner`), virtual account `NT SERVICE\bomcensus-scanner`. |
| `install.ps1`, `uninstall.ps1` | Installer and remover. Windows PowerShell 5.1 or later, 64-bit, run as Administrator. |

Windows 10 1809 or Windows Server 2019 and later (they ship `tar.exe`), amd64 or arm64. Logs go to the Application event log under the service names as sources.

### 5.1 Layout and permissions

```
%ProgramFiles%\bomcensus\              SYSTEM, Administrators: full; Users, agent, scanner: read and execute
  versions\<version>\{bomcensus-agent.exe,bomcensus-probe.exe,bomcensus-updater.exe}
  current                              directory junction to versions\<version>
  state.json, updater.lock             written by the updater
  scanner\bomcensus-scanner.exe        with -Scanner
%ProgramData%\bomcensus\               SYSTEM, Administrators: full; Users: list this folder
  agent\                               SYSTEM, Administrators, NT SERVICE\bomcensus-agent: full
  scanner\                             SYSTEM, Administrators, NT SERVICE\bomcensus-scanner: full
  update-spool\                        SYSTEM, Administrators: full; NT SERVICE\bomcensus-agent: modify
```

- Every DACL is protected: nothing is inherited from `%ProgramFiles%` or `%ProgramData%` (where every user may create folders). `install.ps1` makes Administrators the owner, replaces the DACL, and refuses a junction or symbolic link found in place of one of these directories. The agent applies the DACL of its state directory again at every start.
- The agent's account can read the install directory but not change it, so a compromised agent cannot replace an executable that a LocalSystem service runs.
- In the spool the agent may create, write, rename and delete files. An `OWNER RIGHTS` entry limits it to the same rights on the files it owns, so it cannot lock the updater out of them. The updater only opens names that are regular files (not junctions or symbolic links) and checks that the file it opened is the one it looked at.
- `current` is a directory junction, not a symbolic link: creating one needs no privilege. The updater switches versions by replacing the target of the existing junction (`FSCTL_SET_REPARSE_POINT`), a single file system operation, so a service started through `current` gets the old or the new version and never a missing path. The service command lines point into `current`.
- The command lines name the install directory, the state directory and the spool explicitly.

### 5.2 Install

Run from an elevated 64-bit PowerShell in a directory that holds `install.ps1` (a checkout or a release directory). Use `powershell -ExecutionPolicy Bypass -File .\install.ps1 …` where scripts are not allowed to run.

```powershell
# From a release bundle: the updater verifies and installs it (first install included).
.\install.ps1 .\bomcensus-<version>.tar

# From a directory with bomcensus-agent.exe, bomcensus-probe.exe and bomcensus-updater.exe
# (or a directory holding windows-<arch>\ with them). Not verified by the script.
.\install.ps1 .\windows-amd64

# With enrollment (the agent is started only when enrolled). The token from the environment:
$env:BOMCENSUS_TOKEN = 'bc1.…'
.\install.ps1 .\bomcensus-<version>.tar -Server https://HOST:8443 `
    [-ConnectMode connect|listen] [-Listen :7443 -ServerName NAME] [-TlsVerify pinned|system|none]

# Also install the scanner service:
.\install.ps1 .\bomcensus-<version>.tar -Scanner
```

`install.ps1` is idempotent: running it again keeps the state and the installed version, applies the directory ACLs and the service configuration again, and does not enroll again when `%ProgramData%\bomcensus\agent\enrollment.json` exists. `-Token` is accepted too, but command lines are visible to other users. `-NoStart` installs without starting the services. With a source, the agent and updater services are stopped while the release is installed.

How a bundle is installed: the script extracts `manifest.json` and `windows-<arch>/bomcensus-updater.exe` from the bundle into a scratch directory under `%ProgramFiles%\bomcensus` and runs that updater once (as Administrator) with a private spool that holds a copy of the bundle. The updater verifies the manifest signature, the hashes and the Authenticode signatures and installs into `versions\<version>\` the normal way. As with `install.sh`, that first updater comes from the bundle: check where the bundle came from before you run the script. Later updates are checked by the installed updater.

A directory of binaries is copied as it is into `versions\<version>\` (the version comes from `bomcensus-updater.exe version`) and `current` is created if it is missing. The updater adopts that version when it first runs if the binaries pass the Authenticode check, so that a rollback to it is possible.

The scanner is not part of an agent installation and is not updated by the updater. `-Scanner` copies `bomcensus-scanner.exe` to `%ProgramFiles%\bomcensus\scanner\`. From a bundle it is used only when the bundle's `manifest.json` is the manifest the updater recorded for that version in `state.json` and the file matches its hash in it. Run `install.ps1` again with a newer bundle to update it. The scanner enrolls separately:

```powershell
& "$env:ProgramFiles\bomcensus\scanner\bomcensus-scanner.exe" enroll --server https://HOST:8443 `
    --state-dir "$env:ProgramData\bomcensus\scanner"
Start-Service bomcensus-scanner
```

Enrollment runs as Administrator; the state directory keeps its DACL, and the agent takes ownership of it at its next start. In listen mode the script adds an inbound firewall rule for the listen port that applies to the agent service only.

### 5.3 Remove

`uninstall.ps1` stops and deletes the services, removes the firewall rules, `%ProgramFiles%\bomcensus` and the spool. The state directories (identity key, certificate, trust bundle) and the event log sources are kept, so a later `install.ps1` continues with the same identity. `uninstall.ps1 -Purge` removes `%ProgramData%\bomcensus` and the event log sources as well. Revoke the agent in the console either way.

### 5.4 Services and updates

There are no systemd units on Windows, so the updater service does what the path unit and the boot check unit do on Linux. The hand-off files in the spool are the same (SECURITY section 5.2). The agent never runs the updater on Windows.

1. At boot the service manager starts `bomcensus-updater`. Before it reports *running* it runs the boot check (count a start of a pending version, roll back when the limits are exceeded) and removes version directories other than the current and the previous one. The agent depends on the updater, so it starts afterwards. If the updater does not start, the agent does not start either.
2. The agent downloads a newer release into the spool under a temporary name and renames it to `bomcensus-<version>.tar`.
3. The updater checks the spool every 5 seconds and runs `apply` when it holds a bundle, a confirmation or a rollback request. After a version change (install or rollback) it restarts the agent service and then stops itself with a failure status; its recovery action starts it again through `current`, so the updater of the new version takes over. If the agent notices the change first, it exits with a failure status and its own recovery action starts the new version.
4. The new updater's boot check counts the agent start. While a version is pending, every new process of the agent service counts as another start; when the starts exceed 3, or the version has been pending for 30 minutes, the updater rolls back. These limits are flags of `bomcensus-updater service` (section 6.4).
5. The agent writes `confirm-<version>` after its first successful signed poll, and the updater clears the pending mark.

Files of a running executable cannot be deleted on Windows. The directory of a rolled-back version is removed by the next start of the updater, after both services have been restarted.

Service configuration set by `install.ps1`:

| | `bomcensus-updater` | `bomcensus-agent`, `bomcensus-scanner` |
|---|---|---|
| Account | LocalSystem | `NT SERVICE\<name>` |
| Start | automatic | automatic; the agent depends on the updater |
| Recovery | restart after 2 s, 5 s, 10 s | restart after 5 s, 30 s, 60 s |
| Failure actions also on an error exit | yes | yes |
| Service SID | unrestricted | unrestricted |
| Privileges | `SeChangeNotifyPrivilege` only | `SeChangeNotifyPrivilege` only |
| Firewall | inbound and outbound blocked | no rule (in listen mode: inbound allowed on the listen port) |

The recovery counters reset after one day without failures; the last action repeats, so the services are restarted indefinitely.

### 5.5 Checking an installation

```powershell
Get-Service bomcensus-*
sc.exe qc bomcensus-agent; sc.exe qfailure bomcensus-updater; sc.exe qprivs bomcensus-updater
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'bomcensus-agent', 'bomcensus-updater' } -MaxEvents 50
& "$env:ProgramFiles\bomcensus\current\bomcensus-updater.exe" status
icacls "$env:ProgramData\bomcensus\update-spool"
```

## 6. Configuration reference

### 6.1 Server environment

The server reads `BOMCENSUS_*` environment variables only. All variables that are set are checked at start and all problems are reported together.

| Variable | Default | Meaning |
|---|---|---|
| `BOMCENSUS_DATABASE_URL` | required | PostgreSQL connection string, for example `postgres://user:password@host:5432/bomcensus` |
| `BOMCENSUS_MASTER_KEY` | | 32 random bytes, base64. Encrypts CA keys and credentials at rest. Exactly one of this and `BOMCENSUS_MASTER_KEY_FILE` is required for `serve` |
| `BOMCENSUS_MASTER_KEY_FILE` | | file holding the master key (base64) |
| `BOMCENSUS_ADMIN_USER` | | console user name. Set together with the hash; both empty disables login |
| `BOMCENSUS_ADMIN_PASSWORD_HASH` | | argon2id PHC string (`$argon2id$…`) from `bomcensus-server hash-password`. A plaintext password is rejected |
| `BOMCENSUS_WEB_LISTEN` | `:8080` | console and API listener |
| `BOMCENSUS_WEB_TLS` | `auto` | `auto`: HTTPS with the stored Web/API TLS setting, initially a certificate from the internal web CA. `manual`: HTTPS with the certificate uploaded in the console (the automatic one until then). `off`: plain HTTP, behind a proxy that terminates TLS |
| `BOMCENSUS_WEB_SERVER_NAMES` | `localhost` | comma-separated DNS names and IP addresses of the automatic web certificate (`*.` wildcard allowed) |
| `BOMCENSUS_TRUST_PROXY` | `false` | believe `X-Forwarded-*` headers on the console listener |
| `BOMCENSUS_AGENT_LISTEN` | `:8443` | agent listener, always TLS. Must differ from `BOMCENSUS_WEB_LISTEN` |
| `BOMCENSUS_AGENT_SERVER_NAMES` | host name | comma-separated names of the automatic agent TLS certificate. Agents connect with one of them |
| `BOMCENSUS_RELEASE_DIR` | | directory whose release bundles are imported at start. The server image sets `/usr/share/bomcensus/releases` |
| `BOMCENSUS_EMBEDDED_SCANNER` | `true` | run the scanner inside the server process |
| `BOMCENSUS_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `BOMCENSUS_LOG_FORMAT` | `text` | `text` or `json` |

Boolean values accept `true/false`, `1/0`, `yes/no`, `on/off`.

Commands:

| Command | Purpose |
|---|---|
| `bomcensus-server [serve]` | run the server (default) |
| `bomcensus-server migrate` | apply the database migrations and exit; needs only `BOMCENSUS_DATABASE_URL` |
| `bomcensus-server hash-password` | print an argon2id hash. Prompts twice on a terminal, otherwise reads the first line of stdin |
| `bomcensus-server bootstrap-scanner` | create a Register Key for a scanner deployed with the server and store its enrollment string in a Kubernetes Secret (section 3.5, flags there). Uses the server's database and master key configuration |
| `bomcensus-server healthcheck` | request `/readyz` on the loopback address of `BOMCENSUS_WEB_LISTEN` (an all-interfaces listener is reached at 127.0.0.1), over HTTP when `BOMCENSUS_WEB_TLS=off` and HTTPS otherwise, without verifying the certificate; 3 s timeout. Exit 0 and no output when ready, else exit 1 with the reason. Needs neither the database URL nor the master key |
| `bomcensus-server version` | print the version |

### 6.2 Compose `.env`

| Variable | Default | Meaning |
|---|---|---|
| `BOMCENSUS_REPO`, `BOMCENSUS_VERSION` | `bomcensus`, `0.0.0-dev` | image names `REPO/{server,agent}:VERSION` |
| `WEB_PORT`, `AGENT_PORT` | `8080`, `8443` | host ports |
| `BIND_ADDRESS` | `0.0.0.0` | host address the ports are bound to |
| `WEB_TLS` | `auto` | `BOMCENSUS_WEB_TLS` |
| `WEB_SERVER_NAMES` | `localhost` | `BOMCENSUS_WEB_SERVER_NAMES` |
| `AGENT_SERVER_NAMES` | `localhost,server` | `BOMCENSUS_AGENT_SERVER_NAMES` |
| `ADMIN_USER`, `ADMIN_PASSWORD_HASH` | written by `init.sh` | console login. Keep the hash in single quotes |
| `BOMCENSUS_MASTER_KEY` | written by `init.sh` | master key |
| `POSTGRES_PASSWORD` | written by `init.sh` | password of the bundled PostgreSQL |
| `BOMCENSUS_LOG_LEVEL` | `info` | server log level |

### 6.3 Agent

`bomcensus-agent enroll` enrolls and, when the Register Key needs approval, waits for it. A pending agent asks for the result every 10 seconds, so an approval reaches it within about 10 seconds. An interrupted pending enrollment is resumed by `enroll` or `run`.

| Flag | Default | Meaning |
|---|---|---|
| `--server` | | `https://HOST:PORT` of the agent listener (connect mode) |
| `--token` | `$BOMCENSUS_TOKEN` | enrollment string. Prefer the environment variable: command lines are visible to other users |
| `--connect-mode` | `connect` | `connect` (agent dials the server) or `listen` (server dials the agent) |
| `--listen` | `:7443` | listen address in listen mode |
| `--server-name` | host of `--server` | name expected in the server certificate; required in listen mode |
| `--tls-verify` | `pinned` | `pinned`, `system` or `none` (relaxed modes must be allowed by the Register Key; see [SECURITY.md](SECURITY.md) §4.7) |
| `--tls-ca` | | PEM file with extra CA certificates for `system` |
| `--state-dir` | `$BOMCENSUS_STATE_DIR` or `/var/lib/bomcensus/agent` | state directory |
| `--log-level` | `$BOMCENSUS_LOG_LEVEL` or `info` | `debug`, `info`, `warn`, `error` |
| `--if-not-enrolled` | `false` | when the state directory already holds an approved enrollment, log one line and exit 0 instead of failing with `already enrolled`. For install scripts and init steps that run on every start |
| `--probe-socket` | | take the host facts of the enrollment request from the probe behind this socket instead of reading the system the command runs on; the socket is waited for up to 2 minutes. Asked only for a new enrollment. For the node agent, whose enroll container does not see the node |

`bomcensus-agent run`:

| Flag | Default | Meaning |
|---|---|---|
| `--state-dir` | `$BOMCENSUS_STATE_DIR` or `/var/lib/bomcensus/agent` | state directory |
| `--install-dir` | `$BOMCENSUS_INSTALL_DIR`, else derived from the executable path (`<install>/versions/<v>/bomcensus-agent`) | install directory; updates are disabled when it cannot be determined |
| `--update-spool` | `/var/lib/bomcensus/update-spool`; Windows: `%ProgramData%\bomcensus\update-spool` | update spool directory |
| `--probe-socket` | `/run/bomcensus/probe.sock` | probe socket; when it does not exist the probe runs as a child |
| `--require-probe-socket` | `false` | never run the probe as a child: a collection fails while the socket is missing |
| `--disable-updates` | `false` | turn the update flow off (images that are updated as a whole) |
| `--log-level` | `$BOMCENSUS_LOG_LEVEL` or `info` | log level |

`bomcensus-agent init-state --dir DIR --owner UID:GID` makes the existing directory `DIR` (not a symbolic link) owned by `UID:GID` with mode 0700, without touching its content. It is the node agent's init step and needs root with `CAP_CHOWN` and `CAP_FOWNER`.

`bomcensus-probe` commands besides `collect` and `self-test`:

| Command | Flags (default) |
|---|---|
| `collect --host-root DIR` | change the root directory to `DIR`, where the host's root file system is mounted, before the sandbox; then require the full privilege drop (uid 65534, exactly `CAP_DAC_READ_SEARCH` and `CAP_SYS_PTRACE`, no_new_privs, seccomp) and exit 1 without a report otherwise. Needs root with `CAP_SYS_CHROOT`, `CAP_SETUID`, `CAP_SETGID`, `CAP_SETPCAP` and the two read capabilities. Not combinable with `--no-sandbox` |
| `serve` | `--socket` (required), `--host-root` (passed to every `collect`), `--allow-uid` (comma-separated peer uids; socket mode 0666, otherwise 0600 and any peer), `--max-connections` (`4`; further connections are closed), `--max-runtime` (`20m`; the collection's process group is killed after it), `--log-level` (`info`), `--no-sandbox`. Starts one `collect` per connection with the connection as standard input and output |

`BOMCENSUS_UPDATER=systemd` tells the agent that systemd units run the updater (`apply` from a path unit, `boot-check` before the agent). Otherwise the agent runs both itself. On Windows the agent never runs the updater; the `bomcensus-updater` service does (section 5.4). There the install directory is also derived from `<install>\current\bomcensus-agent.exe`, the path a service started through the junction sees.

The state directory of the agent and of the scanner is created if needed and set to mode 0700 at every start; the command fails when that `chmod` is not possible. When the state is kept on a volume, point `--state-dir` at a subdirectory of the volume, not at the volume root, whose mode the process may not be allowed to change.

Variables read only by the agent image's entry point:

| Variable | Meaning |
|---|---|
| `BOMCENSUS_SERVER` | `--server` for the first enrollment |
| `BOMCENSUS_TOKEN` | enrollment string for the first enrollment; removed from the environment before `run` |
| `BOMCENSUS_TOKEN_FILE` | file with the enrollment string, read when `BOMCENSUS_TOKEN` is not set |
| `BOMCENSUS_SERVER_NAME` | `--server-name` |
| `BOMCENSUS_TLS_VERIFY` | `--tls-verify` |
| `BOMCENSUS_TLS_CA` | `--tls-ca` |
| `BOMCENSUS_STATE_DIR` | state directory for both commands |

### 6.4 Updater

| Command | Flags (default) |
|---|---|
| `bomcensus-updater apply` | `--spool` (`/var/lib/bomcensus/update-spool`), `--install` (`/opt/bomcensus`), `--lock-wait` (`30s`) |
| `bomcensus-updater boot-check` | `--install` (`/opt/bomcensus`), `--max-attempts` (`3`), `--pending-timeout` (`30m`), `--lock-wait` (`30s`) |
| `bomcensus-updater status` | `--install` (`/opt/bomcensus`); prints the install state as JSON |
| `bomcensus-updater service` | Windows only, run by the service manager (section 5.4): `--install`, `--spool`, `--agent-service` (`bomcensus-agent`), `--poll` (`5s`), `--max-attempts` (`3`), `--pending-timeout` (`30m`), `--lock-wait` (`30s`) |

On Windows the defaults are `%ProgramFiles%\bomcensus` for `--install` and `%ProgramData%\bomcensus\update-spool` for `--spool`.

### 6.5 Scanner

`bomcensus-scanner enroll` takes `--server`, `--token` (`$BOMCENSUS_TOKEN`), `--server-name`, `--tls-verify`, `--tls-ca`, `--state-dir`, `--log-level` and `--if-not-enrolled` as the agent does. Scanners support connect mode only. The default state directory is `/var/lib/bomcensus/scanner`.

`bomcensus-scanner run`:

| Flag | Default | Meaning |
|---|---|---|
| `--state-dir` | `$BOMCENSUS_STATE_DIR` or `/var/lib/bomcensus/scanner` | state directory (identity, HPKE key) |
| `--workers` | `4` | scan jobs run at the same time |
| `--backlog` | `64` | scan jobs waiting for a worker |
| `--kube-allow-external-credentials` | `false` | allow kubeconfigs from the server to run credential plugins or read local files |
| `--log-level` | `$BOMCENSUS_LOG_LEVEL` or `info` | log level |

### 6.6 What is collected from the file system

Agents and SSH scan targets do not walk the whole file system. By default they report:

- the OS packages of the package database;
- the executables of running processes (read through `/proc/<pid>/exe`, so deleted and replaced binaries count);
- the Java archives that running JVMs hold open (read through `/proc/<pid>/fd`), for example `XXXX.jar` of `java -jar XXXX.jar`.

Files that are only stored on a host, such as downloads in a home directory, are not reported.

To inventory software that is installed but not running, add **detect directories** in the console (Settings, "감지 대상 디렉터리") and assign them to agents (agent page) and to scan targets (scan target form). Each assigned directory is walked recursively with the built-in exclusions (`/proc`, `/sys`, `/dev`, `/run`, container storage, pseudo and network file systems). A directory that does not exist on a host, or is a symbolic link, is skipped without reducing coverage. Changing the directories of an agent makes it collect its artifacts on its next poll.

Container roots are image content and are always walked whole: containers seen by a host agent and containers collected through Kubernetes exec.

When upgrading from a version that walked the whole file system, hosts have no detect directories at first. Their next collection only reports running software, and findings of files that are no longer reported are resolved.
