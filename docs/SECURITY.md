# Security

This document describes the security design of bomcensus: how components authenticate each other, how executables are verified, which privileges each component holds, and what is and is not protected.

Status: design. Nothing here is implemented yet. Section 12 lists the questions that are still open.

## 1. Goals and non-goals

Goals:

- An agent only talks to the server it was enrolled with, and the server only accepts agents it enrolled.
- A compromised server cannot push arbitrary code to agents or collection targets.
- No resident component on a collection target runs as root. A compromised agent process cannot modify the host.
- Authentication and integrity survive TLS interception. Only confidentiality is lost.
- A leaked server database does not allow new agents to be enrolled.

Non-goals:

- Hiding collected data from a privileged user on the collection target.
- Preventing denial of service by someone who controls the network path. Messages can always be dropped or delayed.
- Protecting a host that is already compromised at the root level.

## 2. Components and trust boundaries

| Component | Runs on | Network | Trusts |
|---|---|---|---|
| server | management server | UI/API listener, agent listener, outbound to listen-mode agents | its database, the release signing keys |
| agent | collection target, resident | connection to the server only | the trust anchor from its enrollment string, the release signing keys |
| probe | collection target, on demand | none | nothing. It reads local state and writes a report |
| updater | collection target, on demand | none | the release signing keys |
| scanner | outside the target (built into the server, or deployed remotely) | SSH, WinRM, Kubernetes API, connection to the server | the server, the release signing keys |

Everything a probe reads from a target is untrusted input: files, package databases, archives, process metadata, and the output of version commands.

Release signing keys are held by the build pipeline. They are not present on the server.

## 3. Threat summary

| Threat | Mitigation | Section |
|---|---|---|
| Agent is pointed at a fake server | Trust anchor hash pinned in the enrollment string. Server signs its responses | 4.2, 4.3 |
| TLS inspection device or other man in the middle | Message signatures keep authentication and integrity. The enrollment secret is never transmitted. Secret values are encrypted to the recipient key | 4.6, 4.7 |
| Enrollment string leaks | Expiry, allowed source ranges, use limit, manual approval, revocation | 4.4 |
| Server database leaks | Only the public half of each Register Key is stored. Credentials are envelope-encrypted | 4.4, 7.4 |
| Server is compromised and pushes a malicious update | Updates need a manifest signature from an offline key and a code signature. The server holds neither key | 5.1 |
| Probe binary is tampered with in the scanner's store | Code signature verified immediately before every transfer | 5.3 |
| Agent process is compromised over the network | Unprivileged user, no capabilities. Can only send fixed collection requests to the probe. Cannot write to the install directory | 6.1 |
| Probe is compromised by a malicious file | No network, no writable path, ptrace-family system calls blocked. Its only output is a report | 6.2 |
| Planted binary named like a known program | Version commands run as an unprivileged user with no capabilities, under resource and time limits | 6.6 |
| Unauthorized connection to a listen-mode agent | Client certificate required. Failed verification ends the handshake. Pre-authentication connections are limited | 4.5 |
| Stolen agent identity | An agent certificate only authorizes uploads for its own asset. It cannot read other assets. Certificates are short-lived and can be revoked | 4.8 |
| Secrets inside collected data | Command lines are masked. Environment variables are not collected | 8 |
| Malicious archives (zip bombs and similar) | Depth, entry count, size and time limits in every parser | 10 |

## 4. Identity and transport

### 4.1 Server TLS and trust anchors

The server has two TLS configurations. They are managed independently and share neither certificates nor CAs.

| | Web/API TLS | Agent TLS |
|---|---|---|
| Used by | the UI and administrative API listener | the agent listener, and the client certificate the server presents to listen-mode agents (4.5) |
| Verified by | browsers | agents, against the trust anchor pinned in the enrollment string (4.2) |

Each of the two is in one of two modes.

| Mode | Certificate | Operation |
|---|---|---|
| Automatic | The server creates an internal CA on first start, issues the certificate and renews it. Web/API TLS and Agent TLS use separate internal CAs | No configuration. For Web/API TLS, browsers show a warning unless they trust the internal CA |
| Manual | The administrator supplies a certificate chain and key | Expiry and replacement are the administrator's responsibility. The server warns before expiry |

A common setup is manual Web/API TLS with a certificate from a public or corporate CA, and automatic Agent TLS. Replacing the Web/API certificate never affects agents or enrollment strings.

Independently of both, the server operates an internal **Agent CA** that issues agent certificates. The Agent TLS trust anchor and the Agent CA are separate.

When the server connects to an agent (listen mode, 4.5) it presents a TLS client certificate that belongs to Agent TLS. In automatic mode the internal Agent TLS CA issues it. In manual mode the administrator supplies a client-authentication certificate under the same trust anchor as the Agent TLS server certificate. A certificate that carries both usages can serve as both.

Agents keep a **trust bundle** for Agent TLS and synchronize it periodically over the authenticated channel. To replace the Agent TLS trust anchor, the new anchor is added to the bundle first and the switch happens after agents have picked it up. The UI shows how many agents have not synchronized yet and warns before a switch that would disconnect them.

### 4.2 Enrollment string

An agent is installed with a single string. The server address is passed separately.

```
bc1.<ca-hash>.<key-id>.<secret>

bc1      format version
ca-hash  SHA-256 of the Agent TLS trust anchor certificate's SPKI, 32 bytes (43 characters)
key-id   Register Key identifier, 8 random bytes (11 characters). Not secret; safe to log
secret   Ed25519 private key seed of the Register Key, 32 bytes (43 characters)

Example:
bc1.G8R7VVe0OqdFPuyDNuhf9ybu_SInPxoLzh801xR3LeU.LqVSSwJDhTo.2TsFaobRZXyaZajjGC_lZwnlwXXj1PuOEbmBKf5ICPE
```

Fields are unpadded base64url separated by `.`. The whole string is 103 characters and contains no whitespace or shell metacharacters.

A Register Key is the server-side record `(key-id, public key, policy)`. The enrollment string adds the trust anchor hash and the private seed. The server does not keep the seed and shows the string once, when the key is created.

Because `ca-hash` covers the SPKI, reissuing the CA certificate with the same key keeps existing strings valid. With manual Agent TLS the hash defaults to the topmost certificate of the supplied chain and the administrator can choose another one.

### 4.3 Enrollment protocol

1. The agent connects to the server over TLS. System roots are not used. The agent looks for a certificate in the presented chain whose SPKI hash equals `ca-hash`, uses it as the root, verifies the chain down to the leaf and checks the host name.
2. The agent generates its identity key pair and sends `key-id`, a nonce, a CSR and host facts.
3. The server replies with its own nonce and its certificate chain, and signs the message from step 2 together with both nonces using the server key. The agent verifies the chain against `ca-hash` by the same rule as step 1 and checks the signature.
4. The agent signs the whole exchange of steps 2 and 3 with the Register Key and sends the signature. **The secret itself is never transmitted.**
5. The server verifies the signature and the Register Key policy (4.4). On success it returns the agent certificate, the agent ID and the trust bundle, signed with the server key.
6. From then on the agent uses mTLS plus message signatures (4.6). The agent's private key never leaves the host.
7. The agent discards the secret after enrollment.

Mutual authentication in steps 2 to 5 rests on signatures, so it does not depend on who terminated the TLS connection. Enrollment stays safe when TLS is intercepted (4.7): the interceptor does not learn the secret, and it cannot substitute its own key because the CSR is covered by the signature in step 4.

A PAKE is not used. The Register Key is a 256-bit random value, so a signature is sufficient and needs only standard primitives. If enrollment with a short, human-typed code is added later, a PAKE such as SPAKE2+ is the appropriate tool for that case. PKCE does not apply: it sends its verifier in clear and assumes a trustworthy TLS channel.

### 4.4 Register Keys

| Attribute | Meaning |
|---|---|
| Expiry | Enrollment is refused afterwards |
| Allowed source ranges | CIDR list. The peer address must fall inside it |
| Maximum uses | 0 means unlimited |
| Target kind | agent or scanner |
| Default group and tags | Assigned to assets enrolled with this key |
| Approval | Automatic, or pending until an administrator approves |
| Relaxed TLS | Whether agents enrolled with this key may use a relaxed TLS verification mode (4.7). Off by default |
| Revocation | Takes effect immediately. Agents that are already enrolled are not affected |

- One Register Key can enroll many nodes. The key only proves the right to enroll. Each node generates its own identity key and receives its own agent ID and certificate. Revoking one node's certificate does not affect other nodes enrolled with the same key.
- The server stores only the public key. A database leak does not reveal anything that can be used to enroll.
- The source address is the TCP peer address on the agent listener. If an L4 device sits in front, PROXY protocol is accepted only from a configured list of trusted addresses. Forwarding headers from any other path are ignored. In listen mode the address the server dialed is checked against the allowed ranges.
- Every enrollment attempt is written to the server log, successful or not. Failures are rate-limited per `key-id`.
- The same string ends up in the install scripts of many nodes. Keys used for mass rollout should have a short expiry, an allowed source range and a use limit. Sensitive segments should use manual approval.

### 4.5 Connection direction

| Mode | TCP connection | TLS role of the agent | Use |
|---|---|---|---|
| connect (default) | agent to server | client | general |
| listen | server to agent | server | networks that block outbound connections from the agent |

The mode is set per agent. Scanners support connect mode only.

The API is the same in both directions. In listen mode the HTTP roles are swapped after the TLS handshake: the agent, which accepted the connection, becomes the HTTP/2 client and the server becomes the HTTP/2 server. A dedicated ALPN value distinguishes this from ordinary HTTPS. In either mode the server takes the agent identity from the TLS peer certificate and from the message signatures.

Enrollment in listen mode:

1. The agent is started with the enrollment string, a listen address and the expected server name. It creates a **temporary key and self-signed certificate in memory** and listens with it. Nothing is written to disk.
2. The administrator registers the target address on the server. The server connects and presents its client certificate.
3. The agent requires a client certificate and verifies it by the rule of 4.3 step 1: a certificate with the pinned SPKI hash is used as the root, and the certificate name must match the expected server name. On failure the handshake is aborted.
4. The server cannot verify the temporary certificate. On such a connection it accepts enrollment requests only.
5. The enrollment exchange is the same as in connect mode (4.3 steps 2 to 5). The agent proves itself with the Register Key signature.
6. The server returns the certificate, agent ID and trust bundle, and binds the agent ID to the target address.
7. The agent replaces the listener certificate with the issued one. Later connections are mTLS with chain verification on both sides. The server also checks that the agent ID in the certificate is the one bound to the address.

The temporary certificate is used only until enrollment completes.

The agent listener limits the number of unauthenticated connections and the handshake time. An allowed source address list can be configured. The agent identifies the server by certificate, not by address, so a change of server address needs no change on the agent.

### 4.6 Message signatures

A TLS inspection device re-terminates TLS. The agent then sees the device's certificate and the agent's client certificate never reaches the server, so both the pinned trust anchor and mTLS fail. For this reason authentication is not left to TLS alone. **TLS provides confidentiality. Message signatures provide authentication and integrity.**

Message signatures are always on, regardless of the TLS mode.

- Every request and response is signed using HTTP Message Signatures (RFC 9421). The signature covers the method, the path, the body digest and a nonce. Bodies stay in clear, so an inspection device can still read them.
- The agent signs with its identity key. The server signs with the key of a certificate that chains to the `ca-hash` anchor.
- A response signature includes the nonce of its request. Replaying an old response does not work.
- State-changing requests carry a per-agent monotonic counter. The server rejects values at or below the last one it accepted. An agent that lost its counter, for example after a disk restore, obtains the current value from a signed response.
- The server derives the agent identity from the signature. If a TLS client certificate is present it must belong to the same identity.

### 4.7 TLS verification modes

TLS verification can be relaxed per agent. Both the agent configuration and the Register Key policy must allow it.

| Mode | Server certificate verification | Client certificate | Who can read the traffic |
|---|---|---|---|
| `pinned` (default) | `ca-hash` and the trust bundle | presented | nobody |
| `system` | OS trust store plus configured CAs | none | the inspection device |
| `none` | none | none | anyone on the path |

Use `system` where the inspection device's CA is installed on the host. Use `none` only where even that is not possible.

| Property | `pinned` | `system` / `none` |
|---|---|---|
| Mutual authentication of server and agent | yes | yes, by signatures |
| Protection against tampering, forgery and replay | yes | yes, by signatures |
| Register Key protection | yes | yes, the secret is not transmitted |
| Update integrity | yes | yes (5.1) |
| Confidentiality | yes | no. Report contents are readable in transit |
| Protection against blocking or delay | no | no |

- Values that need confidentiality do not rely on TLS. They are encrypted to the recipient's public key with HPKE. At present this applies to credentials sent to scanners. A scanner registers an encryption public key at enrollment.
- On the agent listener the server verifies a client certificate if one is given. A request without a client certificate is accepted only if that agent is allowed to use a relaxed mode.
- The agent includes the fingerprint of the server certificate it saw in its signed requests. If it differs from the server's own certificate, the server marks the agent as "TLS terminated in transit" and shows the issuer. The UI lists agents that are not in `pinned` mode and reveals unexpected interception.
- There is no automatic downgrade. If `pinned` verification fails, the connection fails. Relaxed modes apply only when configured explicitly.
- Relaxed modes are defined for connect mode.

### 4.8 Renewal and revocation

- Agent certificates are short-lived (for example 90 days) and renewed by the agent before expiry.
- An agent is revoked by blocking its certificate serial number and identity key. The server checks this itself during the mTLS handshake and when verifying message signatures.
- An agent certificate authorizes report uploads and API calls for its own asset only.

## 5. Code signing

Executables that run on collection targets (agent, probe, updater) are signed by the build pipeline. The server distributes them but cannot sign them.

### 5.1 Release verification

A release is installed only if **both** checks pass.

| Check | Covers | Trust basis |
|---|---|---|
| Release manifest signature | Version, per-OS/architecture file hashes and sizes, issue and expiry time | A dedicated Ed25519 public key compiled into the binaries. The key is used for nothing else |
| Code signature | The executable itself | [AuthentiELF](https://github.com/jc-lab/authentielf) on Linux, Authenticode on Windows. Pinned publisher chain, with a timestamp |

- The private manifest key exists only in the build pipeline's HSM or KMS.
- Binaries carry the current and the next public key so that the key can be rotated.
- Rollback protection: the manifest version must be higher than the installed one. The manifest expiry time prevents an old manifest from being replayed indefinitely.
- The server obtains releases online or by manual upload in closed networks. It performs the same verification when it receives one.

### 5.2 Updater

- The agent downloads a release into a spool directory. It cannot write to the install directory.
- The updater checks hashes, the manifest signature and the code signatures itself. It does not rely on any check the agent made. It has no network access and reads only the spool.
- The updater installs into a per-version directory and switches a `current` link. The previous version is kept.
- If the new version does not communicate with the server successfully within a set time, the previous version is restored. The updater only switches to versions it has verified.

### 5.3 Probe delivery

The scanner pushes the probe to SSH and WinRM targets and into Kubernetes pods. Probes are part of the same release and are signed the same way.

- Immediately before each transfer the scanner reads the probe into memory, verifies its code signature (AuthentiELF for Linux, Authenticode for Windows) against the pinned chain, and sends those same bytes. This closes the window between verification and transfer.
- If verification fails, nothing is sent.
- On Windows targets the file is checked again after transfer with `Get-AuthenticodeSignature` and its hash, before it is executed.

## 6. Host privilege model

### 6.1 Linux components

The Linux agent is installed as separate components. Root is needed only at install time, to create users, units and directories.

| Component | User | Capabilities | Network | Writable |
|---|---|---|---|---|
| agent (resident) | `bomcensus` | none | connection to the server | state directory, update spool |
| probe (on demand) | `bomcensus-probe` | `CAP_DAC_READ_SEARCH`, `CAP_SYS_PTRACE` | none | nothing |
| updater (on demand) | `bomcensus-update` | none | none | install directory |
| exec helper (optional, off by default) | `bomcensus-exec` | `CAP_SETUID`, `CAP_SETGID` | none | nothing |

- The agent does not collect. It asks the probe for a report over a Unix socket. The probe is started per request by systemd socket activation and exits when done. Only the agent user can connect to the socket.
- A request names the sections to collect and policy values. It cannot name arbitrary paths or commands, so a compromised agent cannot use the probe to read arbitrary files.
- `CAP_DAC_READ_SEARCH` is used to read all files. `CAP_SYS_PTRACE` is used to access `/proc/<pid>/{exe,maps,fd,map_files,root}` of other users' processes.
- The agent cannot write to the install directory, so a compromised agent cannot replace the probe binary that receives capabilities.
- The probe is not given access to container runtime sockets. Access to the Docker or containerd socket is equivalent to root. Container state is read from the files the runtime keeps on disk. Socket access can be enabled by policy where those files are not sufficient.

### 6.2 Probe sandbox

**The probe's two capabilities are equivalent to root for reading.** What is removed is the ability to write and to tamper. Left alone, `CAP_SYS_PTRACE` would allow code injection into other processes and from there full root, so that path is closed.

- seccomp blocks `ptrace`, `process_vm_readv`, `process_vm_writev`, `pidfd_getfd`, `perf_event_open`, `bpf` and related calls.
- The whole file system is read-only, including `/proc`, so `/proc/<pid>/mem` cannot be written. No path is writable.
- No network sockets can be created. Only Unix sockets are allowed.
- `NoNewPrivileges` is set and the capability bounding set is limited to the two capabilities above.
- Memory, CPU and I/O limits are set on the unit.
- `PrivateTmp` is not used, because the probe must see the host's `/tmp`.

These restrictions are set in the systemd unit, and the probe also applies them to itself at start (seccomp and Landlock, as far as the kernel supports them). A probe started by a scanner over SSH or in a pod is therefore restricted the same way.

When a probe is started as root (SSH collection with sudo, or a kernel older than 4.3 without ambient capabilities), it keeps only the two capabilities above and switches to an unprivileged user immediately after start.

### 6.3 Exec helper

Some software is installed so that only its owner can execute it. The exec helper runs a requested file **as the owner of that file**. Files owned by root are run as `nobody`. Arguments are limited to those fixed in the matching detector.

`CAP_SETUID` is a dangerous capability. The helper is off by default and should be enabled only where owner-only installations exist.

### 6.4 Windows

| Component | Account | Restrictions |
|---|---|---|
| agent service | virtual service account | no administrative rights |
| probe service | LocalSystem with a reduced token | only the required privileges are declared (`SeBackupPrivilege` for reading files); write-restricted token; network blocked by a per-service firewall rule |
| updater service | dedicated account | write access to the install directory only |

The agent and the probe communicate over a named pipe whose ACL admits only the agent service SID. `SeDebugPrivilege` is not granted. This configuration still has to be validated on real systems (section 12).

### 6.5 Running without privileges

The agent and the probe can run as any ordinary user with no capabilities. The agent then starts the probe as a child process and the probe collects what its privileges allow. The same applies to SSH collection with an account that has no sudo, and to a probe that runs in a container as a non-root user.

Reduced coverage is never presented as a clean result. Each report states the privilege level it was collected with and the coverage of every section. The server shows partially collected assets as "limited visibility", and does not treat items that disappeared because of reduced coverage as removed.

### 6.6 Version command execution

The probe runs version commands of known software (for example `java -version`, `php -v`) to identify versions. These are files found on the target and are not trusted.

- Only arguments fixed in a detector are used. A file that matches no detector is not executed.
- Nothing is executed as root. Commands run as an unprivileged user with all capabilities dropped and `no_new_privs` set. Setuid bits have no effect.
- The environment is empty except for variables named by the detector and derived from the install path (such as `JAVA_HOME`). The environment of the target process is not copied.
- Standard input is closed and the network is detached where possible. CPU time, memory, process count and file writes are limited by rlimits. After a time limit (10 seconds by default) the process group is killed.
- On Windows the same limits are applied with a restricted token and a job object.
- The output is treated as untrusted input and is size-limited.

A planted file named `java` is therefore executed only as an isolated, unprivileged process. Execution can be disabled by policy per asset group; static extraction is used instead.

## 7. Remote collection

### 7.1 SSH

- The host key is either pinned when the target is registered, or stored on first connection and any later change is refused.
- The probe is transferred over the session's standard input after verification (5.3). sudo and jump hosts are supported.

### 7.2 WinRM

- HTTPS (port 5986) is the default transport.
- The probe is verified before transfer and again on the target before execution (5.3).

### 7.3 Kubernetes

The scanner needs `get`, `list` and `watch` on pods, namespaces and workloads, and `create` on `pods/exec`.

- `pods/exec` is a strong permission. Where the set of included namespaces is fixed, it is granted with namespace-scoped Roles instead of a ClusterRole.
- With exec collection disabled, `pods/exec` is not needed and only the image inventory is collected.
- The probe is verified with AuthentiELF immediately before it is piped into a pod (5.3).
- Images are never pulled from a registry.
- `exec` calls appear in the Kubernetes audit log and can trigger runtime security alerts. Operators need to add exceptions for the scanner's identity.

### 7.4 Credentials

- SSH, WinRM and kubeconfig credentials are stored in the server database with envelope encryption. The master key comes from a file, an environment variable or a KMS.
- A remote scanner receives credentials per job, encrypted to its public key (4.7), and keeps them in memory only.

## 8. Data handling

- Process command lines can contain passwords. Known patterns are masked before collection, and collection of command lines can be turned off by policy.
- Environment variables are not collected.
- Raw version command output is stored as produced, with a size limit.
- Reports contain a full software inventory of each host. In `pinned` mode they are protected in transit by TLS. In relaxed modes they are readable in transit (4.7).
- Raw reports are kept on the server for a configurable retention period.

## 9. Server

- There is a single administrative user. Its name and password hash (argon2id) are set through environment variables (`BOMCENSUS_ADMIN_USER`, `BOMCENSUS_ADMIN_PASSWORD_HASH`). The server does not accept a plaintext password. There is no user management, no roles and no audit log.
- The UI and administrative API use session cookies (`HttpOnly`, `SameSite`).
- Security-relevant events (logins, enrollment attempts, credential use, changes to Register Keys and to the deployed version) are written to the server log.
- The code keeps the seam for adding users later: the authentication middleware puts a principal into the request context, every handler reads the user from there, and authorization goes through a single check that currently allows any authenticated principal.
- There are two listeners. The UI/API listener may sit behind a reverse proxy. The agent listener must terminate TLS in the server itself, because of mTLS; a device in front of it may only pass traffic at L4.
- Multi-tenancy is not supported. Assets are organized with groups and tags.

## 10. Untrusted input

The probe parses arbitrary files while holding the capability to read every file on the host.

- Parsers are pure Go. No parser uses cgo or an external tool.
- Archive handling limits recursion depth, entry count, decompressed size and time.
- Each parser is fuzzed in CI.
- A compromised probe has no network and no writable path (6.2). What it can emit is a report in the fixed format, which the server validates.

## 11. Known limitations

- The probe can read every file and every process on the host. The sandbox limits what a compromised probe can do with that, not what it can see.
- In relaxed TLS modes report contents are readable in transit. In `none` mode this applies to anyone on the path.
- The network path can always block or delay communication.
- With the exec helper enabled, a component holding `CAP_SETUID` exists on the host.
- Storing an SSH host key on first connection trusts the first connection.
- The server signs messages with the key of its TLS certificate. Signature formats are domain-separated, but the key serves two purposes.
- Process collection is polling-based. A process that starts and exits between two collections is not seen.

## 12. Open questions

1. **Code signing certificates.** Whether AuthentiELF and Authenticode signatures use a public EV certificate or a private CA, and what is pinned at verification: root, issuer or leaf.
2. **Manual Agent TLS in listen mode.** Public CAs are issuing fewer client-authentication certificates. If a client certificate for the server is hard to obtain with manual Agent TLS, issue only that certificate from the internal CA and carry a second hash in the enrollment string. Keeping Agent TLS automatic avoids the problem.
3. **Privilege setup on older distributions.** Ambient capabilities need kernel 4.3 and systemd 229. RHEL 7 and its derivatives must start the probe as root and let it drop privileges. The list of supported distributions and the availability of seccomp and Landlock on each has to be worked out.
4. **Windows privilege setup.** Whether the reduced probe token (declared privileges, write-restricted token, per-service firewall rule) still permits all required collection, and whether a virtual service account can replace LocalSystem.
5. **Exec helper default.** Owner-only installations are common for some middleware. Decide whether the helper stays off by default or becomes an install-time choice.
6. **`none` mode.** Whether a mode without any TLS verification should exist, or whether `system` is sufficient.
