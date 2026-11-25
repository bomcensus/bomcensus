# Security

This document describes the security design of bomcensus: how components authenticate each other, how executables are verified, which privileges each component holds, and what is and is not protected.

Status: implemented for Linux hosts, agentless SSH collection and Kubernetes (stages 1 to 3). Not implemented: vulnerability matching, Windows (6.4, 7.2), the exec helper (6.3), PROXY protocol on the agent listener (4.4) and Landlock (6.2). Sections that describe something not implemented say so. Section 12 lists the questions that are still open. The exact bytes signed on the agent protocol are specified in [PROTOCOL.md](PROTOCOL.md).

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
| Planted binary named like a known program | Version commands never run as root: an unprivileged user with no capabilities, under the probe's seccomp filter and resource and time limits | 6.6 |
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
| Manual | The administrator supplies a certificate chain and key | Expiry and replacement are the administrator's responsibility. The server logs a warning before expiry |

Web/API TLS has a third mode, `off` (`BOMCENSUS_WEB_TLS=off`): the listener serves plain HTTP and a reverse proxy or ingress in front of it terminates TLS. Agent TLS cannot be turned off (9).

A common setup is manual Web/API TLS with a certificate from a public or corporate CA, and automatic Agent TLS. Replacing the Web/API certificate never affects agents or enrollment strings.

Independently of both, the server operates an internal **Agent CA** that issues agent certificates. The Agent TLS trust anchor and the Agent CA are separate.

When the server connects to an agent (listen mode, 4.5) it presents a TLS client certificate that belongs to Agent TLS. In automatic mode the internal Agent TLS CA issues it. In manual mode the administrator supplies a client-authentication certificate under the same trust anchor as the Agent TLS server certificate. A certificate that carries both usages can serve as both.

Agents keep a **trust bundle** for Agent TLS and synchronize it periodically over the authenticated channel. To replace the Agent TLS trust anchor, the new anchor is added to the bundle first and the switch happens after agents have picked it up. The UI shows how many agents have not synchronized yet and warns before a switch that would disconnect them.

An anchor change (`internal/server/pkisvc`) has these steps:

1. **Prepare.** The new anchor is either a new internal CA or a certificate supplied by the administrator (the topmost certificate of the given chain). It is added to the trust bundle and the bundle version is raised. Only one change can be prepared at a time.
2. **Stage** (external anchor only). The administrator uploads the Agent TLS server certificate and the client certificate under the prepared anchor. Certificates that chain to the prepared anchor instead of the current one are staged and do not take effect yet.
3. **Activate.** The server certificates switch to the new anchor: for an internal CA, new leaves are issued from it and Agent TLS becomes automatic; for an external anchor, the staged certificates become active and Agent TLS becomes manual. The old anchor is dropped from the bundle. Activation is refused while agents have not synchronized the bundle that contains the new anchor, unless it is forced. An external anchor cannot be activated without staged certificates.
4. **Cancel** drops the prepared anchor and any staged certificates.

Manual certificates uploaded outside an anchor change must chain to the current anchor. Switching Agent TLS from manual back to automatic is allowed only when the internal Agent TLS CA is the current anchor; otherwise an internal anchor has to be prepared and activated, so that agents are never left with an anchor they do not trust. Enrollment strings created before an anchor change carry the old `ca-hash` (4.2) and stop working once the change is activated.

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

Because `ca-hash` covers the SPKI, reissuing the CA certificate with the same key keeps existing strings valid. `ca-hash` is always the current Agent TLS anchor. Manual Agent TLS certificates must chain to that anchor; a different anchor, such as a corporate CA, is introduced with an anchor change (4.1), where it is the topmost certificate of the supplied chain.

### 4.3 Enrollment protocol

1. The agent connects to the server over TLS. System roots are not used. The agent looks for a certificate in the presented chain whose SPKI hash equals `ca-hash`, uses it as the root, verifies the chain down to the leaf and checks the host name.
2. The agent generates its identity key pair and sends (`enroll/start`) `key-id`, a nonce, a CSR, its kind, connection and TLS mode, and host facts. A scanner also sends its HPKE public key (4.7).
3. The server checks the Register Key policy (4.4) and replies with its own nonce and its certificate chain. It signs the SHA-256 hashes of the exact request and response bodies, which contain both nonces, with the server key and sends the signature in the `Bomcensus-Enroll-Signature` response header. The agent verifies the chain against `ca-hash` by the same rule as step 1 and checks the signature.
4. The agent signs the hashes of the same two bodies with the Register Key and sends the signature (`enroll/finish`). **The secret itself is never transmitted.**
5. The server verifies the signature, then evaluates the Register Key policy again and consumes one use of the key. On success it returns the agent certificate, the agent ID and the trust bundle, or the state `pending` when the key requires approval. The response is signed over the hashes of both start bodies and its own body, again in `Bomcensus-Enroll-Signature`.
6. From then on the agent uses mTLS plus message signatures (4.6). The agent's private key never leaves the host. A pending agent has no certificate yet: it authenticates by message signature alone and may only ask for its enrollment result (`GET /enroll/result`) until it is approved.
7. The agent discards the secret after enrollment.

Signatures cover hashes of the bodies as sent, with no JSON canonicalization. The signed messages, labels and header formats are in [PROTOCOL.md](PROTOCOL.md) §2.

The enrollment session lives 5 minutes, can be finished once, and `enroll/finish` must come from the same source address as `enroll/start`. An identity key that is already enrolled is refused.

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
| Relaxed TLS | Whether agents enrolled with this key may use a relaxed TLS verification mode (4.7). Off by default. Recorded per agent at enrollment |
| Revocation | Takes effect immediately. Agents that are already enrolled are not affected |

- One Register Key can enroll many nodes. The key only proves the right to enroll. Each node generates its own identity key and receives its own agent ID and certificate. Revoking one node's certificate does not affect other nodes enrolled with the same key.
- The server stores only the public key. A database leak does not reveal anything that can be used to enroll.
- The source address is the TCP peer address on the agent listener. Forwarding headers are ignored. Behind an L4 load balancer or NAT the server therefore sees the address of that device. PROXY protocol, accepted only from a configured list of trusted addresses, is planned and not implemented. In listen mode the address the server dialed is checked against the allowed ranges.
- The policy is checked at `enroll/start` and again at `enroll/finish`: key validity, target kind, source range, connection direction, and the TLS mode the agent declares. A scanner cannot enroll in listen mode, and a relaxed TLS mode is refused in listen mode (4.7).
- Every enrollment attempt is written to the server log, successful or not. The client receives one uniform refusal; the reason is only logged. Failures (refusals and malformed requests) are rate-limited per `key-id`: after 10 failures within 10 minutes further attempts with that `key-id` are refused until the window ends. The counter is kept per server process.
- The same string ends up in the install scripts of many nodes. Keys used for mass rollout should have a short expiry, an allowed source range and a use limit. Sensitive segments should use manual approval.

### 4.5 Connection direction

| Mode | TCP connection | TLS role of the agent | Use |
|---|---|---|---|
| connect (default) | agent to server | client | general |
| listen | server to agent | server | networks that block outbound connections from the agent |

The mode is set per agent. Scanners support connect mode only; the server refuses a scanner enrollment in listen mode. Relaxed TLS modes (4.7) are not available in listen mode.

The API is the same in both directions. In listen mode the HTTP roles are swapped after the TLS handshake: the agent, which accepted the connection, becomes the HTTP/2 client and the server becomes the HTTP/2 server. A dedicated ALPN value distinguishes this from ordinary HTTPS. In either mode the server takes the agent identity from the TLS peer certificate and from the message signatures.

Enrollment in listen mode:

1. The agent is started with the enrollment string, a listen address and the expected server name. It creates a **temporary key and self-signed certificate in memory** and listens with it. Nothing is written to disk.
2. The administrator registers the target address on the server. The server connects and presents its client certificate.
3. The agent requires a client certificate and verifies it by the rule of 4.3 step 1: a certificate with the pinned SPKI hash is used as the root, and the certificate name must match the expected server name. On failure the handshake is aborted.
4. The server cannot verify the temporary certificate. On such a connection it accepts enrollment requests only.
5. The enrollment exchange is the same as in connect mode (4.3 steps 2 to 5). The agent proves itself with the Register Key signature.
6. The server returns the certificate, agent ID and trust bundle, and binds the agent ID to the target address.
7. The agent replaces the listener certificate with the issued one. Later connections are mTLS with chain verification on both sides. The server also checks that the agent ID in the certificate is the one bound to the address.

The temporary certificate is used only until enrollment completes. Until it is approved, a pending listen-mode agent still presents a temporary certificate, so the server accepts only enrollment requests (including `GET /enroll/result`) on that connection, and the agent authenticates by message signature only (4.3 step 6).

The agent listener limits the number of unauthenticated connections (8) and the handshake time (10 seconds). The listener code supports a list of allowed source addresses, but the agent does not expose it as an option yet. The agent identifies the server by certificate, not by address, so a change of server address needs no change on the agent.

With several server replicas, each listen target is dialed by the one replica that holds its lease in the database. After a failed or closed connection the server redials with a delay that grows from 1 second to 5 minutes.

### 4.6 Message signatures

A TLS inspection device re-terminates TLS. The agent then sees the device's certificate and the agent's client certificate never reaches the server, so both the pinned trust anchor and mTLS fail. For this reason authentication is not left to TLS alone. **TLS provides confidentiality. Message signatures provide authentication and integrity.**

Message signatures are always on, regardless of the TLS mode. This section describes the built-in HTTP channel; a channel built into your own agent and server ([EXTENDING.md](EXTENDING.md) §3) authenticates requests and answers in its own way.

- Every request and response after enrollment is signed using HTTP Message Signatures (RFC 9421), restricted to a fixed subset, with the exceptions listed at the end of this section. A request signature covers the method, the path, the query, the body digest, the agent ID, a fresh nonce and, where present, the counter. A response signature covers the status, the body digest, the request's nonce and, where present, the counter. Bodies stay in clear, so an inspection device can still read them. The exact format is in [PROTOCOL.md](PROTOCOL.md) §3 to §5.
- `Content-Digest` (SHA-256, RFC 9530) is always present, also for an empty body.
- The signature parameter `created` is required. The server rejects a request whose `created` is more than 5 minutes away from its own clock, so **agents need a roughly correct clock**.
- The agent signs with its identity key. The server signs with the key of its Agent TLS server certificate, which chains to the `ca-hash` anchor.
- The agent learns the server signing key with `GET /agent/v1/server-chain` and verifies that chain against its trust bundle (before the first bundle, against `ca-hash`). The signing key therefore stays pinned even when TLS is terminated in between and the agent never sees the server's own certificate (4.7). The response of `/server-chain` is unsigned and trusted only through that verification.
- A response signature includes the nonce of its request. Replaying an old response does not work. The server also remembers accepted nonces for 10 minutes and rejects repeats; this memory is per server process.
- Every request other than `GET` and `HEAD` carries a per-agent monotonic counter, including the long poll. The server rejects values at or below the last one it accepted with a signed answer that carries its current value, so an agent that lost its counter, for example after a disk restore, can continue above it.
- The server derives the agent identity from the signature. If a TLS client certificate is present it must belong to the same identity.
- Not signed: the enrollment calls (they carry the enrollment signatures of 4.3 instead), `/server-chain`, and the responses of release bundle and probe downloads, which are verified by their manifest and code signatures (5). Error responses to a request without a well-formed nonce are unsigned as well; agents treat every unsigned or wrongly signed answer as a transport failure.

### 4.7 TLS verification modes

TLS verification can be relaxed per agent. Both the agent configuration and the Register Key policy must allow it.

| Mode | Server certificate verification | Client certificate | Who can read the traffic |
|---|---|---|---|
| `pinned` (default) | `ca-hash` and the trust bundle | presented | nobody |
| `system` | OS trust store plus the CAs given with `--tls-ca` | none | the inspection device |
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
- On the agent listener the server verifies a client certificate if one is given. A request without a client certificate is accepted only if that agent is allowed to use a relaxed mode, or if it has no valid certificate yet (a pending agent).
- The agent reports the SHA-256 fingerprint, subject and issuer of the server leaf certificate it saw in its signed poll request, together with the SPKI hash of the presented certificate that signed the leaf. Only the issuing CA is compared, because the leaf changes on renewal and when the server names change. If that CA is not one of the server's own Agent TLS CAs (the current trust anchor and a prepared one), or the agent reported none, the server stores the issuer the agent reported (or "unknown issuer") as the agent's observed issuer, marks the agent as "TLS terminated in transit" and counts it on the dashboard. The UI lists agents that are not in `pinned` mode and reveals unexpected interception.
- There is no automatic downgrade. If `pinned` verification fails, the connection fails. Relaxed modes apply only when configured explicitly.
- Relaxed modes are defined for connect mode only. The server refuses them at enrollment in listen mode.

### 4.8 Renewal and revocation

- Agent certificates are short-lived (90 days by default) and renewed by the agent before expiry.
- An agent is revoked by blocking its certificate serial numbers and its agent record, which holds the identity key. The server checks this itself during the mTLS handshake and again on every request: the client certificate of the connection is re-checked and the agent state is read when the message signature is verified. Revocation therefore also applies to connections that are already open. A serial the server never issued counts as revoked. Revocations made on another server replica take effect within one refresh of the in-memory revocation cache (30 seconds by default).
- A revoked agent receives a signed `403 agent_revoked` answer. The agent accepts it as authentic, because it is signed, and stops instead of retrying.
- An agent certificate authorizes report uploads and API calls for its own asset only. Agents may upload reports only for themselves; scan target and Kubernetes subjects and the scanner operations are reserved for scanners, and a scanner may report only on the scan targets and clusters assigned to it.

## 5. Code signing

Executables that run on collection targets (agent, probe, updater) are signed by the build pipeline. The server distributes them but cannot sign them.

### 5.1 Release verification

A release is installed only if **both** checks pass.

| Check | Covers | Trust basis |
|---|---|---|
| Release manifest signature | Version, per-OS/architecture file hashes and sizes, issue and expiry time | A dedicated Ed25519 public key compiled into the binaries. The key is used for nothing else |
| Code signature | The executable itself | [AuthentiELF](https://github.com/jc-lab/authentielf) on Linux, Authenticode on Windows. Every signer chain must end at a compiled-in code-signing root, with an optional timestamp |

- The private manifest key exists only in the build pipeline's HSM or KMS.
- Binaries accept a list of manifest public keys, so that they can carry the current and the next key and the key can be rotated.
- Trust is compiled in through build flags (`-ldflags -X` for `internal/sign.releaseKeys` and `internal/sign.codeSigningRoots`). A binary built without them fails every manifest and code signature verification, so it can neither install updates nor deliver probes.
- Code signatures without a timestamp are verified against the current time, so they **stop verifying when the signing certificate expires**. Release builds must therefore be timestamped (RFC 3161). With a timestamp the signer chain is validated at the time of the timestamp. Verifying the timestamp needs the root of the TSA's chain, either in the system trust store of the verifying host or among the compiled-in code-signing roots.
- Both formats follow the same rules (`internal/sign`): SHA-256, SHA-384 or SHA-512 only (SHA-1 is rejected), RSA (PKCS #1 v1.5) or ECDSA signers, the code-signing extended key usage listed in the signer certificate itself, and every signature in a file must be valid.
- Authenticode is verified in Go on every platform, without Windows APIs. A PE file is accepted only if its certificate table holds exactly one `WIN_CERT_TYPE_PKCS_SIGNED_DATA` entry, lies after all headers and section data and ends the file, so that every byte outside the signature is covered by the image hash; data appended after the signature is rejected. The only accepted timestamp is the RFC 3161 counter-signature (unsigned attribute `1.3.6.1.4.1.311.3.3.1`, as written by `jsign --tsmode RFC3161` and `signtool /tr`). Signatures nested in the primary one (`signtool /as`) must verify as well; any other unsigned attribute, such as a legacy Authenticode counter-signature, makes the file fail. Parsing accepts DER only and is size-bounded, because it runs on the server for uploaded bundles.
- Rollback protection: the manifest version must be higher than the installed one. The manifest expiry time prevents an old manifest from being replayed indefinitely.
- The server obtains releases by upload in the console or from a directory read at start (`BOMCENSUS_RELEASE_DIR`). Download from a release server is not implemented. The server performs the same verification when it receives a release, and stores only releases that pass.

### 5.2 Updater

- The agent downloads a release into a spool directory. It cannot write to the install directory.
- The updater checks hashes, the manifest signature and the code signatures itself. It does not rely on any check the agent made, and nothing the agent writes into the spool is trusted. It reads only the spool; under its systemd unit it has no network access, and on Windows firewall rules for its service SID block all traffic.
- The updater installs into a per-version directory and switches a `current` link. The current and the previous version are kept, older ones are removed. It installs only the agent's files of the bundle (agent, probe, updater; the scanner is verified as part of the bundle but not installed), records their hashes and only ever switches to a version directory whose agent files still match them. A `bomcensus-scanner` file left in a version directory by an earlier version is ignored.
- A bundle is installed only if its version is newer than the current one, and never if that version was rolled back before: rolled-back versions are remembered in the install state.

The hand-off between agent and updater (`internal/updater`) uses files in the spool:

| Spool file | Written by the agent when | Effect in the updater |
|---|---|---|
| `bomcensus-<version>.tar` | a newer deployed version was downloaded (written under a temporary name, then renamed) | verify, install, switch `current`, mark the version *pending* in `<install>/state.json` |
| `confirm-<version>` | the new version completed its first successful signed poll | clear the pending mark |
| `rollback` | its pending version stayed unconfirmed past the pending timeout | switch back to the previous version |

- The agent sees that `current` points to another version and re-executes itself from it.
- `bomcensus-updater boot-check` runs before every agent start. It counts start attempts of a pending version and rolls back when the attempts exceed the limit (3 by default) or the version has been pending longer than the pending timeout (30 minutes by default).
- Boot-check acts only at start. A new version that keeps running without ever reaching the server would stay pending, so the agent writes `rollback` itself when its pending version is older than the same timeout.
- A rollback is possible only while a version is pending. Once it is confirmed it stays, and only a newer release replaces it. The version that was rolled back is recorded as failed and its directory removed.
- A first installation from a release bundle (`deploy/systemd/install.sh`, `deploy/windows/install.ps1`) runs the updater contained in that bundle, because no installed updater exists yet. That updater verifies the bundle the normal way, but its own origin cannot be checked on the host: check where the bundle came from out of band before installing. Later updates are verified by the installed updater. Both scripts give that updater a private spool in the install directory: they run as root or Administrator and must not write into the shared spool, where the agent could have planted a link under the name they use.

On Windows (DEPLOYMENT.md chapter 5) the same files and checks are used, with these differences:

- One updater service replaces the systemd path unit and the boot check unit. It runs the boot check before it reports *running*, and the agent service depends on it. Every 5 seconds it runs `apply` when the spool holds an entry. While a version is pending it counts each new process of the agent service as a start, and it rolls back a version that has been pending longer than the timeout itself, so a crashing or hanging agent does not need to cooperate.
- After a version change the updater restarts the agent service and then stops with a failure status; the service manager starts it again through `current`, so the updater code of the version just installed (or rolled back to) is what runs afterwards. The agent never runs the updater on Windows.
- `current` is a directory junction. Creating one needs no privilege, and the updater switches versions by replacing the target of the existing junction in one file system operation, so a process started through it never sees a missing path. A junction found where a regular file is expected in the spool is refused like a symbolic link.
- Executables that are running cannot be deleted. The directory of a rolled-back version is removed when the updater starts again after the restarts.

### 5.3 Probe delivery

The scanner pushes the probe to SSH and WinRM targets and into Kubernetes pods. Probes are part of the same release and are signed the same way.

- Immediately before each transfer the scanner reads the probe into memory, verifies its code signature (AuthentiELF for Linux, Authenticode for Windows) against the compiled-in code-signing roots, and sends those same bytes. This closes the window between verification and transfer.
- If verification fails, nothing is sent.
- On Windows targets the file is checked again after transfer with `Get-AuthenticodeSignature` and its hash, before it is executed (not implemented).

## 6. Host privilege model

### 6.1 Linux components

The Linux agent is installed as separate components. Root is needed only at install time, to create users, units and directories.

| Component | User | Capabilities | Network | Writable |
|---|---|---|---|---|
| agent (resident) | `bomcensus` | none | connection to the server | state directory, update spool |
| probe (on demand) | `bomcensus-probe` | `CAP_DAC_READ_SEARCH`, `CAP_SYS_PTRACE` | none | nothing |
| updater (on demand) | `bomcensus-update` | none | none | install directory |
| exec helper (planned, 6.3) | `bomcensus-exec` | `CAP_SETUID`, `CAP_SETGID` | none | nothing |

- The agent does not collect. It asks the probe for a report over a Unix socket. The probe is started per request by systemd socket activation and exits when done. Only the agent user can connect to the socket.
- A request names the sections to collect and policy values. It cannot name arbitrary paths or commands, so a compromised agent cannot use the probe to read arbitrary files.
- One exception is the Go symbol query. To tell whether a vulnerable function is actually linked into a Go binary, the server names files by path and SHA-256, both taken from an earlier report of the same asset, together with function names from the Go vulnerability database. The probe answers only "present", "absent" or "not checked" per name (supported executables and tests: [GO_SYMBOLS.md](GO_SYMBOLS.md)). It answers only when the file is a regular file, a Go executable with build info, and its SHA-256 equals the requested one; otherwise every name is "not checked". Names are looked up in the binary's Go function table and in the inline trees of its functions, never searched as bytes. When the inline trees cannot be read, a name missing from the table is "not checked", not "absent". A container path is opened under the root of a process of that container with `os.Root`, so links cannot leave it. A request may name at most 64 files, 512 names per file, 4,096 names in all and names of up to 512 bytes; a larger request is refused as a whole. The same query is passed through the scanner for agentless and Kubernetes collection. A compromised agent can therefore learn which functions are linked into Go executables already listed in its reports. It cannot read file contents or probe files that are not Go executables. On the server, answers are kept per asset and used only for that asset's findings, and only answers to the query waiting for that asset are stored: a compromised agent cannot lower the findings of another asset, even one running the same binary. An answer of "absent" lowers a finding's exposure to installed; it never marks the finding not affected or adds it to a VEX document.
- `CAP_DAC_READ_SEARCH` is used to read all files. `CAP_SYS_PTRACE` is used to access `/proc/<pid>/{exe,maps,fd,root}` of other users' processes.
- Opening `/proc/<pid>/map_files/*` needs `CAP_CHECKPOINT_RESTORE` or `CAP_SYS_ADMIN`, which the probe does not get. With the two capabilities above, replaced and deleted libraries are detected from `/proc/<pid>/maps`, but usually not hashed. Deleted or replaced executables are hashed through `/proc/<pid>/exe`.
- The agent cannot write to the install directory, so a compromised agent cannot replace the probe binary that receives capabilities.
- The probe is not given access to container runtime sockets and never connects to them. Access to the Docker or containerd socket is equivalent to root. Container state is read from the files the runtime keeps on disk. containerd holds an exclusive lock on its metadata database (`meta.db`), so the probe copies it into an anonymous memory file (`memfd`) and reads the copy; it never writes to the runtime's files.

### 6.2 Probe sandbox

**The probe's two capabilities are equivalent to root for reading.** What is removed is the ability to write and to tamper. Left alone, `CAP_SYS_PTRACE` would allow code injection into other processes and from there full root, so that path is closed.

The probe applies the restrictions to itself at start, before it reads anything (`internal/probe/sandbox*.go`), so a probe started by a scanner over SSH or in a pod is restricted the same way as one started by the systemd unit. The unit sets its own restrictions on top (see [DEPLOYMENT.md](DEPLOYMENT.md) §4.4). Each step is best effort and logged; `bomcensus-probe self-test` shows what took effect.

The seccomp filter is a deny list. Denied calls fail with an error instead of killing the process, except calls of a foreign architecture (i386, x32), which kill it. It denies:

- tampering with other processes: `ptrace`, `process_vm_readv`, `process_vm_writev`, `pidfd_getfd`, `process_madvise`;
- kernel attack surface: `perf_event_open`, `bpf`, `userfaultfd`, `io_uring_*`, and user namespaces (`unshare`, `setns`, `clone` with `CLONE_NEWUSER`);
- system changes: module loading, `kexec_*`, `mount` and the new mount API, `pivot_root`, `chroot`, `reboot`, `swapon`/`swapoff`, `acct`, setting the clock, the host name or the domain name, `quotactl`, and `syslog` actions other than reading;
- every way of writing: opening with write access, `O_CREAT` or `O_TRUNC`, `truncate`, creating, removing, renaming and linking names, changing modes, owners, extended attributes and timestamps by path or by descriptor. This makes the whole file system read-only, including `/proc`, so `/proc/<pid>/mem` cannot be written. Descriptors that are already open (standard output, pipes, memory files) can still be written;
- network sockets: `socket` is allowed only for `AF_UNIX` and `AF_NETLINK`;
- `open_by_handle_at`, which with `CAP_DAC_READ_SEARCH` would open files around path checks;
- `clone3` and `openat2` (with `ENOSYS`), because their flags are in memory the filter cannot inspect; C libraries fall back to `clone` and `openat`.

Further restrictions:

- `no_new_privs` is set on every thread. The filter and `no_new_privs` are inherited by every child, including version commands (6.6).
- Memory, CPU parallelism and scheduling priority are limited by the probe itself (memory limit, lowest nice value, idle I/O class); the systemd unit adds memory, CPU, task and I/O limits.
- `PrivateTmp` is not used, because the probe must see the host's `/tmp`.

**Landlock is not used.** A Landlock domain also restricts access to processes outside the domain, which includes `/proc/<pid>/{exe,maps,fd,root}`. Every other process on the host is outside the probe's domain, so process and container collection would see almost nothing (measured: 342 of 343 processes unreadable). The seccomp filter enforces read-only access instead, also on kernels without Landlock.

Privileges at start:

| Started as | What the probe does |
|---|---|
| a non-root user (for example `bomcensus-probe` from the unit, with the two capabilities as ambient capabilities) | keeps what it was given |
| root, with `CAP_DAC_READ_SEARCH` and `CAP_SYS_PTRACE` available (SSH collection with sudo, a kernel without ambient capabilities) | keeps only those two in the effective and permitted sets, reduces the bounding set to them, clears the ambient set and switches to uid/gid 65534 without supplementary groups |
| root without the two capabilities (a container with the default capability set: Kubernetes exec, SSH into a container) | stays uid 0 with its capability set, under `no_new_privs` and the seccomp filter. Switching to 65534 or reducing the set would hide what root can read: a process may read `/proc/<pid>/exe` of another process of the same uid only when its permitted set covers the other's |
| root with all capabilities dropped | stays uid 0 under `no_new_privs` and the seccomp filter. Without `CAP_SETUID` a version command cannot be started as another user, so version commands are not executed and static extraction is used (6.6): nothing found on a target is ever executed as root |

When the probe switches to uid 65534 and its own binary is not executable by that user (a scanner uploads it with mode 0700), it copies itself into a sealed memory file and re-executes from there before reading the request, so that it can still start version commands. This needs `memfd_create` and execution of memory files; if that fails, version commands fall back to static extraction.

### 6.3 Exec helper

**Planned; not implemented.** The design follows. Until it exists, software that only its owner can execute is identified by static extraction.

Some software is installed so that only its owner can execute it. The exec helper runs a requested file **as the owner of that file**. Files owned by root are run as `nobody`. Arguments are limited to those fixed in the matching detector.

`CAP_SETUID` is a dangerous capability. The helper is off by default and should be enabled only where owner-only installations exist.

### 6.4 Windows

The agent and updater services are implemented (DEPLOYMENT.md chapter 5); the probe service is not, and the rest of this section describes its design. Administrator rights are needed only at install time.

| Component | Account | Restrictions |
|---|---|---|
| agent service | virtual account `NT SERVICE\bomcensus-agent` | no administrative rights; `SeChangeNotifyPrivilege` only; writes its state directory and the update spool, reads and executes the install directory |
| probe service (planned) | LocalSystem with a reduced token | only the required privileges are declared (`SeBackupPrivilege` for reading files); write-restricted token; network blocked by a per-service firewall rule |
| updater service | LocalSystem | `SeChangeNotifyPrivilege` only; all traffic blocked by firewall rules for its service SID; the only component that writes the install directory |

The updater runs as LocalSystem, not as a dedicated account as on Linux. It must stop and start the agent service, and it installs the executables that LocalSystem services run (itself, and the planned probe service), so a dedicated account that can replace them would not limit what a compromised updater reaches. What keeps it narrow is the input: it has no network, reads only the spool, and installs nothing that does not pass the manifest and Authenticode checks. The agent's account cannot write the install directory or any executable a LocalSystem service runs. In the spool it may create, change and delete files; an `OWNER RIGHTS` entry stops it from changing the ACL of files it owns, and the updater refuses junctions and symbolic links there (5.2).

The agent and the probe communicate over a named pipe whose ACL admits only the agent service SID. `SeDebugPrivilege` is not granted. This configuration still has to be validated on real systems (section 12).

What runs today, until the probe service exists:

- **No collection.** The probe reads the host identity from the registry (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, `MachineGuid`) and reports every other section with coverage `none` and the reason "not implemented on Windows", so the server records the sections as not collected and removes nothing.
- **No probe sandbox.** None of 6.2 applies; the probe keeps every right of the account that started it, and `bomcensus-probe self-test` reports this as a failed check. This is acceptable only while the probe reads nothing but the registry values above. Collection must not be added before the probe service restrictions exist.
- The agent starts `bomcensus-probe.exe` as a child, at below-normal priority, in a job object that kills it when the agent stops or the request is cancelled. The probe lowers itself further to the idle priority class and background mode.
- State directories (`%ProgramData%\bomcensus\agent`, `%ProgramData%\bomcensus\scanner`) get a protected DACL on every open: full control for `SYSTEM`, `BUILTIN\Administrators`, the account of the process and the component's service account (`NT SERVICE\bomcensus-agent` or `NT SERVICE\bomcensus-scanner`), nothing inherited. Files inside, including the identity and HPKE keys, inherit it. The process also takes ownership; when it cannot and the owner is anyone other than those principals, it refuses to start (`internal/platform/winacl`). The directory is locked with `LockFileEx` instead of `flock`.

### 6.5 Running without privileges

The agent and the probe can run as any ordinary user with no capabilities. The agent then starts the probe as a child process and the probe collects what its privileges allow. The same applies to SSH collection with an account that has no sudo, and to a probe that runs in a container as a non-root user.

Reduced coverage is never presented as a clean result. Each report states the privilege level it was collected with and the coverage of every section. The server shows partially collected assets as "limited visibility", and does not treat items that disappeared because of reduced coverage as removed: it remembers the best coverage the stored items of a section were collected with, and only a report with at least that coverage replaces them.

### 6.6 Version command execution

The probe runs version commands of known software (for example `java -version`, `php -v`) to identify versions. These are files found on the target and are not trusted.

- Only arguments fixed in a detector are used. A file that matches no detector is not executed.
- Only files on the probe's own root are executed. Inside a container root seen through `/proc/<pid>/root`, only static extraction is used. A probe in host root mode (6.7) has changed its root to the host's, so the host's files are executed as on a host installation.
- The command is started through a helper process, a re-execution of the probe binary (`internal/collect/artifact/exechelper.go`). The probe passes the exact file it opened and inspected as an inherited file descriptor, and the helper executes that descriptor, so the file cannot be swapped between inspection and execution.
- Nothing is executed as root. When the probe is root, the command runs as uid/gid 65534 without supplementary groups; otherwise it runs as the probe's own user. In the helper the ambient and bounding capability sets are cleared, all capabilities are dropped and `no_new_privs` is set, so setuid bits and file capabilities have no effect. The probe's seccomp filter (6.2) is inherited: no writes to the file system and no network sockets. A root probe that cannot switch users does not run version commands (6.2).
- The environment is empty except for variables named by the detector and derived from the install path (such as `JAVA_HOME`). The environment of the target process is not copied.
- Standard input is `/dev/null`. When the probe is root, the command also gets a new, empty network namespace where the kernel permits it.
- rlimits: no core files, CPU time 10 seconds, address space 2 GiB (a detector may set another value), file size 0 (no file writes), 64 open files, and a process count of what the user already runs plus 64.
- The command runs in its own process group with `SIGKILL` as parent-death signal. After the time limit (10 seconds) or after it exits, the whole group is killed.
- 32-bit executables are killed by the seccomp architecture check and fall back to static extraction.
- On Windows the same limits are applied with a restricted token and a job object (not implemented).
- The output is treated as untrusted input. Standard output and standard error are kept separately, each truncated at 64 KiB.

A planted file named `java` is therefore executed only as an isolated, unprivileged process. Execution can be disabled by the collection policy (`exec_version`); static extraction is used instead. The policy is a single server-wide setting; per-group policies are not implemented.

### 6.7 Kubernetes node agent

The node agent of the `bomcensus-scanner` chart ([DEPLOYMENT.md](DEPLOYMENT.md) §3.7) runs the Linux components of 6.1 as the containers of one pod per node.

| Component | systemd | Node agent pod |
|---|---|---|
| agent | user `bomcensus`, no capabilities | uid 65532, no capabilities, read-only root file system; of the node it mounts only its state directory |
| probe | one process per connection (socket activation), user `bomcensus-probe` with the two capabilities | one process per connection, started by `bomcensus-probe serve`; starts as root, changes its root to the node's file system and drops to uid 65534 with the two capabilities |
| updater | user `bomcensus-update` | none: the image is the update unit |

The same as with systemd:

- The agent never holds the probe's capabilities. It does not start a probe itself (`--require-probe-socket`) and can only ask for a report; the probe accepts connections from the agent's uid only (`SO_PEERCRED`).
- Every collection runs under the sandbox of 6.2: uid/gid 65534 without groups, exactly `CAP_DAC_READ_SEARCH` and `CAP_SYS_PTRACE`, the bounding set reduced to them, `no_new_privs` and the seccomp filter. In host root mode (`collect --host-root`) this is not best effort: a collection whose drop is incomplete writes no report and exits.
- Version commands (6.6) run from the node's root file system as uid 65534.

Differences:

- **The listener is a resident root process.** `bomcensus-probe serve` keeps `CAP_DAC_READ_SEARCH`, `CAP_SYS_PTRACE`, `CAP_SYS_CHROOT`, `CAP_SETUID`, `CAP_SETGID` and `CAP_SETPCAP` in its permitted set so that its children start with them; it keeps none effective, sets `no_new_privs` and installs the probe's seccomp filter without the `chroot` denial, so it cannot write files, open network sockets or trace processes. It parses nothing it receives: the connection becomes the child's standard input and output. With systemd, PID 1 is the listener.
- **Each collection is root from its start until the drop.** In that window it checks `/host/proc`, changes its root and drops its privileges; it has not read its request yet.
- **The node's root file system is mounted into the probe container**, read-only. Without recursive read-only mounts (before Kubernetes 1.31, or a runtime without support) the node's submounts under `/host` (`/proc`, `/sys`, `/run`, volumes of other pods mounted before the pod started) stay writable for root. The listener and the collections cannot write through the seccomp filter, and a collection is uid 65534 by the time it reads input.
- **AppArmor is off for the probe container**, because the runtime's default profile denies reading other processes. The systemd probe is not confined by AppArmor either. On SELinux nodes the probe needs the `spc_t` type, which is unconfined.
- **The pod is in the node's network namespace** (`hostNetwork`), as the systemd agent is; NetworkPolicies do not apply. The probe container shares it, but its seccomp filter allows only `AF_UNIX` and `AF_NETLINK` sockets.
- **Kubernetes access is node access.** Whoever can change the DaemonSet, create pods in its namespace (which admits privileged pods), exec or attach to its pods, add ephemeral containers to them or replace the image can read every file on every node it runs on: kubelet credentials, the Secret volumes of other pods and, on control plane nodes, the administrator kubeconfig and the etcd data, which leads to cluster administration. With systemd the same takes root on the host. The image has no shell, but an exec into the probe container still runs as root with the six capabilities and the node mounted. Keep the namespace for bomcensus, restrict who may change workloads, exec and read Secrets there, and keep the DaemonSet off control plane nodes unless they must be collected (no tolerations by default).
- **Updates are trusted as the image.** The systemd updater verifies the release signature before it installs (5.2); the node agent runs the image the kubelet pulls. Released images are signed with cosign ([RELEASING.md](RELEASING.md)); pin the image by digest and verify the signature at admission.
- **The enrollment string is a Secret** in the namespace and is used by every node. Give its Register Key the number of uses the nodes need, and require approval if nodes are not added by trusted operators only.

## 7. Remote collection

### 7.1 SSH

- The host key is either pinned when the target is registered, or trusted on first use: the server pins the key the target presented on the first successful or partial run. A pinned key is checked in the handshake, before any credential is sent. A different key fails the job with `host_key_changed`; such a job is never retried automatically, and the pinned key changes only after an administrator clears it. Key formats: [PROTOCOL.md](PROTOCOL.md) §9.
- The probe is transferred over the session's standard input after verification (5.3), into the first candidate directory that allows creating and executing it (`$XDG_RUNTIME_DIR`, `/tmp`, `/var/tmp`, `/dev/shm`, `$HOME`), and removed afterwards. Remote commands are fixed scripts; values from outside are passed as quoted positional parameters, never spliced into the script.
- With sudo enabled the probe runs through `sudo`. When a password is configured, sudo is started with a random marker as its prompt (`sudo -S -p <marker>`) and the password is sent once, only after that marker appears; a second prompt counts as a rejected password. Without a password sudo runs with `-n`. When sudo is not available or refuses, the probe runs without it under the login account, and the job is recorded as partial with the reason.
- **The login account is trusted.** Code running as that account, for example from its shell start-up files, can observe the sudo password or replace the uploaded probe before it is executed.
- Jump hosts (bastions) are not supported. A target that the server cannot reach directly is collected by a remote scanner placed in its network.

### 7.2 WinRM

Not implemented. The design follows.

- HTTPS (port 5986) is the default transport.
- The probe is verified before transfer and again on the target before execution (5.3).

### 7.3 Kubernetes

The scanner needs `get` and `list` on namespaces, pods and nodes, `list` on the `apps` and `batch` controllers (Deployments, ReplicaSets, StatefulSets, DaemonSets, Jobs, CronJobs) to follow owner references, and `create` and `get` on `pods/exec` (`get` is needed for WebSocket exec before Kubernetes 1.35). It does not use `watch`. The `bomcensus-scanner` chart grants `get` and `list` on the controllers.

- `pods/exec` is a strong permission. Where the set of included namespaces is fixed, it is granted with namespace-scoped Roles instead of a ClusterRole. The inventory still lists pods cluster-wide.
- With exec collection disabled, `pods/exec` is not needed and only the image inventory is collected.
- The probe is verified with AuthentiELF immediately before it is piped into a pod (5.3). It is written to `/tmp` or `/dev/shm` under a name containing a random nonce, with mode 0700 and without reusing an existing file, and removed when the exec session ends. Containers with a read-only root file system are therefore usually still collectable through `/dev/shm`.
- A kubeconfig sent to a scanner is refused by default if it runs credential plugins (`exec`, `auth-provider`) or refers to files on the scanner host (certificate, key or token files). `--kube-allow-external-credentials` allows them.
- Images are never pulled from a registry.
- `exec` calls appear in the Kubernetes audit log and can trigger runtime security alerts. Operators need to add exceptions for the scanner's identity.

### 7.4 Credentials

- SSH and kubeconfig credentials are stored in the server database with envelope encryption (`internal/server/secret`): each value gets a fresh random data key; the value is encrypted with the data key and the data key with the master key, both with AES-256-GCM. The associated data binds a ciphertext to its record (for example `credential:<id>`), so a ciphertext copied into another record does not open. Format (version 1): `0x01 ‖ key nonce (12) ‖ sealed data key (48) ‖ data nonce (12) ‖ sealed value`. The private keys of the internal CAs are encrypted with the same master key.
- The master key (32 random bytes) comes from an environment variable or a file (`BOMCENSUS_MASTER_KEY`, `BOMCENSUS_MASTER_KEY_FILE`). KMS support is not implemented.
- A remote scanner receives credentials per job, encrypted to its public key with HPKE (4.7, [PROTOCOL.md](PROTOCOL.md) §9). The encryption binds each value to the scanner, the job and the field. The scanner keeps opened credentials in memory only, for the duration of the job.

## 8. Data handling

- Process command lines can contain passwords. Known patterns are masked before collection, and collection of command lines can be turned off by the collection policy (`collect_cmdline`). Masking is heuristic.
- Environment variables are not collected.
- Raw version command output is stored as produced, truncated at 64 KiB per stream.
- Reports contain a full software inventory of each host. In `pinned` mode they are protected in transit by TLS. In relaxed modes they are readable in transit (4.7).
- Raw reports are kept on the server for 30 days. The retention period is not configurable yet.

## 9. Server

- There is a single administrative user. Its name and password hash (argon2id PHC string) are set through environment variables (`BOMCENSUS_ADMIN_USER`, `BOMCENSUS_ADMIN_PASSWORD_HASH`). The server does not accept a plaintext password, and hashes with excessive cost parameters are rejected. With neither variable set, login is disabled. There is no user management, no roles and no audit log. The password is checked in constant time and the hash is computed whether or not the user name matches.
- Failed logins are throttled per client address and per user name: from the fifth failure on, each failure locks the key out, for 30 seconds at first and twice as long with every further failure, up to 15 minutes. The count is forgotten after an hour without failures. Attempts during a lockout are refused without checking the password. The counters are kept in memory per server process.
- The UI and administrative API use a session cookie `bomcensus_session` (`HttpOnly`, `SameSite=Strict`, `Path=/`, `Secure` when the request arrived over TLS). A session lasts 12 hours from login and is not extended by use. The database stores only the SHA-256 of session IDs.
- CSRF: every request other than `GET`, `HEAD` and `OPTIONS` must carry `X-Requested-With: bomcensus`, which a page of another origin cannot add without a CORS preflight; the server answers no preflights. When an `Origin` header is present its host must equal the request host, otherwise the same applies to `Referer`. The login request is checked the same way.
- `BOMCENSUS_TRUST_PROXY=true` makes the console listener believe `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host` (for the client address used by throttling and logs, the `Secure` flag and the CSRF host check). Only the last `X-Forwarded-For` entry, the one the proxy appended, is used. Set it only when the listener is reachable through the proxy alone.
- Security-relevant events (logins and failed logins, enrollment attempts, approval and revocation of agents, changes to Register Keys, credentials, scan targets, listen targets, TLS settings and the deployed version, with the principal that made them) are written to the server log.
- The code keeps the seam for adding users later: the authentication middleware puts a principal into the request context, every handler reads the user from there, and authorization goes through a single check that currently allows any authenticated principal.
- There are two listeners. The UI/API listener may sit behind a reverse proxy. The agent listener must terminate TLS in the server itself, because of mTLS; a device in front of it may only pass traffic at L4.
- Multi-tenancy is not supported. Assets are organized with groups and tags.

## 10. Untrusted input

The probe parses arbitrary files while holding the capability to read every file on the host.

- Parsers are pure Go. No parser uses cgo or an external tool.
- Archive handling limits recursion depth, entry count, decompressed size and time.
- The Go function table reader (`internal/collect/gosymbol`) bounds the table size, the function count, the bytes searched for the table and module data, and the inline tree bytes read; a malformed file gives an error.
- Fuzz targets exist for the rpm header, rpm database and dpkg status parsers, the JAR scanner and the Go function table reader. They are not run automatically yet.
- A compromised probe has no network and no writable path (6.2). What it can emit is a report in the fixed format, which the server validates.

## 11. Known limitations

- The probe can read every file and every process on the host. The sandbox limits what a compromised probe can do with that, not what it can see.
- In relaxed TLS modes report contents are readable in transit. In `none` mode this applies to anyone on the path.
- The network path can always block or delay communication.
- Storing an SSH host key on first connection trusts the first connection.
- The SSH login account is trusted (7.1).
- The server signs messages with the key of its TLS certificate. Signature formats are domain-separated, but the key serves two purposes.
- Process collection is polling-based. A process that starts and exits between two collections is not seen. Network namespaces without a visible process are not seen, UDP sockets bound by clients appear as listening, and command-line masking is heuristic.
- Replaced and deleted libraries are usually not hashed, because the probe lacks the capability to open `/proc/<pid>/map_files` (6.1).
- The node agent's probe listener runs as root with six capabilities permitted (none effective), and without recursive read-only mounts the node's submounts are writable for root in its container (6.7).
- Access to the node agent's namespace in Kubernetes amounts to reading every file of the nodes it runs on (6.7).
- A root probe in a container with the default capability set keeps that set (6.2). It is still confined by `no_new_privs` and the seccomp filter, but it holds more capabilities than the two of a host installation.
- Software that only its owner may execute, and every file inside a container root seen from the host, is identified by static extraction only (6.3, 6.6).
- Agents need a clock within 5 minutes of the server's (4.6).
- Nonce memory, enrollment failure counters and login throttling are kept per server process; with several replicas each counts separately. Replay protection for state-changing requests rests on the counter, which is in the database.
- A revocation made on one replica reaches the others within one refresh of their revocation cache (4.8).
- Register Key source ranges see the address of a load balancer or NAT in front of the agent listener; PROXY protocol is not supported (4.4).
- The listen-mode agent listener cannot be restricted to source addresses by configuration (4.5).
- Containers: rootless Docker and containerd, Podman and CRI-O are not covered; the writable layer of a container is found only for the overlay2 and overlayfs storage drivers.
- The collection policy (`exec_version`, `collect_cmdline`) is server-wide; it cannot be set per asset group.
- On Windows the updater counts starts of a pending agent version by polling the process ID of the agent service every 5 seconds. Starts closer together than that can be counted as one; the pending timeout still applies.

## 12. Open questions

1. **Code signing certificates.** Whether AuthentiELF and Authenticode signatures use a public EV certificate or a private CA. The implementation pins one or more roots compiled into the binaries (5.1); whether an issuer or leaf should be pinned as well is open. Which TSA release builds use, and whether its root is compiled in, is part of the same decision.
2. **Manual Agent TLS in listen mode.** Public CAs are issuing fewer client-authentication certificates. If a client certificate for the server is hard to obtain with manual Agent TLS, issue only that certificate from the internal CA and carry a second hash in the enrollment string. Keeping Agent TLS automatic avoids the problem.
3. **Privilege setup on older distributions.** Ambient capabilities need kernel 4.3 and systemd 229. RHEL 7 and its derivatives must start the probe as root and let it drop privileges. The list of supported distributions and the availability of seccomp filter features on each has to be worked out.
4. **Windows privilege setup.** Whether the reduced probe token (declared privileges, write-restricted token, per-service firewall rule) still permits all required collection, and whether a virtual service account can replace LocalSystem.
5. **Exec helper.** Owner-only installations are common for some middleware. Decide whether the helper is built at all, and if so whether it stays off by default or becomes an install-time choice.
6. **`none` mode.** Whether a mode without any TLS verification should exist, or whether `system` is sufficient.
7. **Root in containers.** Whether a probe that runs as root with the default container capability set (Kubernetes exec, SSH into a container) should reduce its capabilities further, at the cost of not seeing other processes of the container.
8. **PROXY protocol.** Whether the agent listener should accept PROXY protocol from trusted load balancers, so that Register Key source ranges work behind them.
9. **Clock dependence.** Whether agents with a wrong clock should be able to recover, for example by taking the time from a signed server response, instead of failing the 5-minute check.
