# Agent protocol: signatures and sealed secrets

This document specifies the bytes that are signed on the agent protocol (`api/openapi/agent.yaml`, base path `/agent/v1`) and how secrets in scanner directives are sealed (§9). JSON bodies are defined by the OpenAPI document; this document does not depend on them. Security rationale: `docs/SECURITY.md` §4.3 and §4.6. It covers the built-in HTTP channel; channels of your own carry the same operations and authenticate them in their own way (`docs/EXTENDING.md` §3), while the enrollment signatures (§2) and sealed secrets (§9) are the same on every channel.

Notation: `‖` is byte concatenation, `H(x)` is SHA-256, `b64url` is unpadded base64url (RFC 4648 §5), `b64` is standard base64 with padding (RFC 4648 §4). All text is ASCII.

## 1. Server signature schemes

The server signs with the private key of its Agent TLS leaf certificate. The scheme follows from the key type; a verifier derives the expected scheme from the certificate and rejects any other.

| Key type | Enrollment scheme | Enrollment encoding | Message signature `alg` | Message signature encoding |
|---|---|---|---|---|
| Ed25519 | `ed25519` | 64 bytes | `ed25519` | 64 bytes |
| ECDSA P-256 | `ecdsa-sha256` | ASN.1 DER `Ecdsa-Sig-Value`, SHA-256 | `ecdsa-p256-sha256` | `r ‖ s`, 32 bytes each, SHA-256 |
| ECDSA P-384 | `ecdsa-sha256` | ASN.1 DER, SHA-256 | `ecdsa-p384-sha384` | `r ‖ s`, 48 bytes each, SHA-384 |
| RSA | `rsa-pss-sha256` | RSASSA-PSS, SHA-256, MGF1-SHA-256, salt 32 | `rsa-pss-sha512` | RSASSA-PSS, SHA-512, MGF1-SHA-512, salt 64 |

The message signature column is the RFC 9421 §3.3 algorithm registry. Agents always sign with Ed25519.

## 2. Enrollment

`POST /enroll/start` and `POST /enroll/finish` carry no message signature. Their integrity rests on three signatures over hashes of the exact HTTP body bytes as sent and received (no JSON canonicalization).

```
Rq = H(enroll/start request body)
Rs = H(enroll/start response body)
Rf = H(enroll/finish response body)

server start   = Sign(server key,   "bomcensus enroll v1 server" ‖ Rq ‖ Rs)
agent          = Sign(register key, "bomcensus enroll v1 agent"  ‖ Rq ‖ Rs)
server result  = Sign(server key,   "bomcensus enroll v1 result" ‖ Rq ‖ Rs ‖ Rf)
```

The labels are ASCII without terminator; the signed messages are 90, 89 and 122 bytes long. Ed25519 signs the message itself; the other schemes sign its hash as listed in §1.

| Signature | Carried in | Encoding |
|---|---|---|
| server start | `Bomcensus-Enroll-Signature` header of the `enroll/start` response | `<scheme> "." b64url(signature)` |
| agent | `signature` field of the `enroll/finish` request | raw 64-byte Ed25519 signature (JSON `format: byte`) |
| server result | `Bomcensus-Enroll-Signature` header of the `enroll/finish` response | `<scheme> "." b64url(signature)` |

The register key is the Ed25519 key whose seed is the `secret` of the enrollment string (SECURITY §4.2). The server stores `Rq ‖ Rs` (64 bytes) in the enrollment session between the two calls.

Agent procedure:

1. Send the start request; keep its exact body bytes.
2. Read the start response bytes. Decode `server_chain` (DER, leaf first). Verify it with the pinned rule: every certificate whose SPKI SHA-256 equals `ca-hash` is a root, no other root is trusted, the leaf must verify up to one of them with `serverAuth` and the expected server name.
3. Verify the server start signature with the leaf public key. Abort on any failure.
4. Send the finish request with the agent signature.
5. Verify the server result signature over the finish response bytes with the same leaf key.

Server procedure: on finish, verify the agent signature with the stored Register Key public key and the stored `Rq ‖ Rs` before evaluating the key policy.

## 3. Message signatures

Every other request is signed by the agent; every response to a signed request is signed by the server, except for the paths in §5. This is a strict subset of RFC 9421 with RFC 9530 digests.

### 3.1 Headers

| Header | Direction | Value |
|---|---|---|
| `Content-Digest` | both | `sha-256=:` b64(H(body)) `:` — always present, also for an empty body |
| `Bomcensus-Agent-Id` | request | agent id from enrollment, `[A-Za-z0-9._-]{1,64}` |
| `Bomcensus-Nonce` | request | b64url of 16 random bytes (22 characters), fresh per request |
| `Bomcensus-Counter` | request | decimal 1..2^63−1, no sign, no leading zero; present on every method except `GET` and `HEAD`, absent on those |
| `Bomcensus-Request-Nonce` | response | the request's `Bomcensus-Nonce` |
| `Bomcensus-Counter` | response | last counter the server accepted; sent with `409 counter_replayed` |
| `Signature-Input` | both | see 3.3 |
| `Signature` | both | `sig1=:` b64(signature) `:` |

Each of these headers must occur at most once (exactly once where required). The request body digest is computed over the bytes as sent; responses use no content coding, and the agent sends `Accept-Encoding: identity`.

### 3.2 Covered components

Request, in this order (the last one only when `Bomcensus-Counter` is present):

```
"@method" "@path" "@query" "content-digest" "bomcensus-agent-id" "bomcensus-nonce" "bomcensus-counter"
```

Response, in this order (the last one only when the response carries `Bomcensus-Counter`):

```
"@status" "content-digest" "bomcensus-request-nonce" "bomcensus-counter"
```

Component values (RFC 9421 §2.2):

- `@method`: the method, as sent.
- `@path`: the request-target path as sent, up to the first `?`.
- `@query`: `?` followed by the raw query as sent; `?` alone when there is no query.
- `@status`: the three-digit status code.
- header components: the field value.

`@path` must start with `/`, consist of `A-Z a-z 0-9 - . _ ~ ! $ & ' ( ) * + , ; = : @ /`, contain no percent-encoding and no empty, `.` or `..` segment except a trailing `/`. The server rejects other paths with `400`, so routing and path policies see exactly the signed value.

### 3.3 Signature parameters

```
Signature-Input: sig1=(<components>);created=<unix seconds>;keyid="<keyid>";alg="<alg>"
```

- One signature, label `sig1`. Components separated by one space, parameters exactly `created`, `keyid`, `alg` in this order. No other parameter, no whitespace elsewhere. The verifier rebuilds the canonical form and rejects a header that differs from it.
- Request: `keyid` is the agent id (equal to `Bomcensus-Agent-Id`), `alg` is `ed25519`.
- Response: `keyid` is b64url(SHA-256(SPKI)) of the server signing certificate, `alg` follows §1.
- `created`: the server rejects requests more than 5 minutes off its clock. Agents check nothing on the response `created`; the nonce binds the response.

Signature base (RFC 9421 §2.5): one line per component, `"<name>": <value>`, followed by the line `"@signature-params": ` and the Signature-Input value without the `sig1=` prefix. Lines end with LF; the last line has none.

### 3.4 Server key ids

The agent resolves a response `keyid` it has not seen with `GET /agent/v1/server-chain`, verifies that chain against its trust bundle anchors (or, before the first bundle, against `ca-hash` as in §2), and caches the leaf key under b64url(SHA-256(leaf SPKI)). The response of `/server-chain` is unsigned and is trusted only through that chain verification.

## 4. Nonces and counters

- The server remembers each accepted `(agent id, nonce)` for 10 minutes and rejects a repeat with `401 nonce_replayed`. The memory is per server process and bounded; replay protection for state-changing requests rests on the counter.
- On every method other than `GET` and `HEAD` the agent sends a counter greater than every counter it sent before, persisted before sending. The server accepts it only if it is greater than the last accepted value and stores it atomically. Checks happen in this order: envelope and digest, signature, `created`, nonce, agent state, TLS binding, counter. A request rejected at any step does not advance the counter.
- A stale counter yields `409` with code `counter_replayed`, signed, carrying the server's value in `Bomcensus-Counter` (covered). The agent raises its counter to at least that value and resends the request with a new nonce and counter. The handler did not run for the rejected attempt. Concurrent state-changing requests of one agent can arrive out of order; the agent retries up to three times.
- The response is accepted only if `Bomcensus-Request-Nonce` equals the nonce of the request it answers.

## 5. Paths

| Path | Request signature | Response signature |
|---|---|---|
| `POST /agent/v1/enroll/start`, `POST /agent/v1/enroll/finish` | none | none (enrollment signatures, §2) |
| `GET /agent/v1/server-chain` | none | none (§3.4) |
| `GET /agent/v1/update/bundle/…`, `GET /agent/v1/probe/…` | required | none; streamed, self-authenticating (manifest and code signatures) |
| everything else | required | required |

A pending agent (enrolled, waiting for approval) may call only `GET /agent/v1/enroll/result`; other paths return `403 agent_pending`.

## 6. Agent identity checks

After the signature verifies, the server checks the agent state (revoked: `403 agent_revoked`). If the request arrived with a verified TLS client certificate (in listen mode: the agent's server certificate), its agent id must equal the signing identity. An agent that is not allowed a relaxed TLS mode must present such a certificate. Both failures return `403 client_certificate_mismatch`. A TLS client certificate that no longer verifies on an already open connection is reported at the same step: `403 agent_revoked` when its serial is revoked or unknown, `403 client_certificate_mismatch` otherwise (for example expired). On the unsigned paths of §5 such a request gets a plain `403`. An agent treats a verified `403 agent_revoked` as final: it stops polling and exits with a non-zero status. While it remembers that answer it connects without its client certificate (the server refuses the handshake of a revoked certificate), waits 5 minutes before the first request after a start, doubled per further start up to 1 hour, and forgets the answer after a successful request or a `403 client_certificate_mismatch`.

## 7. Errors

Errors are JSON `{code, message}`. They are signed whenever the request carried a well-formed `Bomcensus-Nonce`; an agent treats an unsigned or wrongly signed response as a transport failure, whatever its status.

| Status | Code | Cause |
|---|---|---|
| 400 | `invalid_request` | malformed path, missing or malformed signature headers, counter on `GET` or missing elsewhere |
| 400 | `digest_mismatch` | `Content-Digest` does not match the body |
| 401 | `unauthorized` | unknown agent, bad signature, `keyid`/`alg` mismatch, `created` out of range |
| 401 | `nonce_replayed` | nonce seen before |
| 403 | `agent_pending`, `agent_revoked`, `client_certificate_mismatch` | §5, §6 |
| 409 | `counter_replayed` | §4 |
| 413 | `body_too_large` | request body above the server limit (default 256 MiB) |
| 500 | `internal_error` | includes a response above the buffering limit |

## 8. Worked example

Agent key: Ed25519 seed `9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60` (hex). Server key: Ed25519 seed `4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb`, keyid `3rLe053Cb84OYIW2_DS_a1lBkTu_4uphQRPP-eAEwXA`. The values are checked by `internal/msgsig` tests.

Request `POST /agent/v1/poll`, body `{"version":"1.4.0"}` (19 bytes), counter 42:

```
Content-Digest: sha-256=:hHLDpmZRqj18Pee9aZwud5GWiY+vo9LyA9at7ai1alw=:
Bomcensus-Agent-Id: a7Kq2mXr
Bomcensus-Nonce: AAECAwQFBgcICQoLDA0ODw
Bomcensus-Counter: 42
Signature-Input: sig1=("@method" "@path" "@query" "content-digest" "bomcensus-agent-id" "bomcensus-nonce" "bomcensus-counter");created=1795305600;keyid="a7Kq2mXr";alg="ed25519"
Signature: sig1=:owyZTbCYmk8RuvrCbcNGSZWZPdwg1/Vv5XOG4XlYMR9tFkzYRqRl6Yt1+EF1TYyZkQiOUeDhEXAIclMvcYsHDQ==:
```

Signature base:

```
"@method": POST
"@path": /agent/v1/poll
"@query": ?
"content-digest": sha-256=:hHLDpmZRqj18Pee9aZwud5GWiY+vo9LyA9at7ai1alw=:
"bomcensus-agent-id": a7Kq2mXr
"bomcensus-nonce": AAECAwQFBgcICQoLDA0ODw
"bomcensus-counter": 42
"@signature-params": ("@method" "@path" "@query" "content-digest" "bomcensus-agent-id" "bomcensus-nonce" "bomcensus-counter");created=1795305600;keyid="a7Kq2mXr";alg="ed25519"
```

Response `200`, body `{"directives":[]}` (17 bytes):

```
Content-Digest: sha-256=:awmRrw3eXfkm3+nMmhZVhqda2RjhepllY0H7Fm+a47o=:
Bomcensus-Request-Nonce: AAECAwQFBgcICQoLDA0ODw
Signature-Input: sig1=("@status" "content-digest" "bomcensus-request-nonce");created=1795305601;keyid="3rLe053Cb84OYIW2_DS_a1lBkTu_4uphQRPP-eAEwXA";alg="ed25519"
Signature: sig1=:8L1ck4U7HSnimM9ez0ralZ6OEyNprl1gwPtD2k2bnxpYH7hcqYIt8252FOsABB9OPg+6HbvBomt/rSfwljt/DA==:
```

Signature base:

```
"@status": 200
"content-digest": sha-256=:awmRrw3eXfkm3+nMmhZVhqda2RjhepllY0H7Fm+a47o=:
"bomcensus-request-nonce": AAECAwQFBgcICQoLDA0ODw
"@signature-params": ("@status" "content-digest" "bomcensus-request-nonce");created=1795305601;keyid="3rLe053Cb84OYIW2_DS_a1lBkTu_4uphQRPP-eAEwXA";alg="ed25519"
```

## 9. Sealed directive secrets

Credentials in scanner directives are encrypted to the scanner's encryption key with HPKE (RFC 9180), base mode, single shot, independent of TLS (SECURITY §4.7, §7.4).

Suite: DHKEM(X25519, HKDF-SHA256) `0x0020`, HKDF-SHA256 `0x0001`, AES-256-GCM `0x0002`. The scanner generates the key pair at enrollment, keeps the private key in its state directory and sends the public key as `hpke_public_key` of `enroll/start`: the 32-byte X25519 encoding (RFC 9180 `SerializePublicKey`).

A `SealedSecret` (JSON `format: byte`) is:

```
0x01 ‖ enc (32 bytes) ‖ ciphertext
```

`0x01` is the format version, `enc` the encapsulated key and `ciphertext` the AEAD output (plaintext plus a 16-byte tag), sealed with empty AAD. Any other version byte, a short value or a failed open is rejected; the scanner then reports the job as failed with reason `secret_unavailable` and runs nothing.

The HPKE `info` binds a value to its recipient, job and field:

```
info = "bomcensus directive secret v1" ‖ L(scanner id) ‖ L(job id) ‖ L(field)
L(x) = uint16 big-endian length of x ‖ x
```

The label is ASCII without terminator. The scanner id is its agent id from enrollment, the job id is the directive's `job_id`.

| Directive | Field | `field` | Plaintext |
|---|---|---|---|
| `scan_ssh` | `credential` | `credential` | `SSHCredentialSecret` as JSON |
| `k8s_sync`, `k8s_exec` | `kubeconfig` (only with `connection=kubeconfig`) | `kubeconfig` | kubeconfig YAML |

The scanner keeps opened secrets in memory only, for the duration of the job.

SSH host keys (SECURITY §7.1). `host_key` is an SSH public key in wire format (RFC 4253 §6.6) and `host_key_fingerprint` is `SHA256:` followed by the unpadded standard base64 of its SHA-256.

- `scan_ssh` carries both when the target has a pinned key. The scanner checks that they match and accepts only that key in the handshake, before any credential is sent. A fingerprint without `host_key` is refused (reason `host_key_unavailable`). Without either, the scanner accepts the first key it is offered.
- The result of a `scan_ssh` job carries the key the target presented in both fields whenever the handshake reached it, including a `host_key_changed` failure. A key different from the pinned one fails the job with reason `host_key_changed`; it is not retried. The server pins the reported key on the first `ok` or `partial` result of a target without a pinned key. A pinned key changes only after an administrator clears it.

Result messages of failed and partial jobs start with a reason code: `<code>: <detail>`, `code` in `[a-z_]+`.
