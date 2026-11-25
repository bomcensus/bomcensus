# Extending bomcensus

bomcensus can be built from a Go module of your own: a server with your authentication and authorization, and agents and scanners that reach the server over a channel of your own. `examples/custom-server` is a complete example.

```sh
go get github.com/bomcensus/bomcensus@vX.Y.Z
```

| Package | Use |
|---|---|
| `server` | `server.Main` and `server.Run` with `server.Options` |
| `server/config` | the server configuration (`BOMCENSUS_*` variables, or filled by your program) |
| `server/auth` | `Principal`, `WithPrincipal`, `FromContext`, `PasswordProvider` |
| `server/authz` | `Authorizer`, the operation ids (`authz.Op*`) |
| `server/scope` | data scopes (`scope.All`, `scope.Of`) |
| `server/apierror` | writing errors in the admin API format |
| `agent`, `scanner` | `agent.Main`, `scanner.Main` with your channels |
| `agentproto` | the agent protocol as operations (`API`), its errors, and the interfaces of channels (`Gateway`, `Server`, `Agents`, `ChannelFactory`, `Channel`) |
| `agentproto/dto` | the DTOs of the agent protocol (generated from `api/openapi/agent.yaml`) |
| `agentproto/conformance` | the check for the DTO conversion of channel adapters |

Everything under `internal/` may change at any time. The packages above are the API; their changes are listed in the release notes.

## 1. The server

`cmd/bomcensus-server` is:

```go
server.Main(server.Options{Console: server.EmbeddedConsole(), Session: &server.Session{}})
```

`server.Main` provides the same commands (`serve`, `migrate`, `hash-password`, `bootstrap-scanner`, `healthcheck`, `version`) and reads the same environment variables ([DEPLOYMENT.md](DEPLOYMENT.md)). With the zero `Options` the server serves the admin API only: no console, no `/api/v1/auth/login`, and every request needs a principal from `APIMiddleware`.

| Option | Effect |
|---|---|
| `Console` | the web console; `nil` serves none |
| `Session` | the built-in login with cookie sessions; `nil` disables it (`login` and `logout` answer 404) |
| `APIMiddleware` | `func(http.Handler) http.Handler` run on every `/api/v1` request, after the session cookie and before authorization |
| `Authorizer` | decides every operation and returns its data scope; `nil` allows everything to every principal |
| `Mounts` | further handlers by path prefix outside `/api` (for example an OIDC callback) |
| `WebListener`, `AgentListener` | listeners to use instead of binding the configured addresses |
| `AgentGateways`, `NoAgentListener` | agent channels (§3) |

### 1.1 Authentication

A middleware authenticates and puts the caller into the request context:

```go
func verifyJWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := parseBearer(r)
		if err != nil {
			apierror.Unauthenticated(w, "invalid token")
			return
		}
		next.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), User{claims})))
	})
}
```

`auth.Principal` is an interface with `ID()` and `Name()`. bomcensus stores `ID()` with the records a principal creates and shows `Name()`; your type carries everything else (roles, groups, tenants) for your Authorizer. A request without a principal gets 401 on every operation except the public ones (`authz.IsPublic`).

The CSRF check (`X-Requested-With: bomcensus`) applies only to requests authenticated by the session cookie and to the login request. Requests authenticated by your middleware do not carry ambient credentials and are not checked; if your middleware reads a cookie, protect it yourself.

The built-in login takes a `server.Session.Provider` (`auth.PasswordProvider`, for example LDAP) and a `Restore` function that turns a stored session back into your principal type.

### 1.2 Authorization

```go
type Authorizer interface {
	Authorize(ctx context.Context, p auth.Principal, req authz.Request) (authz.Decision, error)
}
```

It is called once per request, before the handler, with the operation id from `api/openapi/admin.yaml` (`authz.OpListAssets`, ...; `authz.Operations()` lists them), the method, the path and its parameters. Return an error wrapping `authz.ErrForbidden` to deny (403); any other error is a 500.

`Decision.Scope` is the data the request may see (§2). The zero `Decision` has the empty scope: lists are empty and every scoped record is not found. Global data (vulnerability advisories, feeds, PKI and TLS settings, releases, update settings, integrity policy, detection directories, scanners) is not scoped; deny the operations that change it to principals that may not.

## 2. Data scopes

Every scoped record belongs to one scope id, which you choose (tenant, team, organization): `scopeId` in the admin API.

| Records | Scope |
|---|---|
| Register Keys, scan targets, Kubernetes clusters, credentials, listen targets | chosen at creation (`scopeId` in the request) |
| agents | the scope of the Register Key they enrolled with |
| host assets | the scope of their agent or scan target |
| workload assets, workloads, pods | the scope of their cluster |
| components, processes, containers, findings, integrity results, reports | the scope of their asset |
| images | visible to a scope when one of its assets or pods uses them |
| triage rules, integrity allow rules | the scope they are created in; they apply only to findings and assets of that scope |
| scanners and their Register Keys | shared: visible to every scope, changed only with `scope.All` |

A new record gets the requested `scopeId` if it is in the request scope, else the only id of the scope, else `default` for `scope.All`; a request with several ids must name one. A request for a record outside its scope gets 404; creating a record outside it, or referring to a credential of another scope, gets 403. Records that existed before scopes are in `default`.

The store enforces the scope on every query and fails when a request has none, so a missing scope is an error and never a leak. Moving records between scopes is not supported yet.

## 3. Agent channels

The agent protocol is a set of operations, `agentproto.API` (the operations of `api/openapi/agent.yaml`), with the DTOs of `agentproto/dto`. A channel carries them between agent and server; it is an adapter with an agent end and a server end. The built-in HTTP channel is the protocol of [PROTOCOL.md](PROTOCOL.md): HTTPS under `/agent/v1`, requests and responses signed with HTTP Message Signatures. A channel of your own may use any transport, for example gRPC with protobuf messages converted from and to the DTOs.

The adapter owns the wire, including how requests and answers are authenticated. The server's operations check what does not depend on it: the agent's state (a pending agent may only ask for its enrollment result, a revoked one for nothing), the operations reserved for scanners, and the enrollment protocol. Enrollment messages are signed by the server and with the Register Key over their exact bytes, so `EnrollStart` and `EnrollFinish` carry bytes, which a channel passes unchanged.

Server side, in `server.Options`:

- `AgentGateways []agentproto.Gateway`: `Run(ctx, s)` gets an `agentproto.Server` with `API`, the operations, and `Agents`: the identity key and state of an agent, its request counter, the server's response signing key and Agent TLS certificate, and the check of agent certificates. The gateway authenticates each request, then calls `s.API` with the agent (`agentproto.WithAgent`) and the connection facts (`agentproto.WithPeer`) in the context. Calls without an agent are refused, except `EnrollStart`, `EnrollFinish` and `GetServerChain`.
- `NoAgentListener`: turns off the built-in HTTP listener. Listen-mode targets are still dialed with the HTTP channel.

Agent side, in `agent.Options.Channels` (and `scanner.Options.Channels`): `agentproto.ChannelFactory` by name. The agent enrolls with

```sh
bomcensus-agent enroll --channel NAME --channel-setting key=value --server ADDRESS --server-name NAME --token bc1....
```

and keeps the channel. The factory gets `agentproto.ChannelParams`: the enrollment's server address and name, the settings, `VerifyServer` for the server's certificate chain (against the anchor of the enrollment string, later against the trust bundle), the agent certificate, and `Identity`, the agent id and identity key to authenticate calls with. It returns an `agentproto.Channel`.

A channel must:

- authenticate the server and return `*agentproto.Error` only for answers it authenticated, with `Status`, `Code` and `Message` as the server gave them. The agent acts on them; an `agent_revoked` answer stops it;
- authenticate every request except the three above as the agent and protect it against replay, for example with a signature by `Identity` verified with `Agents.AgentKey`, or with the agent certificate verified with `Agents.VerifyCertificate`. When `AgentKey.RequireCertificate` is set, the agent holds a certificate and its Register Key does not allow relaxed TLS: accept its requests only on a connection authenticated with that certificate;
- report the remote address in `agentproto.Peer` only if it can vouch for it (Register Key address limits refuse an unknown address);
- carry every DTO field. Run `conformance.Run(t, roundTrip)` with your conversion in your tests; it checks samples of every DTO and fails when your adapter misses a field, also after bomcensus adds one;
- allow at least two minutes per call (the long poll) and bound what it reads.

`examples/custom-server/framechannel` is a complete channel: TLS with the Agent TLS certificate, the agent certificate when there is one, and an identity-key signature with a timestamp and a nonce on every request.

## 4. Signing your own agent

An agent or scanner built with its own channels is not an official bomcensus binary and cannot be signed with the official keys. It must be built with the trust of your own release keys: without release keys and code-signing roots compiled in, or with the official release keys compiled in, it refuses to run. Updates, probe delivery and the updater all verify against the compiled trust, so every component on your hosts is signed with your keys:

```sh
go run github.com/bomcensus/bomcensus/cmd/bomcensus-release@vX.Y.Z keygen --out keys
trust=$(go run github.com/bomcensus/bomcensus/cmd/bomcensus-release@vX.Y.Z print-ldflags --keys keys)

# Your agent and scanner, and the stock probe and updater, with that trust.
go build -ldflags "$trust" -o bundle/linux-amd64/bomcensus-agent ./cmd/agent
for c in bomcensus-probe bomcensus-updater bomcensus-scanner; do
	go build -ldflags "$trust" -o bundle/linux-amd64/$c github.com/bomcensus/bomcensus/cmd/$c
done

go run github.com/bomcensus/bomcensus/cmd/bomcensus-release@vX.Y.Z sign-elf \
	--key keys/codesign.key --cert keys/codesign.crt bundle/linux-amd64/*
go run github.com/bomcensus/bomcensus/cmd/bomcensus-release@vX.Y.Z bundle \
	--version X.Y.Z --manifest-key keys/manifest.key --dir bundle --out bomcensus-X.Y.Z.tar
```

Build the server with the same `-ldflags "$trust"`: it verifies the bundles it imports (`BOMCENSUS_RELEASE_DIR`, or uploads in the console API) with its compiled trust. Keep `keys/manifest.key` and `keys/codesign-ca.key` offline; installed agents trust only the keys compiled into them, so keep the same keys across releases ([RELEASING.md](RELEASING.md) §3 describes rotation).

## 5. Licensing

bomcensus is dual-licensed under the AGPL-3.0-only and a commercial license ([LICENSING.md](../LICENSING.md)). A modified server that users reach over a network is subject to AGPL §13 unless you hold the commercial license.
