# Custom server and agent

An example of building bomcensus from your own module:

- `tokenauth`: admin API authentication with bearer tokens (`server.Options.APIMiddleware`) and an `authz.Authorizer` with roles and tenant scopes.
- `framechannel`: an agent channel without HTTP, the operations of `agentproto.API` as length-prefixed JSON frames over TLS. It implements `agentproto.Gateway` on the server and `agentproto.ChannelFactory` on the agent, and authenticates both directions itself: the server's Agent TLS certificate verified against the agent's enrollment anchor, the agent certificate when there is one, and an identity-key signature with a timestamp and a nonce on every request. Its test runs the DTOs through `agentproto/conformance`.
- `cmd/server`: the server with both, without the console and the cookie login.
- `cmd/agent`: the agent with the frame channel. Build it with your own release keys; see [docs/EXTENDING.md](../../docs/EXTENDING.md).

```sh
go test ./...
go build ./cmd/...
```
