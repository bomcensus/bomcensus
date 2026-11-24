# bomcensus

[한국어](README.ko.md)

bomcensus collects the software installed and running on servers, containers, and Kubernetes, manages it as SBOMs, and matches it against vulnerability advisories.

## Status

Implemented: Linux agents (connect and listen mode), agentless collection over SSH, Kubernetes inventory and exec collection, automatic agent updates, and the web console. All commands build and run on Windows (amd64, arm64); a Windows agent reports the host identity only. Not implemented yet: vulnerability matching, SBOM export, software collection on Windows and Windows scan targets.

## Install

The latest stable release, with one command each (Linux; the server needs Docker with the compose plugin, the agent needs root and systemd):

```sh
# Server (PostgreSQL + bomcensus in Docker Compose)
curl -fsSL https://github.com/bomcensus/bomcensus/releases/latest/download/install.sh \
    | bash -s -- server --env AGENT_SERVER_NAMES=bomcensus.example.com

# Host agent, with the enrollment string of a Register Key
curl -fsSL https://github.com/bomcensus/bomcensus/releases/latest/download/install.sh \
    | sudo BOMCENSUS_TOKEN=bc1.... bash -s -- agent --server https://bomcensus.example.com:8443
```

`--rc` also considers pre-releases, `--version X.Y.Z` pins a version, and `--attest prefer|required|disabled` controls the build provenance check with the GitHub CLI (default `prefer`: verify when `gh` is installed and logged in). Details and server options: [DEPLOYMENT.md, Quick install](docs/DEPLOYMENT.md#quick-install).

## Getting started

- `make demo-up`: a local demo with example data at http://localhost:8080 (admin / demo), see [DEPLOYMENT.md §2.9](docs/DEPLOYMENT.md#29-demo).
- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md): building and running the server, agents and scanners with Docker Compose, Helm, systemd or Windows services.
- [docs/SECURITY.md](docs/SECURITY.md): security design, privileges and known limitations.
- [docs/PROTOCOL.md](docs/PROTOCOL.md): signatures and sealed secrets on the agent protocol.
- [docs/RELEASING.md](docs/RELEASING.md): published images, charts and binaries, and how to verify them.

## License

bomcensus is dual-licensed under the [AGPL-3.0-only](LICENSE) and a commercial license from JC-Lab. See [LICENSING.md](LICENSING.md).

"bomcensus" is a trademark of JC-Lab. See [LICENSING.md](LICENSING.md#trademarks).

Contributions require a signed CLA. See [CONTRIBUTING.md](CONTRIBUTING.md).
