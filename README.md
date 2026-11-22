# bomcensus

[한국어](README.ko.md)

bomcensus collects the software installed and running on servers, containers, and Kubernetes, manages it as SBOMs, and matches it against vulnerability advisories.

## Status

Implemented: Linux agents (connect and listen mode), agentless collection over SSH, Kubernetes inventory and exec collection, automatic agent updates, and the web console. Not implemented yet: vulnerability matching, SBOM export and Windows support.

## Getting started

- `make demo-up`: a local demo with example data at http://localhost:8080 (admin / demo), see [DEPLOYMENT.md §2.9](docs/DEPLOYMENT.md#29-demo).
- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md): building and running the server, agents and scanners with Docker Compose, Helm or systemd.
- [docs/SECURITY.md](docs/SECURITY.md): security design, privileges and known limitations.
- [docs/PROTOCOL.md](docs/PROTOCOL.md): signatures and sealed secrets on the agent protocol.
- [docs/RELEASING.md](docs/RELEASING.md): published images, charts and binaries, and how to verify them.

## License

bomcensus is dual-licensed under the [AGPL-3.0-only](LICENSE) and a commercial license from JC-Lab. See [LICENSING.md](LICENSING.md).

"bomcensus" is a trademark of JC-Lab. See [LICENSING.md](LICENSING.md#trademarks).

Contributions require a signed CLA. See [CONTRIBUTING.md](CONTRIBUTING.md).
