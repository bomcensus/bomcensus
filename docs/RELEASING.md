<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

# Releasing

A release is published by pushing a tag `vMAJOR.MINOR.PATCH` (or `vMAJOR.MINOR.PATCH-PRERELEASE`, published as a pre-release). The workflow `.github/workflows/release.yml` first runs CI (`ci.yml`) and then has three jobs: `build` builds and signs everything below (the only job with access to the signing keys), `windows` runs the Windows binaries and the installer on Windows runners (x64 and arm64), and `publish` pushes images and charts, writes the attestations and creates the release. The GitHub release is created last, so it exists only when every step passed. Steps that fail after images, charts or attestations were pushed leave those on ghcr.io and GitHub without a release; a re-run of the same tag pushes them again and replaces the release assets.

## 1. What is published

Images are named after the GitHub repository (`ghcr.io/OWNER/REPO/<image>`) and charts after its owner (`ghcr.io/OWNER/charts/<chart>`), in lower case; below they are written for `bomcensus/bomcensus`.

| Artifact | Where | Code signature | Provenance |
|---|---|---|---|
| `<command>_VERSION_linux_{amd64,arm64}`: server, agent, probe, updater, scanner, release | GitHub release | AuthentiELF, timestamped | attestation |
| `<command>_VERSION_windows_{amd64,arm64}.exe`: the same commands | GitHub release | Authenticode (jsign), timestamped | attestation |
| `bomcensus-VERSION.tar`: agent bundle (agent, probe, updater, scanner for linux and windows, amd64 and arm64) | GitHub release, and inside the server image | Ed25519 manifest signature; the files inside are the signed binaries above | attestation |
| `bomcensus-systemd_VERSION.tar.gz`: units, `install.sh`, `uninstall.sh` | GitHub release | — | attestation |
| `bomcensus-windows_VERSION.zip`: `install.ps1`, `uninstall.ps1` | GitHub release | — | attestation |
| `bomcensus-compose_VERSION.tar.gz`: `compose.yaml`, `.env.example`, `init.sh` of `deploy/docker` | GitHub release | — | attestation |
| `install.sh`: the `curl \| bash` installer for the server and the agent (`scripts/install.sh`, see DEPLOYMENT.md, Quick install) | GitHub release | — | attestation |
| `bomcensus-{manager,scanner}-VERSION.tgz` | GitHub release | — | attestation |
| `SHA256SUMS` of all of the above | GitHub release | — | — |
| `ghcr.io/bomcensus/bomcensus/{server,scanner,agent}:VERSION` (and `:latest` for releases that are not pre-releases), linux/amd64 and linux/arm64 | GitHub Container Registry | cosign (keyless) | attestation, BuildKit provenance and SBOM |
| `oci://ghcr.io/bomcensus/charts/bomcensus-{manager,scanner}` version `VERSION` | GitHub Container Registry | cosign (keyless) | attestation |

The images are not built from source again: they take the signed binaries and the bundle of the same run (build context `dist` of `deploy/docker/Dockerfile`). The charts are packaged by `scripts/package-charts.sh` with `version` and `appVersion` set to `VERSION` and the default images pointing to the images above.

Attestations are SLSA build provenance statements signed with a Sigstore certificate bound to the workflow run. They are stored with GitHub and, for images and charts, pushed to the registry next to the artifact.

## 2. Verifying

```sh
# A downloaded file (binary, bundle, chart, systemd archive):
gh attestation verify bomcensus-server_1.2.3_linux_amd64 --repo bomcensus/bomcensus

# An image or chart:
gh attestation verify oci://ghcr.io/bomcensus/bomcensus/server:1.2.3 --repo bomcensus/bomcensus
cosign verify ghcr.io/bomcensus/bomcensus/server:1.2.3 \
    --certificate-identity-regexp '^https://github.com/bomcensus/bomcensus/\.github/workflows/release\.yml@refs/tags/v' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Code signatures:
authentielf verify bomcensus-agent_1.2.3_linux_amd64
osslsigncode verify -in bomcensus-agent_1.2.3_windows_amd64.exe
Get-AuthenticodeSignature .\bomcensus-agent_1.2.3_windows_amd64.exe   # on Windows

# The agent bundle, with the trust compiled into the release tool of the same release:
./bomcensus-release_1.2.3_linux_amd64 verify bomcensus-1.2.3.tar
```

## 3. Repository configuration

The release job runs in the GitHub environment **`signed-release`**. Protect it (required reviewers, deployment tag rule `v*`), because it holds the signing access.

| Name | Kind | Content |
|---|---|---|
| `GCP_PROJECT_ID` | secret | Google Cloud project of the signing key |
| `GCP_WIF_PROVIDER` | secret | Workload Identity Federation provider for this repository |
| `GCP_KMS_SERVICE_ACCOUNT` | secret | service account with `roles/cloudkms.signerVerifier` and `roles/cloudkms.viewer` on both keys |
| `SIGN_KEY_FILE` | secret | `gcp-kms://projects/P/locations/L/keyRings/R/cryptoKeys/K[/cryptoKeyVersions/N]`, the code-signing key |
| `SIGN_CERT` | variable | PEM: the code-signing certificate of that key, then its intermediates |
| `CODESIGN_ROOTS` | variable | PEM: the root certificate(s) that `SIGN_CERT` chains to. Compiled into every binary as the code-signing trust |
| `MANIFEST_KEY_FILE` | secret | `gcp-kms://projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/N`, the release manifest key (algorithm `EC_SIGN_ED25519`). Its public key is compiled into every binary |

The same key and certificate sign the Linux binaries (AuthentiELF) and the Windows binaries (Authenticode), as in the AuthentiELF project. Timestamps come from `http://timestamp.digicert.com`. The key must be RSA with PKCS #1 v1.5 padding (`RSA_SIGN_PKCS1_*`) or ECDSA: agents and the server verify Windows signatures themselves and do not accept RSA-PSS. Windows timestamps must be RFC 3161 counter-signatures (`scripts/sign-pe.sh` runs jsign with `--tsmode RFC3161`).

Creating the manifest key, once (the key never leaves Cloud KMS; `bomcensus-release bundle` and `manifest-pub` use it through the API with `$GOOGLE_OAUTH_ACCESS_TOKEN`):

```sh
gcloud kms keys create bomcensus-manifest --keyring R --location L \
    --purpose asymmetric-signing --default-algorithm ec-sign-ed25519
```

Use the key version (`.../cryptoKeyVersions/1`), not the key: binaries trust exactly that version's public key.

**List the manifest key in `internal/sign/official.go`** (the output of `bomcensus-release manifest-pub`, without the PEM lines) before the first release with it. `scripts/release.sh` stops when the key is missing (`bomcensus-release check-official`). Agents and scanners built with their own channels refuse to start when they trust a listed key, so they are always signed with their builder's own keys ([EXTENDING.md](EXTENDING.md#4-signing-your-own-agent)).

**Keep the manifest key and `CODESIGN_ROOTS` the same across releases.** Installed agents and scanners trust only the manifest public key and roots compiled into them; a release signed with another manifest key, or with a certificate under another root, cannot update them. Rotating the manifest key needs a release that trusts both keys (`bomcensus-release print-ldflags` takes `manifest*.pub`); the workflow does not do that yet.

## 4. Local build

`scripts/release.sh` is what the workflow runs. Every key can also be a PEM file instead of a Cloud KMS key; with the development keys of `make release-dev`, signing the Windows files with the release tool instead of jsign:

```sh
K=.devstate/devkeys
MANIFEST_KEY_FILE=$K/manifest.key CODESIGN_ROOTS_FILE=$K/codesign-ca.crt \
SIGN_KEY_FILE=$K/codesign.key SIGN_CERT_FILE=$K/codesign.crt \
PE_SIGNER=go ALLOW_UNOFFICIAL_KEYS=1 make release VERSION=1.2.3
```

It needs Go, Node with pnpm, `zip` and the `authentielf` CLI (`go install github.com/jc-lab/authentielf/cmd/authentielf@v0.0.1`). The workflow signs Windows files with jsign (`JSIGN="java -jar jsign.jar"`, the default `PE_SIGNER`), which also takes Cloud KMS keys. Output: `dist/release/assets` and `dist/release/docker`. Images from that output:

```sh
VERSION=1.2.3 DIST=dist/release/docker docker buildx bake -f deploy/docker/docker-bake.hcl --load
scripts/package-charts.sh 1.2.3 ghcr.io/bomcensus/bomcensus dist/charts
```
