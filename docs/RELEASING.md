<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

# Releasing

A release is published by pushing a tag `vMAJOR.MINOR.PATCH` (or `vMAJOR.MINOR.PATCH-PRERELEASE`, published as a pre-release). The workflow `.github/workflows/release.yml` first runs CI (`ci.yml`) and then builds, signs and publishes everything below. The GitHub release is created last, so it exists only when every step passed. Steps that fail after images, charts or attestations were pushed leave those on ghcr.io and GitHub without a release; a re-run of the same tag pushes them again and replaces the release assets.

## 1. What is published

Images are named after the GitHub repository (`ghcr.io/OWNER/REPO/<image>`) and charts after its owner (`ghcr.io/OWNER/charts/<chart>`), in lower case; below they are written for `bomcensus/bomcensus`.

| Artifact | Where | Code signature | Provenance |
|---|---|---|---|
| `<command>_VERSION_linux_{amd64,arm64}`: server, agent, probe, updater, scanner, release | GitHub release | AuthentiELF, timestamped | attestation |
| `bomcensus-release_VERSION_windows_{amd64,arm64}.exe` | GitHub release | Authenticode (jsign), timestamped | attestation |
| `bomcensus-VERSION.tar`: agent bundle (agent, probe, updater, scanner for both architectures) | GitHub release, and inside the server image | Ed25519 manifest signature; the files inside are the AuthentiELF-signed binaries above | attestation |
| `bomcensus-systemd_VERSION.tar.gz`: units, `install.sh`, `uninstall.sh` | GitHub release | — | attestation |
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
osslsigncode verify -in bomcensus-release_1.2.3_windows_amd64.exe

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

The same key and certificate sign the Linux binaries (AuthentiELF) and the Windows binaries (Authenticode), as in the AuthentiELF project. Timestamps come from `http://timestamp.digicert.com`.

Creating the manifest key, once (the key never leaves Cloud KMS; `bomcensus-release bundle` and `manifest-pub` use it through the API with `$GOOGLE_OAUTH_ACCESS_TOKEN`):

```sh
gcloud kms keys create bomcensus-manifest --keyring R --location L \
    --purpose asymmetric-signing --default-algorithm ec-sign-ed25519
```

Use the key version (`.../cryptoKeyVersions/1`), not the key: binaries trust exactly that version's public key.

**Keep the manifest key and `CODESIGN_ROOTS` the same across releases.** Installed agents and scanners trust only the manifest public key and roots compiled into them; a release signed with another manifest key, or with a certificate under another root, cannot update them. Rotating the manifest key needs a release that trusts both keys (`bomcensus-release print-ldflags` takes `manifest*.pub`); the workflow does not do that yet.

## 4. Local build

`scripts/release.sh` is what the workflow runs. Every key can also be a PEM file instead of a Cloud KMS key; with the development keys of `make release-dev` (no Windows build):

```sh
K=.devstate/devkeys
MANIFEST_KEY_FILE=$K/manifest.key CODESIGN_ROOTS_FILE=$K/codesign-ca.crt \
SIGN_KEY_FILE=$K/codesign.key SIGN_CERT_FILE=$K/codesign.crt \
RELEASE_WINDOWS=0 make release VERSION=1.2.3
```

It needs Go, Node with pnpm and the `authentielf` CLI (`go install github.com/jc-lab/authentielf/cmd/authentielf@v0.0.1`); the Windows build also needs jsign (`JSIGN="java -jar jsign.jar"`), which cannot load the EC development key, so a test needs an RSA certificate. Output: `dist/release/assets` and `dist/release/docker`. Images from that output:

```sh
VERSION=1.2.3 DIST=dist/release/docker docker buildx bake -f deploy/docker/docker-bake.hcl --load
scripts/package-charts.sh 1.2.3 ghcr.io/bomcensus/bomcensus dist/charts
```
