# Copyright (C) 2026 JC-Lab
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
# Additional terms apply. See LICENSING.md.

# Images of bomcensus. Build with the repository root as context:
#
#   docker buildx build -f deploy/docker/Dockerfile --target server .
#
# Targets: server, scanner, agent. The console and Go stages run on the
# build platform and cross-compile, so --platform linux/arm64 on an amd64
# host needs no emulation for them (the agent target runs a few shell
# commands in its own stage and does).
#
# Release keys: pass the directory written by `bomcensus-release keygen` as a
# tar in the BuildKit secret "release_keys":
#
#   tar -C KEYDIR -cf keys.tar . && docker buildx build --secret id=release_keys,src=keys.tar ...
#
# BuildKit does not include secrets in the cache key, so the build argument
# RELEASE_KEYS_ID must name the key set: the SHA-256 (hex) of manifest.pub
# from the tar (make docker-build computes it). The build fails when the two
# do not match.
#
# Without the secret, throwaway keys are generated inside the build step and
# discarded with it. Images built that way only trust bundles from the same
# build, so build all targets with the same builder in one go
# (deploy/docker/docker-bake.hcl, `make docker-build`).

ARG GO_VERSION=1.26.3
ARG NODE_VERSION=26
ARG DEBIAN_RELEASE=trixie

# ---------------------------------------------------------------------------
# Console: static Nuxt output.
FROM --platform=$BUILDPLATFORM node:${NODE_VERSION}-${DEBIAN_RELEASE}-slim AS console
ENV CI=true NUXT_TELEMETRY_DISABLED=1 PNPM_STORE_DIR=/pnpm-store
WORKDIR /src/frontend
COPY frontend/package.json frontend/pnpm-lock.yaml ./
# The pnpm version is the packageManager field of package.json.
RUN npm install -g --no-fund --no-audit "$(node -p 'require("./package.json").packageManager')"
RUN --mount=type=cache,id=bomcensus-pnpm,target=/pnpm-store \
    pnpm config set store-dir /pnpm-store && pnpm fetch --frozen-lockfile
COPY frontend/ ./
RUN --mount=type=cache,id=bomcensus-pnpm,target=/pnpm-store \
    pnpm config set store-dir /pnpm-store \
    && pnpm install --offline --frozen-lockfile \
    && pnpm exec nuxt generate \
    && test -f .output/public/index.html

# ---------------------------------------------------------------------------
# Go build: every command for linux/amd64 and linux/arm64, the trust
# compiled in, the target-side commands AuthentiELF-signed and bundled.
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-${DEBIAN_RELEASE} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,id=bomcensus-gomod,target=/go/pkg/mod \
    go mod download
COPY . .
COPY --from=console /src/frontend/.output/public/ internal/server/console/dist/
ARG VERSION=0.0.0-dev
ARG RELEASE_KEYS_ID=
# The keys live on a tmpfs for the duration of this step only; nothing of
# them is left in a layer or in the build cache.
RUN --mount=type=cache,id=bomcensus-gomod,target=/go/pkg/mod \
    --mount=type=cache,id=bomcensus-gobuild,target=/root/.cache/go-build \
    --mount=type=secret,id=release_keys,required=false \
    --mount=type=tmpfs,target=/keys \
    set -eu; \
    if [ -s /run/secrets/release_keys ]; then \
        mkdir /keys/in; \
        tar -xf /run/secrets/release_keys -C /keys/in; \
        found=$(find /keys/in -name manifest.key -type f | head -n 1); \
        if [ -z "$found" ]; then echo "release_keys: no manifest.key in the tar" >&2; exit 1; fi; \
        keys=$(dirname "$found"); \
        id=$(sha256sum "$keys/manifest.pub" | cut -c1-64); \
        if [ "$id" != "$RELEASE_KEYS_ID" ]; then \
            echo "release_keys: RELEASE_KEYS_ID must be the SHA-256 of manifest.pub ($id)" >&2; exit 1; \
        fi; \
        echo "release keys: taken from the release_keys secret (manifest.pub $id)"; \
    else \
        if [ -n "$RELEASE_KEYS_ID" ]; then echo "release_keys: RELEASE_KEYS_ID is set but the secret is missing" >&2; exit 1; fi; \
        keys=/keys/dev; \
        echo "release keys: NO release_keys SECRET GIVEN, generating throwaway development keys (images of this build trust only bundles of this build)"; \
    fi; \
    make release-dev VERSION="$VERSION" RELEASE_DEVKEYS="$keys" \
        RELEASE_STAGE=build/release DIST=dist RELEASE_ARCHES="amd64 arm64"; \
    mkdir -p /out/release; \
    cp "dist/bomcensus-$VERSION.tar" /out/release/; \
    cp dist/bomcensus-server-linux-amd64 dist/bomcensus-server-linux-arm64 /out/; \
    cp -R build/release/bundle /out/bundle

# release-dev skips commands that are missing from the tree; the scanner
# target fails here instead of later with an unclear COPY error.
FROM --platform=$BUILDPLATFORM debian:${DEBIAN_RELEASE}-slim AS scanner-bin
COPY --from=build /out/bundle/ /bundle/
RUN test -x /bundle/linux-amd64/bomcensus-scanner && test -x /bundle/linux-arm64/bomcensus-scanner \
    || { echo "bomcensus-scanner was not built: cmd/bomcensus-scanner does not exist" >&2; exit 1; }
# Empty state directory for the scanner image, which has no shell to make one.
RUN mkdir /state

# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian13:nonroot AS server
ARG TARGETARCH
ARG VERSION=0.0.0-dev
LABEL org.opencontainers.image.title="bomcensus-server" \
      org.opencontainers.image.description="bomcensus server: console, API, agent gateway and embedded scanner" \
      org.opencontainers.image.source="https://github.com/bomcensus/bomcensus" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="AGPL-3.0-only OR LicenseRef-bomcensus-Commercial" \
      org.opencontainers.image.vendor="JC-Lab"
COPY --from=build /out/bomcensus-server-linux-${TARGETARCH} /usr/local/bin/bomcensus-server
COPY --from=build /out/release/ /usr/share/bomcensus/releases/
ENV BOMCENSUS_RELEASE_DIR=/usr/share/bomcensus/releases
USER nonroot:nonroot
EXPOSE 8080 8443
# The image has no shell; the healthcheck subcommand reads the same
# BOMCENSUS_WEB_LISTEN and BOMCENSUS_WEB_TLS as the server.
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
    CMD ["/usr/local/bin/bomcensus-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/bomcensus-server"]
CMD ["serve"]

# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian13:nonroot AS scanner
ARG TARGETARCH
ARG VERSION=0.0.0-dev
LABEL org.opencontainers.image.title="bomcensus-scanner" \
      org.opencontainers.image.description="bomcensus remote scanner" \
      org.opencontainers.image.source="https://github.com/bomcensus/bomcensus" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="AGPL-3.0-only OR LicenseRef-bomcensus-Commercial" \
      org.opencontainers.image.vendor="JC-Lab"
COPY --from=scanner-bin /bundle/linux-${TARGETARCH}/bomcensus-scanner /usr/local/bin/bomcensus-scanner
COPY --from=scanner-bin --chown=nonroot:nonroot --chmod=0700 /state /var/lib/bomcensus/scanner
USER nonroot:nonroot
# Mount a volume here: it holds the identity and the HPKE key.
WORKDIR /var/lib/bomcensus/scanner
ENTRYPOINT ["/usr/local/bin/bomcensus-scanner"]
CMD ["run"]

# ---------------------------------------------------------------------------
# Agent for trying the product and for tests. Laid out like a host install;
# without systemd the agent starts the probe and the updater as its own
# children, so all three run as the bomcensus user here.
FROM debian:${DEBIAN_RELEASE}-slim AS agent
ARG TARGETARCH
ARG VERSION=0.0.0-dev
LABEL org.opencontainers.image.title="bomcensus-agent" \
      org.opencontainers.image.description="bomcensus agent (demo and test image)" \
      org.opencontainers.image.source="https://github.com/bomcensus/bomcensus" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="AGPL-3.0-only OR LicenseRef-bomcensus-Commercial" \
      org.opencontainers.image.vendor="JC-Lab"
RUN set -eu; \
    groupadd --system --gid 990 bomcensus; \
    useradd --system --uid 990 --gid bomcensus --home-dir /var/lib/bomcensus --no-create-home --shell /usr/sbin/nologin bomcensus; \
    useradd --system --uid 991 --user-group --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin bomcensus-probe; \
    useradd --system --uid 992 --user-group --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin bomcensus-update; \
    install -d -o bomcensus -g bomcensus -m 0755 /opt/bomcensus /opt/bomcensus/versions; \
    install -d -o root -g root -m 0755 /var/lib/bomcensus; \
    install -d -o bomcensus -g bomcensus -m 0700 /var/lib/bomcensus/agent /var/lib/bomcensus/update-spool
COPY --from=build --chown=bomcensus:bomcensus --chmod=0755 /out/bundle/linux-${TARGETARCH}/ /opt/bomcensus/versions/${VERSION}/
COPY --chmod=0755 deploy/docker/agent-entrypoint.sh /usr/local/bin/bomcensus-agent-entrypoint
RUN set -eu; \
    rm -f /opt/bomcensus/versions/${VERSION}/bomcensus-scanner; \
    ln -s versions/${VERSION} /opt/bomcensus/current; \
    chown -h bomcensus:bomcensus /opt/bomcensus/current
USER bomcensus:bomcensus
WORKDIR /var/lib/bomcensus/agent
ENTRYPOINT ["/usr/local/bin/bomcensus-agent-entrypoint"]
CMD ["run"]
