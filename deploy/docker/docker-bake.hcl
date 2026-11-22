# Copyright (C) 2026 JC-Lab
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
# Additional terms apply. See LICENSING.md.

# Builds the images in one BuildKit session, so that all of them come from
# the same Go build stage and carry the same trust (this matters with
# throwaway keys). buildx takes SOURCE_DATE_EPOCH from the environment for
# the image timestamps. Run from the repository root:
#
#   docker buildx bake -f deploy/docker/docker-bake.hcl --load
#   RELEASE_KEYS=keys.tar RELEASE_KEYS_ID=<sha256 of manifest.pub> \
#     docker buildx bake -f deploy/docker/docker-bake.hcl --allow fs.read=keys.tar --load
#   docker buildx bake -f deploy/docker/docker-bake.hcl --set '*.platform=linux/arm64' server

variable "VERSION" {
  default = "0.0.0-dev"
}

variable "REPO" {
  default = "bomcensus"
}

# Path of a tar of the key directory written by `bomcensus-release keygen`.
# Empty: throwaway keys are generated in the build.
variable "RELEASE_KEYS" {
  default = ""
}

# SHA-256 (hex) of manifest.pub in RELEASE_KEYS; see the Dockerfile.
variable "RELEASE_KEYS_ID" {
  default = ""
}

# Directory with signed release files (scripts/release.sh OUTDIR/docker).
# When set, the images take these files instead of building them.
variable "DIST" {
  default = ""
}

# Also tag the images as latest.
variable "LATEST" {
  default = false
}

variable "SOURCE_URL" {
  default = "https://github.com/bomcensus/bomcensus"
}

function "tags" {
  params = [name]
  result = concat(["${REPO}/${name}:${VERSION}"], LATEST ? ["${REPO}/${name}:latest"] : [])
}

group "default" {
  targets = ["server", "scanner", "agent"]
}

target "_common" {
  context    = "."
  dockerfile = "deploy/docker/Dockerfile"
  args = {
    VERSION         = VERSION
    RELEASE_KEYS_ID = RELEASE_KEYS_ID
    SOURCE_URL      = SOURCE_URL
  }
  contexts = DIST != "" ? { dist = DIST } : {}
  secret   = RELEASE_KEYS != "" ? ["id=release_keys,src=${RELEASE_KEYS}"] : []
}

target "server" {
  inherits = ["_common"]
  target   = "server"
  tags     = tags("server")
}

target "scanner" {
  inherits = ["_common"]
  target   = "scanner"
  tags     = tags("scanner")
}

target "agent" {
  inherits = ["_common"]
  target   = "agent"
  tags     = tags("agent")
}
