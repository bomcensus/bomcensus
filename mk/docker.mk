# Copyright (C) 2026 JC-Lab
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
# Additional terms apply. See LICENSING.md.

# docker-build builds the server, scanner, node-agent and agent images as
# $(DOCKER_REPO)/{server,scanner,node-agent,agent}:$(VERSION) in one BuildKit session
# (deploy/docker/docker-bake.hcl), so that they share one Go build and one
# set of keys. RELEASE_KEYS is a tar of a key directory written by
# `bomcensus-release keygen`; without it the build uses throwaway keys.
# DOCKER_TARGETS selects images, DOCKER_PLATFORM builds for another
# platform (the result is then not loaded unless the image store supports
# it; set DOCKER_OUTPUT accordingly).
#
# docker-up and docker-down start and stop deploy/docker/compose.yaml
# (run deploy/docker/init.sh once before docker-up). For a demo, see
# mk/demo.mk.

DOCKER          ?= docker
DOCKER_REPO     ?= bomcensus
DOCKER_TARGETS  ?= server scanner node-agent agent
DOCKER_PLATFORM ?=
DOCKER_OUTPUT   ?= --load
RELEASE_KEYS    ?=
DOCKER_COMPOSE  := $(DOCKER) compose -f deploy/docker/compose.yaml

.PHONY: docker-build docker-up docker-down

docker-build:
	@set -eu; \
	sde=$${SOURCE_DATE_EPOCH:-$$(git log -1 --format=%ct 2>/dev/null || true)}; \
	if [ -n "$$sde" ]; then export SOURCE_DATE_EPOCH=$$sde; fi; \
	keys_id=; \
	if [ -n '$(RELEASE_KEYS)' ]; then \
		keys_id=$$(tar -xOf '$(RELEASE_KEYS)' --wildcards '*manifest.pub' | sha256sum | cut -c1-64); \
	fi; \
	VERSION='$(VERSION)' REPO='$(DOCKER_REPO)' \
	RELEASE_KEYS='$(RELEASE_KEYS)' RELEASE_KEYS_ID="$$keys_id" \
	$(DOCKER) buildx bake -f deploy/docker/docker-bake.hcl $(DOCKER_OUTPUT) \
		$(if $(RELEASE_KEYS),--allow 'fs.read=$(abspath $(RELEASE_KEYS))') \
		$(if $(DOCKER_PLATFORM),--set '*.platform=$(DOCKER_PLATFORM)') \
		$(DOCKER_TARGETS)

# The image version is BOMCENSUS_VERSION in deploy/docker/.env.
docker-up:
	$(DOCKER_COMPOSE) up -d --wait

docker-down:
	$(DOCKER_COMPOSE) down
