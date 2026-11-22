# Copyright (C) 2026 JC-Lab
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
# Additional terms apply. See LICENSING.md.

# demo-up builds the server and agent images (one docker-build run, so they
# share release keys) and starts deploy/demo/compose.yaml: a server with an
# agent and three SSH targets, set up automatically. Console:
# http://localhost:8080, admin / demo. demo-down removes it with its data.

DEMO_COMPOSE = $(DOCKER) compose -f deploy/demo/compose.yaml

.PHONY: demo-up demo-down

demo-up:
	$(MAKE) docker-build DOCKER_TARGETS="server agent"
	BOMCENSUS_VERSION='$(VERSION)' $(DEMO_COMPOSE) up -d --wait

demo-down:
	$(DEMO_COMPOSE) down -v
