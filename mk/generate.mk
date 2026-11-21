# Copyright (C) 2026 JC-Lab
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
# Additional terms apply. See LICENSING.md.

OAPI_CODEGEN := go tool oapi-codegen

.PHONY: generate generate-api

generate: generate-api

generate-api:
	$(OAPI_CODEGEN) -config api/openapi/admin.codegen.yaml api/openapi/admin.yaml
	$(OAPI_CODEGEN) -config api/openapi/agent.codegen.yaml api/openapi/agent.yaml
