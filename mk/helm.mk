# Copyright (C) 2026 JC-Lab
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
# Additional terms apply. See LICENSING.md.

# Helm charts in deploy/charts.
#
#   helm-lint     helm lint both charts, then render the manager chart with
#                 every database mode, with and without ingress, scanner and
#                 node agent, and the scanner chart on its own
#   helm-package  package both charts into $(HELM_DIST)

HELM           ?= helm
HELM_CHARTS    := deploy/charts
HELM_DIST      ?= dist/charts
HELM_MANAGER   := $(HELM_CHARTS)/bomcensus-manager
HELM_SCANNER   := $(HELM_CHARTS)/bomcensus-scanner

# A well-formed argon2id string; only its shape is checked when rendering.
HELM_TEST_HASH := $$argon2id$$v=19$$m=65536\,t=3\,p=4$$c2FsdHNhbHRzYWx0$$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g
HELM_CNPG_APIS := --api-versions postgresql.cnpg.io/v1/Cluster \
	--api-versions postgresql.cnpg.io/v1/Database \
	--api-versions postgresql.cnpg.io/v1/DatabaseRole
HELM_BASE      := --set-string 'admin.passwordHash=$(HELM_TEST_HASH)'

# One line per case: options of "helm template" for the manager chart.
HELM_CASES := \
	"--set database.url=postgres://u:p@db:5432/bomcensus" \
	"--set database.existingSecret.name=bomcensus-db" \
	"--set cnpg.cluster.create=true" \
	"--set cnpg.cluster.create=true --set scanner.enabled=true" \
	"--set cnpg.database.create=true --set cnpg.database.cluster=pg --set cnpg.database.namespace=databases" \
	"--set cnpg.database.create=true --set cnpg.database.cluster=pg --set cnpg.database.createRole=false" \
	"--set database.url=postgres://u:p@db/b --set ingress.enabled=true --set scanner.enabled=true --set scanner.rbac.exec=true" \
	"--set database.url=postgres://u:p@db/b --set scanner.enabled=true --set scanner.enrollment.existingSecret.name=tok" \
	"--set database.url=postgres://u:p@db/b --set scanner.enabled=true --set scanner.nodeAgent.enabled=true --set scanner.nodeAgent.enrollment.existingSecret.name=natok" \
	"--set database.url=postgres://u:p@db/b --set replicaCount=3 --set podDisruptionBudget.enabled=true --set agent.service.type=LoadBalancer --set agent.extraServerNames={bomcensus.example.com}"

.PHONY: helm-deps helm-lint helm-package

helm-deps:
	$(HELM) dependency build --skip-refresh $(HELM_MANAGER)

helm-lint: helm-deps
	@set -euf; \
	$(HELM) lint $(HELM_SCANNER) --set server.url=https://bomcensus.example:8443 --set enrollment.existingSecret.name=tok; \
	$(HELM) lint $(HELM_MANAGER) $(HELM_BASE) --set database.url=postgres://u:p@db/b --set scanner.enabled=true; \
	$(HELM) template t $(HELM_SCANNER) --set server.url=https://bomcensus.example:8443 --set enrollment.token=bc1.x \
		--set rbac.exec=true --set 'rbac.namespaces={a,b}' --set persistence.enabled=false \
		--set networkPolicy.enabled=true --set 'networkPolicy.server.cidrs={10.0.0.1/32}' \
		--set 'networkPolicy.apiServer.cidrs={10.0.0.2/32}' >/dev/null; \
	echo "template bomcensus-scanner: ok"; \
	for kv in 1.29.0 1.30.0 1.31.0; do \
		$(HELM) template t $(HELM_SCANNER) --kube-version $$kv --set server.url=https://bomcensus.example:8443 \
			--set enrollment.existingSecret.name=tok --set nodeAgent.enabled=true \
			--set nodeAgent.enrollment.token=bc1.x --set nodeAgent.probe.seLinuxOptions.type=spc_t \
			--set 'nodeAgent.tolerations[0].operator=Exists' >/dev/null; \
		echo "template bomcensus-scanner nodeAgent (Kubernetes $$kv): ok"; \
	done; \
	for c in $(HELM_CASES); do \
		$(HELM) template t $(HELM_MANAGER) $(HELM_BASE) $(HELM_CNPG_APIS) $$c >/dev/null; \
		echo "template bomcensus-manager $$c: ok"; \
	done; \
	if $(HELM) template t $(HELM_MANAGER) $(HELM_BASE) --set cnpg.cluster.create=true >/dev/null 2>&1; then \
		echo "rendering without the CloudNativePG API must fail" >&2; exit 1; \
	fi; \
	if $(HELM) template t $(HELM_MANAGER) $(HELM_BASE) >/dev/null 2>&1; then \
		echo "rendering without a database must fail" >&2; exit 1; \
	fi; \
	if $(HELM) template t $(HELM_SCANNER) --set server.url=https://bomcensus.example:8443 --set enrollment.token=bc1.x \
		--set nodeAgent.enabled=true >/dev/null 2>&1; then \
		echo "nodeAgent without an enrollment string must fail" >&2; exit 1; \
	fi; \
	if $(HELM) template t $(HELM_SCANNER) --kube-version 1.28.0 --set server.url=https://bomcensus.example:8443 \
		--set enrollment.token=bc1.x --set nodeAgent.enabled=true --set nodeAgent.enrollment.token=bc1.y >/dev/null 2>&1; then \
		echo "nodeAgent before Kubernetes 1.29 must fail" >&2; exit 1; \
	fi; \
	echo "negative cases: ok"

helm-package: helm-deps
	@mkdir -p $(HELM_DIST)
	$(HELM) package $(HELM_SCANNER) --destination $(HELM_DIST)
	$(HELM) package $(HELM_MANAGER) --destination $(HELM_DIST)
