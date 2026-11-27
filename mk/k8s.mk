# Copyright (C) 2026 JC-Lab
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
# Additional terms apply. See LICENSING.md.

# test-k8s runs scripts/k8s-e2e.sh: the node agent and the in-cluster
# scanner on a k3d cluster. Needs Docker, k3d, kubectl, helm, jq and curl.

.PHONY: test-k8s

test-k8s:
	VERSION='$(VERSION)' scripts/k8s-e2e.sh
