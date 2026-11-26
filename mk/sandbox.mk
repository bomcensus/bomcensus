# Copyright (C) 2026 JC-Lab
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
# Additional terms apply. See LICENSING.md.

# Sandbox tests under privilege scenarios (scripts/sandbox-matrix.sh).
# test-sandbox runs them in throwaway containers and needs Docker.
# test-sandbox-host runs them on this host as root and needs passwordless
# sudo, setpriv and unshare; CI runs it on a disposable runner.

.PHONY: test-sandbox test-sandbox-host

test-sandbox:
	scripts/sandbox-matrix.sh docker

test-sandbox-host:
	scripts/sandbox-matrix.sh host
