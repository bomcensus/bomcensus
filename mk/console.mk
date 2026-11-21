# Copyright (C) 2026 JC-Lab
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
# Additional terms apply. See LICENSING.md.

# console builds the web console and copies its static output into the
# server's embed directory. Build the server afterwards to include it.
# console-clean removes the copied files; the placeholder page stays.

CONSOLE_DIR   := frontend
CONSOLE_EMBED := internal/server/console/dist
CONSOLE_NODE  ?= 26

.PHONY: console console-clean

# Removes everything in the embed directory except the placeholder.
CONSOLE_CLEAN = find $(CONSOLE_EMBED) -mindepth 1 -maxdepth 1 ! -name placeholder -exec rm -rf -- {} +

console:
	@set -eu; \
	bash -c 'set -eu; source "$${NVM_DIR:-$$HOME/.nvm}/nvm.sh"; nvm use $(CONSOLE_NODE) >/dev/null; \
		cd $(CONSOLE_DIR); pnpm install --frozen-lockfile; pnpm exec nuxt generate'; \
	test -f $(CONSOLE_DIR)/.output/public/index.html || { echo "console: no index.html in $(CONSOLE_DIR)/.output/public" >&2; exit 1; }; \
	$(CONSOLE_CLEAN); \
	cp -R $(CONSOLE_DIR)/.output/public/. $(CONSOLE_EMBED)/; \
	echo "console copied to $(CONSOLE_EMBED)"

console-clean:
	@$(CONSOLE_CLEAN)
