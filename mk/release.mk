# Copyright (C) 2026 JC-Lab
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
# Additional terms apply. See LICENSING.md.

# release-dev builds a development release signed with throwaway keys.
#
# Every cmd/bomcensus-* command that exists is built for each architecture
# with the trust from RELEASE_DEVKEYS compiled in. The commands that run on
# collection targets are AuthentiELF-signed and packed into
# $(DIST)/bomcensus-$(VERSION).tar, which is then verified by a host build of
# bomcensus-release carrying the same trust. The server binary is written to
# $(DIST). Paths are relative to the repository root.
#
# release builds a signed release with scripts/release.sh into
# $(DIST)/release. Keys and signing configuration come from the
# environment; see docs/RELEASING.md.

RELEASE_ARCHES  ?= amd64 arm64
RELEASE_DEVKEYS ?= .devstate/devkeys
RELEASE_STAGE   ?= build/release
DIST            ?= dist
RELEASE_BUNDLED := bomcensus-agent bomcensus-probe bomcensus-updater bomcensus-scanner

.PHONY: release-dev release

release:
	scripts/release.sh $(VERSION) $(abspath $(DIST))/release

release-dev:
	@set -eu; \
	stage=./$(RELEASE_STAGE); \
	tool=$$stage/host/bomcensus-release; \
	rm -rf -- $$stage/bundle $$stage/linux-*; \
	mkdir -p $$stage/host $(DIST); \
	CGO_ENABLED=0 go build $(GOFLAGS) -o $$tool ./cmd/bomcensus-release; \
	if [ ! -f $(RELEASE_DEVKEYS)/manifest.key ]; then \
		echo "generating development keys in $(RELEASE_DEVKEYS)"; \
		$$tool keygen --out $(RELEASE_DEVKEYS) --name "bomcensus development"; \
	fi; \
	trust=$$($$tool print-ldflags --keys $(RELEASE_DEVKEYS)); \
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$$trust" -o $$tool ./cmd/bomcensus-release; \
	cmds=""; \
	for d in cmd/bomcensus-*/; do \
		if ls $$d*.go >/dev/null 2>&1; then cmds="$$cmds $$(basename $$d)"; fi; \
	done; \
	signed=""; \
	for arch in $(RELEASE_ARCHES); do \
		for c in $$cmds; do \
			case " $(RELEASE_BUNDLED) " in \
			*" $$c "*) out=$$stage/bundle/linux-$$arch/$$c; signed="$$signed $$out" ;; \
			*) if [ "$$c" = bomcensus-server ]; then out=$(DIST)/$$c-linux-$$arch; \
			   else out=$$stage/linux-$$arch/$$c; fi ;; \
			esac; \
			echo "build $$c linux/$$arch"; \
			CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build $(GOFLAGS) \
				-ldflags "$(LDFLAGS) $$trust" -o $$out ./cmd/$$c; \
		done; \
	done; \
	if [ -z "$$signed" ]; then \
		echo "none of $(RELEASE_BUNDLED) exist yet; no bundle written"; \
		exit 0; \
	fi; \
	$$tool sign-elf --key $(RELEASE_DEVKEYS)/codesign.key \
		--cert $(RELEASE_DEVKEYS)/codesign.crt $$signed; \
	$$tool bundle --version $(VERSION) --manifest-key $(RELEASE_DEVKEYS)/manifest.key \
		--dir $$stage/bundle --out $(DIST)/bomcensus-$(VERSION).tar; \
	$$tool verify $(DIST)/bomcensus-$(VERSION).tar
