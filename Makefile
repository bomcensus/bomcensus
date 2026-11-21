# Copyright (C) 2026 JC-Lab
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
# Additional terms apply. See LICENSING.md.

VERSION ?= 0.0.0-dev
GOFLAGS := -trimpath
LDFLAGS := -s -w -X github.com/bomcensus/bomcensus/internal/version.Version=$(VERSION)
BINARIES := bomcensus-server bomcensus-agent bomcensus-probe bomcensus-scanner bomcensus-updater bomcensus-release

.PHONY: build test vet license license-check

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/ ./cmd/...

test:
	go test ./...

vet:
	go vet ./...

license:
	go run ./tools/licensehdr -fix .

license-check:
	go run ./tools/licensehdr .

-include mk/*.mk
