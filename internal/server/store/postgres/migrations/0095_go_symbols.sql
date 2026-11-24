-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up

-- Vulnerable functions of a Go vulnerability:
-- [{path, symbols, goos, goarch}] from the match, '[]' when unknown.
ALTER TABLE component_vulns ADD COLUMN symbols jsonb NOT NULL DEFAULT '[]';

ALTER TABLE findings ADD CONSTRAINT findings_reachability_check
    CHECK (reachability IN ('symbol_present', 'symbol_absent'));

-- Go executables of an asset, replaced with its artifacts. container and
-- layer as in asset_components.
CREATE TABLE go_binaries (
    asset_id  uuid NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    container text NOT NULL DEFAULT '',
    layer     text NOT NULL DEFAULT '',
    path      text NOT NULL,
    sha256    text NOT NULL,
    goos      text NOT NULL DEFAULT '',
    goarch    text NOT NULL DEFAULT '',
    seen_at   timestamptz NOT NULL,
    PRIMARY KEY (asset_id, container, layer, path)
);

-- Go executables of an image, replaced with its content.
CREATE TABLE image_go_binaries (
    digest text NOT NULL,
    path   text NOT NULL,
    sha256 text NOT NULL,
    goos   text NOT NULL DEFAULT '',
    goarch text NOT NULL DEFAULT '',
    PRIMARY KEY (digest, path)
);

-- Answers of an asset's collector about functions in its Go executables.
-- They are used for that asset only.
CREATE TABLE go_symbol_results (
    asset_id   uuid NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    sha256     text NOT NULL,
    name       text NOT NULL,
    result     text NOT NULL CHECK (result IN ('present', 'absent', 'not_checked')),
    reason     text NOT NULL DEFAULT '',
    checked_at timestamptz NOT NULL,
    PRIMARY KEY (asset_id, sha256, name)
);

-- The query waiting for an asset's next collection, per container scope:
-- '' for collectors that read the whole asset (agents, SSH scans), the
-- container name for Kubernetes exec, which runs inside one container.
CREATE TABLE go_symbol_queries (
    asset_id   uuid NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    container  text NOT NULL DEFAULT '',
    query      jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (asset_id, container)
);

-- Optional features an agent or scanner reported in its last poll.
ALTER TABLE agents ADD COLUMN features text[] NOT NULL DEFAULT '{}';

-- +goose Down
ALTER TABLE agents DROP COLUMN features;
DROP TABLE go_symbol_queries;
DROP TABLE go_symbol_results;
DROP TABLE image_go_binaries;
DROP TABLE go_binaries;
ALTER TABLE findings DROP CONSTRAINT findings_reachability_check;
ALTER TABLE component_vulns DROP COLUMN symbols;
