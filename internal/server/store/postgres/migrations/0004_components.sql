-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up

-- Globally deduplicated components. ident is the SHA-256 of the identity
-- (type, name, version, arch, distro, purl), computed by the application.
CREATE TABLE components (
    id             uuid PRIMARY KEY,
    ident          bytea NOT NULL UNIQUE,
    type           text NOT NULL,
    name           text NOT NULL,
    version        text NOT NULL DEFAULT '',
    arch           text NOT NULL DEFAULT '',
    distro         text NOT NULL DEFAULT '',
    purl           text NOT NULL DEFAULT '',
    cpe            text NOT NULL DEFAULT '',
    source_name    text NOT NULL DEFAULT '',
    source_version text NOT NULL DEFAULT '',
    vendor         text NOT NULL DEFAULT '',
    origin         text NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL
);

CREATE INDEX components_name_idx ON components (name, version, id);
CREATE INDEX components_type_name_idx ON components (type, name);

-- Components installed on an asset. A row is one presence interval:
-- removed_at is NULL while the component is installed. container is '' for
-- the asset itself; layer is '' for the asset itself, 'runtime' or 'image'
-- for a container.
CREATE TABLE asset_components (
    id              uuid PRIMARY KEY,
    asset_id        uuid NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    container       text NOT NULL DEFAULT '',
    source          text NOT NULL,
    layer           text NOT NULL DEFAULT '',
    component_id    uuid NOT NULL REFERENCES components (id),
    locations       text[] NOT NULL DEFAULT '{}',
    in_use          boolean NOT NULL DEFAULT false,
    method          text NOT NULL DEFAULT '',
    version_command text NOT NULL DEFAULT '',
    version_raw     text NOT NULL DEFAULT '',
    first_seen      timestamptz NOT NULL,
    removed_at      timestamptz
);

CREATE UNIQUE INDEX asset_components_current_key
    ON asset_components (asset_id, container, source, layer, component_id)
    WHERE removed_at IS NULL;
CREATE INDEX asset_components_component_idx ON asset_components (component_id) WHERE removed_at IS NULL;
CREATE INDEX asset_components_asset_idx ON asset_components (asset_id, first_seen);

-- File hash to component, kept to recognize replaced or deleted binaries.
CREATE TABLE file_hashes (
    sha256       text NOT NULL,
    component_id uuid NOT NULL REFERENCES components (id) ON DELETE CASCADE,
    path         text NOT NULL DEFAULT '',
    first_seen   timestamptz NOT NULL,
    last_seen    timestamptz NOT NULL,
    PRIMARY KEY (sha256, component_id)
);

CREATE INDEX file_hashes_component_id_idx ON file_hashes (component_id);

-- +goose Down
DROP TABLE file_hashes;
DROP TABLE asset_components;
DROP TABLE components;
