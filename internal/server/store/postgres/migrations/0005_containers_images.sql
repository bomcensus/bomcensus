-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up

-- Containers of an asset. name is the key inside the asset; a container that
-- is no longer seen keeps its row with gone_at set.
CREATE TABLE asset_containers (
    asset_id        uuid NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    name            text NOT NULL,
    runtime_id      text NOT NULL DEFAULT '',
    image_ref       text NOT NULL DEFAULT '',
    image_digest    text NOT NULL DEFAULT '',
    previous_digest text NOT NULL DEFAULT '',
    digest_since    timestamptz NOT NULL,
    runtime         text NOT NULL DEFAULT '',
    instances       integer NOT NULL DEFAULT 0,
    coverage        text NOT NULL DEFAULT 'inventory_only',
    coverage_reason text NOT NULL DEFAULT '',
    started_at      timestamptz,
    first_seen      timestamptz NOT NULL,
    last_seen       timestamptz NOT NULL,
    gone_at         timestamptz,
    PRIMARY KEY (asset_id, name)
);

CREATE INDEX asset_containers_digest_idx ON asset_containers (image_digest) WHERE gone_at IS NULL;
CREATE INDEX asset_containers_gone_at_idx ON asset_containers (gone_at) WHERE gone_at IS NOT NULL;

-- Images by digest. content_collected_at is set once the software of the
-- digest is known (image_components).
CREATE TABLE images (
    digest               text PRIMARY KEY,
    repo_tags            text[] NOT NULL DEFAULT '{}',
    os                   text NOT NULL DEFAULT '',
    arch                 text NOT NULL DEFAULT '',
    size                 bigint NOT NULL DEFAULT 0,
    first_seen           timestamptz NOT NULL,
    last_seen            timestamptz NOT NULL,
    content_coverage     text NOT NULL DEFAULT '',
    content_collected_at timestamptz
);

-- Software of an image digest, shared by every container with that digest.
CREATE TABLE image_components (
    digest          text NOT NULL REFERENCES images (digest) ON DELETE CASCADE,
    source          text NOT NULL,
    component_id    uuid NOT NULL REFERENCES components (id),
    locations       text[] NOT NULL DEFAULT '{}',
    in_use          boolean NOT NULL DEFAULT false,
    method          text NOT NULL DEFAULT '',
    version_command text NOT NULL DEFAULT '',
    version_raw     text NOT NULL DEFAULT '',
    PRIMARY KEY (digest, source, component_id)
);

CREATE INDEX image_components_component_id_idx ON image_components (component_id);

-- +goose Down
DROP TABLE image_components;
DROP TABLE images;
DROP TABLE asset_containers;
