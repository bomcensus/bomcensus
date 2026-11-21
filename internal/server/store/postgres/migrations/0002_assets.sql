-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up
CREATE TABLE assets (
    id              uuid PRIMARY KEY,
    kind            text NOT NULL CHECK (kind IN ('host', 'workload')),
    name            text NOT NULL DEFAULT '',
    group_name      text NOT NULL DEFAULT '',
    tags            text[] NOT NULL DEFAULT '{}',
    os_family       text NOT NULL DEFAULT '',
    os_id           text NOT NULL DEFAULT '',
    os_name         text NOT NULL DEFAULT '',
    os_version      text NOT NULL DEFAULT '',
    kernel          text NOT NULL DEFAULT '',
    arch            text NOT NULL DEFAULT '',
    address         text NOT NULL DEFAULT '',
    method          text NOT NULL DEFAULT '',
    coverage        text NOT NULL DEFAULT 'inventory_only',
    coverage_reason text NOT NULL DEFAULT '',
    privilege       text NOT NULL DEFAULT '',
    -- host identity
    agent_id        uuid,
    machine_id      text,
    scanner_id      uuid,
    -- workload identity
    cluster_id      uuid REFERENCES k8s_clusters (id) ON DELETE CASCADE,
    namespace       text,
    workload_kind   text,
    workload_name   text,
    first_seen      timestamptz NOT NULL,
    last_seen       timestamptz NOT NULL,
    gone_at         timestamptz,
    CHECK (kind = 'host' OR (cluster_id IS NOT NULL AND namespace IS NOT NULL
                             AND workload_kind IS NOT NULL AND workload_name IS NOT NULL))
);

CREATE UNIQUE INDEX assets_agent_id_key ON assets (agent_id) WHERE agent_id IS NOT NULL;
CREATE INDEX assets_machine_id_idx ON assets (machine_id) WHERE machine_id IS NOT NULL;
CREATE INDEX assets_scanner_address_idx ON assets (scanner_id, address) WHERE scanner_id IS NOT NULL;
CREATE UNIQUE INDEX assets_workload_key ON assets (cluster_id, namespace, workload_kind, workload_name)
    WHERE kind = 'workload';
CREATE INDEX assets_name_idx ON assets (name, id);
CREATE INDEX assets_gone_at_idx ON assets (gone_at) WHERE gone_at IS NOT NULL;

-- Collection state of each report section. container is '' for the asset
-- itself.
CREATE TABLE asset_sections (
    asset_id     uuid NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    container    text NOT NULL DEFAULT '',
    section      text NOT NULL,
    coverage     text NOT NULL,
    reason       text NOT NULL DEFAULT '',
    digest       text NOT NULL DEFAULT '',
    collected_at timestamptz NOT NULL,
    PRIMARY KEY (asset_id, container, section)
);

-- +goose Down
DROP TABLE asset_sections;
DROP TABLE assets;
