-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up
CREATE TABLE k8s_clusters (
    id            uuid PRIMARY KEY,
    name          text NOT NULL UNIQUE,
    version       text NOT NULL DEFAULT '',
    connection    text NOT NULL,
    credential_id uuid,
    scanner_id    uuid,
    exec_enabled  boolean NOT NULL DEFAULT false,
    filter        jsonb NOT NULL DEFAULT '{}',
    last_sync     timestamptz,
    created_at    timestamptz NOT NULL,
    updated_at    timestamptz NOT NULL
);

CREATE INDEX k8s_clusters_scanner_id_idx ON k8s_clusters (scanner_id);
CREATE INDEX k8s_clusters_credential_id_idx ON k8s_clusters (credential_id);

-- +goose Down
DROP TABLE k8s_clusters;
