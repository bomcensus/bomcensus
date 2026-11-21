-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up
CREATE TABLE credentials (
    id         uuid PRIMARY KEY,
    name       text NOT NULL UNIQUE,
    kind       text NOT NULL CHECK (kind IN ('ssh_key', 'ssh_password', 'kubeconfig')),
    username   text NOT NULL DEFAULT '',
    secret     bytea NOT NULL,
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL
);

CREATE TABLE scan_targets (
    id                   uuid PRIMARY KEY,
    name                 text NOT NULL,
    address              text NOT NULL,
    port                 integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    credential_id        uuid NOT NULL REFERENCES credentials (id) ON DELETE RESTRICT,
    -- NULL means the embedded scanner.
    scanner_id           uuid REFERENCES agents (id) ON DELETE RESTRICT,
    sudo                 boolean NOT NULL DEFAULT false,
    host_key             bytea,
    interval_minutes     integer NOT NULL DEFAULT 0 CHECK (interval_minutes >= 0),
    -- Plain reference to assets(id); no foreign key across store halves.
    asset_id             uuid,
    last_run_at          timestamptz,
    last_run_result      text CHECK (last_run_result IN ('ok', 'partial', 'failed')),
    last_run_message     text NOT NULL DEFAULT '',
    last_run_duration_ms bigint NOT NULL DEFAULT 0 CHECK (last_run_duration_ms >= 0),
    created_at           timestamptz NOT NULL
);
CREATE INDEX scan_targets_credential_id_idx ON scan_targets (credential_id);
CREATE INDEX scan_targets_scanner_id_idx ON scan_targets (scanner_id);

CREATE TABLE listen_targets (
    id                uuid PRIMARY KEY,
    address           text NOT NULL UNIQUE,
    register_key_id   text REFERENCES register_keys (id),
    agent_id          uuid REFERENCES agents (id) ON DELETE SET NULL,
    state             text NOT NULL DEFAULT 'new'
                      CHECK (state IN ('new', 'connected', 'disconnected', 'failed')),
    last_error        text NOT NULL DEFAULT '',
    last_connected_at timestamptz,
    lease_owner       text,
    lease_expires_at  timestamptz,
    created_at        timestamptz NOT NULL
);

-- +goose Down
DROP TABLE listen_targets;
DROP TABLE scan_targets;
DROP TABLE credentials;
