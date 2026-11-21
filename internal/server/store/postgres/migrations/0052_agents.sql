-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up
CREATE TABLE agents (
    id                   uuid PRIMARY KEY,
    kind                 text NOT NULL CHECK (kind IN ('agent', 'scanner')),
    hostname             text NOT NULL DEFAULT '',
    identity_key         bytea NOT NULL UNIQUE,
    hpke_public_key      bytea,
    register_key_id      text REFERENCES register_keys (id),
    state                text NOT NULL CHECK (state IN ('approved', 'pending', 'revoked')),
    version              text NOT NULL DEFAULT '',
    os                   text NOT NULL DEFAULT '',
    arch                 text NOT NULL DEFAULT '',
    connect_mode         text NOT NULL DEFAULT 'connect' CHECK (connect_mode IN ('connect', 'listen')),
    listen_address       text NOT NULL DEFAULT '',
    tls_mode             text NOT NULL DEFAULT 'pinned' CHECK (tls_mode IN ('pinned', 'system', 'none')),
    observed_issuer      text NOT NULL DEFAULT '',
    privilege            text NOT NULL DEFAULT '' CHECK (privilege IN ('', 'privileged', 'non_root')),
    exec_helper          boolean NOT NULL DEFAULT false,
    address              text NOT NULL DEFAULT '',
    trust_bundle_version bigint NOT NULL DEFAULT 0,
    update_state         text NOT NULL DEFAULT 'up_to_date'
                         CHECK (update_state IN ('up_to_date', 'pending', 'updating', 'rolled_back')),
    -- Plain reference to assets(id); no foreign key across store halves.
    asset_id             uuid,
    -- Last accepted message signature counter (SECURITY 4.6).
    msg_counter          bigint NOT NULL DEFAULT 0 CHECK (msg_counter >= 0),
    enrolled_at          timestamptz NOT NULL,
    approved_at          timestamptz,
    revoked_at           timestamptz,
    last_seen            timestamptz
);
CREATE INDEX agents_kind_hostname_idx ON agents (kind, hostname);
CREATE INDEX agents_asset_id_idx ON agents (asset_id);
CREATE INDEX agents_register_key_id_idx ON agents (register_key_id);

CREATE TABLE agent_certs (
    serial     text PRIMARY KEY,
    agent_id   uuid NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    not_before timestamptz NOT NULL,
    not_after  timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL
);
CREATE INDEX agent_certs_agent_id_idx ON agent_certs (agent_id);

-- +goose Down
DROP TABLE agent_certs;
DROP TABLE agents;
