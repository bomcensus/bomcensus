-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up

-- The X25519 key that identifies this installation to feed servers. One row;
-- the private key is sealed with the master key.
CREATE TABLE feed_instance (
    id            boolean PRIMARY KEY DEFAULT true CHECK (id),
    public_key    text NOT NULL,
    encrypted_key bytea NOT NULL,
    created_at    timestamptz NOT NULL
);

-- Feed servers. At most one is active: the one components are matched
-- against. server_key is the key met at the first handshake (trust on first
-- use); NULL until then. When the server later presents another key, it is
-- kept in presented_key and the server is not used until an administrator
-- trusts it.
CREATE TABLE feed_servers (
    id                 uuid PRIMARY KEY,
    name               text NOT NULL CHECK (name <> ''),
    url                text NOT NULL UNIQUE,
    builtin            boolean NOT NULL DEFAULT false,
    active             boolean NOT NULL DEFAULT false,
    enabled            boolean NOT NULL DEFAULT true,
    telemetry          boolean NOT NULL DEFAULT true,
    server_key         text,
    key_trusted_at     timestamptz,
    presented_key      text,
    presented_at       timestamptz,
    status             text NOT NULL DEFAULT 'never'
                       CHECK (status IN ('never', 'connected', 'key_changed', 'error')),
    last_error         text NOT NULL DEFAULT '',
    last_error_at      timestamptz,
    last_ok_at         timestamptz,
    grade              text NOT NULL DEFAULT '',
    session_expires_at timestamptz,
    revision           bigint,
    rules_digest       text,
    sources            jsonb NOT NULL DEFAULT '[]',
    status_checked_at  timestamptz,
    created_at         timestamptz NOT NULL,
    updated_at         timestamptz NOT NULL,
    CHECK (NOT active OR enabled)
);

CREATE UNIQUE INDEX feed_servers_active_key ON feed_servers ((true)) WHERE active;

INSERT INTO feed_servers (id, name, url, builtin, active, created_at, updated_at)
VALUES ('019b0000-0000-7000-8000-000000000001', 'bomcensus', 'https://feed.bomcensus.com', true, true, now(), now());

-- +goose Down
DROP TABLE feed_servers;
DROP TABLE feed_instance;
