-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up
CREATE TABLE pki_objects (
    name           text PRIMARY KEY,
    cert_chain_pem bytea NOT NULL,
    encrypted_key  bytea,
    state          text NOT NULL DEFAULT '',
    version        bigint NOT NULL CHECK (version > 0),
    created_at     timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL
);

CREATE TABLE tls_settings (
    endpoint   text PRIMARY KEY CHECK (endpoint IN ('web', 'agent')),
    mode       text NOT NULL CHECK (mode IN ('auto', 'manual')),
    updated_at timestamptz NOT NULL
);

CREATE TABLE trust_bundle (
    id      boolean PRIMARY KEY DEFAULT true CHECK (id),
    version bigint NOT NULL
);

-- +goose Down
DROP TABLE trust_bundle;
DROP TABLE tls_settings;
DROP TABLE pki_objects;
