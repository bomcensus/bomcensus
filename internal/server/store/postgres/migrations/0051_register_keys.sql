-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up
CREATE TABLE register_keys (
    id                text PRIMARY KEY CHECK (char_length(id) = 11),
    name              text NOT NULL,
    public_key        bytea NOT NULL,
    target_kind       text NOT NULL CHECK (target_kind IN ('agent', 'scanner')),
    expires_at        timestamptz,
    allowed_cidrs     cidr[] NOT NULL DEFAULT '{}',
    max_uses          integer NOT NULL DEFAULT 0 CHECK (max_uses >= 0),
    used_count        integer NOT NULL DEFAULT 0 CHECK (used_count >= 0),
    approval          text NOT NULL CHECK (approval IN ('auto', 'manual')),
    allow_relaxed_tls boolean NOT NULL DEFAULT false,
    default_group     text NOT NULL DEFAULT '',
    default_tags      text[] NOT NULL DEFAULT '{}',
    created_by        text NOT NULL DEFAULT '',
    created_at        timestamptz NOT NULL,
    revoked_at        timestamptz
);
CREATE INDEX register_keys_created_at_idx ON register_keys (created_at DESC);

-- +goose Down
DROP TABLE register_keys;
