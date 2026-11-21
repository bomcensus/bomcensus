-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up
CREATE TABLE directives (
    id           uuid PRIMARY KEY,
    agent_id     uuid NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    type         text NOT NULL CHECK (type <> ''),
    payload      jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    dedupe_key   text CHECK (dedupe_key <> ''),
    created_at   timestamptz NOT NULL,
    delivered_at timestamptz,
    acked_at     timestamptz,
    expires_at   timestamptz
);
-- A dedupe key is unique per agent among pending directives.
CREATE UNIQUE INDEX directives_pending_dedupe_idx ON directives (agent_id, dedupe_key)
    WHERE acked_at IS NULL AND dedupe_key IS NOT NULL;
CREATE INDEX directives_pending_idx ON directives (agent_id, created_at) WHERE acked_at IS NULL;
CREATE INDEX directives_expires_at_idx ON directives (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX directives_acked_at_idx ON directives (acked_at) WHERE acked_at IS NOT NULL;

CREATE TABLE agent_enrollments (
    agent_id          uuid PRIMARY KEY REFERENCES agents (id) ON DELETE CASCADE,
    csr               bytea NOT NULL,
    allow_relaxed_tls boolean NOT NULL DEFAULT false,
    default_group     text NOT NULL DEFAULT '',
    default_tags      text[] NOT NULL DEFAULT '{}',
    created_at        timestamptz NOT NULL
);

-- +goose Down
DROP TABLE agent_enrollments;
DROP TABLE directives;
