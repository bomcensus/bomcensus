-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up
CREATE TABLE sessions (
    id_hash        bytea PRIMARY KEY,
    principal_id   text NOT NULL,
    principal_name text NOT NULL,
    created_at     timestamptz NOT NULL,
    expires_at     timestamptz NOT NULL
);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

CREATE TABLE enroll_sessions (
    id         uuid PRIMARY KEY,
    state      bytea NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX enroll_sessions_expires_at_idx ON enroll_sessions (expires_at);

-- +goose Down
DROP TABLE enroll_sessions;
DROP TABLE sessions;
