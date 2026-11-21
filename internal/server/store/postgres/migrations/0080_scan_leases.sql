-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up
CREATE TABLE scan_leases (
    key         text PRIMARY KEY CHECK (key <> ''),
    owner       text NOT NULL CHECK (owner <> ''),
    acquired_at timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL
);
CREATE INDEX scan_leases_expires_at_idx ON scan_leases (expires_at);

-- +goose Down
DROP TABLE scan_leases;
