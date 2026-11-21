-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up
CREATE TABLE reports (
    id           uuid PRIMARY KEY,
    source_id    text NOT NULL DEFAULT '',
    subject_kind text NOT NULL DEFAULT '',
    subject      jsonb,
    asset_id     uuid REFERENCES assets (id) ON DELETE SET NULL,
    received_at  timestamptz NOT NULL,
    size         integer NOT NULL,
    body         bytea NOT NULL
);

-- The body is already zstd-compressed.
ALTER TABLE reports ALTER COLUMN body SET STORAGE EXTERNAL;

CREATE INDEX reports_received_at_idx ON reports (received_at);
CREATE INDEX reports_asset_id_idx ON reports (asset_id, received_at DESC);

-- +goose Down
DROP TABLE reports;
