-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up
CREATE TABLE releases (
    version      text PRIMARY KEY,
    manifest     bytea NOT NULL,
    signature    bytea NOT NULL,
    published_at timestamptz NOT NULL,
    source       text NOT NULL CHECK (source IN ('online', 'upload')),
    verified     boolean NOT NULL DEFAULT false,
    notes        text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL
);

CREATE TABLE release_files (
    id         uuid PRIMARY KEY,
    version    text NOT NULL REFERENCES releases (version) ON DELETE CASCADE,
    os         text NOT NULL,
    arch       text NOT NULL,
    name       text NOT NULL,
    sha256     bytea NOT NULL,
    size       bigint NOT NULL CHECK (size >= 0),
    chunks     integer NOT NULL CHECK (chunks >= 0),
    created_at timestamptz NOT NULL,
    UNIQUE (version, os, arch, name)
);

-- File content split into fixed-size pieces so it can be written and read
-- without holding a whole file in memory or a transaction open for a read.
CREATE TABLE release_file_chunks (
    file_id uuid NOT NULL REFERENCES release_files (id) ON DELETE CASCADE,
    seq     integer NOT NULL CHECK (seq >= 0),
    data    bytea NOT NULL,
    PRIMARY KEY (file_id, seq)
);
-- Executables compress poorly; skip TOAST compression.
ALTER TABLE release_file_chunks ALTER COLUMN data SET STORAGE EXTERNAL;

CREATE TABLE update_settings (
    id                     boolean PRIMARY KEY DEFAULT true CHECK (id),
    target_version         text REFERENCES releases (version),
    check_interval_minutes integer NOT NULL CHECK (check_interval_minutes > 0),
    updated_at             timestamptz NOT NULL
);

-- +goose Down
DROP TABLE update_settings;
DROP TABLE release_file_chunks;
DROP TABLE release_files;
DROP TABLE releases;
