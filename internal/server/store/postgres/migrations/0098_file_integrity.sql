-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up

-- One pass over the package files of an asset. A pass arrives in chunks,
-- possibly on several nights; pass_key is the collector's pass id and
-- completed_at is set by the chunk that checked the last package.
CREATE TABLE integrity_passes (
    id               uuid PRIMARY KEY,
    asset_id         uuid NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    pass_key         text NOT NULL,
    started_at       timestamptz NOT NULL,
    last_chunk_at    timestamptz NOT NULL,
    completed_at     timestamptz,
    files_checked    bigint NOT NULL DEFAULT 0,
    files_excluded   bigint NOT NULL DEFAULT 0,
    files_unreadable bigint NOT NULL DEFAULT 0,
    coverage         text NOT NULL DEFAULT 'full' CHECK (coverage IN ('full', 'partial', 'none')),
    coverage_reason  text NOT NULL DEFAULT '',
    -- Resume point of the next chunk. Kept for SSH targets, whose scanners
    -- hold no state; agents keep their own.
    cursor           text NOT NULL DEFAULT '',
    -- UTC offset of the host as the probe saw it, to place the next SSH
    -- window in the host's local time.
    utc_offset_s     integer,
    UNIQUE (asset_id, pass_key)
);
CREATE INDEX integrity_passes_asset_idx ON integrity_passes (asset_id, last_chunk_at DESC);

-- A package file that differs from its database digest, or is missing. A
-- row is one presence interval of one actual content: a new hash is a new
-- row. actual_sha256 is '' for a missing file.
CREATE TABLE integrity_findings (
    id            uuid PRIMARY KEY,
    asset_id      uuid NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    path          text NOT NULL,
    status        text NOT NULL CHECK (status IN ('modified', 'missing')),
    pkg_type      text NOT NULL CHECK (pkg_type IN ('deb', 'rpm', 'apk')),
    package       text NOT NULL,
    version       text NOT NULL,
    arch          text NOT NULL DEFAULT '',
    algo          text NOT NULL CHECK (algo IN ('md5', 'sha1', 'sha256', 'sha384', 'sha512')),
    expected      text NOT NULL,
    actual        text NOT NULL DEFAULT '',
    actual_sha256 text NOT NULL DEFAULT '',
    size          bigint,
    mtime         timestamptz,
    ctime         timestamptz,
    last_pass     uuid NOT NULL REFERENCES integrity_passes (id) ON DELETE CASCADE,
    first_seen    timestamptz NOT NULL,
    last_seen     timestamptz NOT NULL,
    resolved_at   timestamptz,
    CHECK ((status = 'missing') = (actual_sha256 = ''))
);
CREATE UNIQUE INDEX integrity_findings_open_key
    ON integrity_findings (asset_id, path, status, actual_sha256) WHERE resolved_at IS NULL;
CREATE INDEX integrity_findings_open_group
    ON integrity_findings (path, status, actual_sha256) WHERE resolved_at IS NULL;
CREATE INDEX integrity_findings_resolved_idx ON integrity_findings (resolved_at) WHERE resolved_at IS NOT NULL;

-- Hides open findings with the same path, status and actual SHA-256: on one
-- asset (scope asset) or on every asset, including later ones (scope
-- fleet). A revoked rule hides nothing.
CREATE TABLE integrity_allow_rules (
    id            uuid PRIMARY KEY,
    scope         text NOT NULL CHECK (scope IN ('asset', 'fleet')),
    asset_id      uuid REFERENCES assets (id) ON DELETE CASCADE,
    path          text NOT NULL CHECK (path LIKE '/%'),
    status        text NOT NULL CHECK (status IN ('modified', 'missing')),
    actual_sha256 text NOT NULL DEFAULT '',
    note          text NOT NULL CHECK (length(note) BETWEEN 1 AND 1000),
    created_by    text NOT NULL,
    created_at    timestamptz NOT NULL,
    revoked_by    text NOT NULL DEFAULT '',
    revoked_at    timestamptz,
    CHECK ((scope = 'asset') = (asset_id IS NOT NULL)),
    CHECK ((status = 'missing') = (actual_sha256 = ''))
);
CREATE INDEX integrity_allow_rules_key
    ON integrity_allow_rules (path, status, actual_sha256) WHERE revoked_at IS NULL;

-- Per collector choice: 'inherit' follows the default of its kind in the
-- integrity policy setting.
ALTER TABLE agents ADD COLUMN integrity text NOT NULL DEFAULT 'inherit'
    CHECK (integrity IN ('inherit', 'on', 'off'));
ALTER TABLE scan_targets ADD COLUMN integrity text NOT NULL DEFAULT 'inherit'
    CHECK (integrity IN ('inherit', 'on', 'off'));
