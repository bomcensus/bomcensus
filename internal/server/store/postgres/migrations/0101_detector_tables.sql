-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up

-- Vendor build or revision number reported by a detector. Part of the
-- identity when set (see ivIdent): builds of one version are different
-- components.
ALTER TABLE components ADD COLUMN build text NOT NULL DEFAULT '';

-- Every edit of the known-software detector table. The newest row is the
-- table in effect; a row with reset set (and no yaml) returns to the default
-- table of the server.
CREATE TABLE detector_tables (
    id         bigserial PRIMARY KEY,
    yaml       text NOT NULL DEFAULT '',
    digest     text NOT NULL DEFAULT '',
    reset      boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL,
    created_by text NOT NULL DEFAULT '',
    CHECK (reset = (yaml = '')),
    CHECK (length(yaml) <= 1048576)
);

-- Digest of the detector table the agent reported in its last poll; NULL
-- when the agent does not report one (it uses the table built into its
-- probe).
ALTER TABLE agents ADD COLUMN detectors_digest text;

-- +goose Down
ALTER TABLE agents DROP COLUMN detectors_digest;
DROP TABLE detector_tables;
ALTER TABLE components DROP COLUMN build;
