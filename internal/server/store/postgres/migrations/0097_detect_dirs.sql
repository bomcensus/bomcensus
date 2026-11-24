-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up

-- Directories walked for software on the agents and scan targets they are
-- assigned to. Without any, only running software is collected.
CREATE TABLE detect_dirs (
    id          uuid PRIMARY KEY,
    path        text NOT NULL UNIQUE CHECK (path LIKE '/%' AND length(path) <= 1024),
    description text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL
);

CREATE TABLE agent_detect_dirs (
    agent_id uuid NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    dir_id   uuid NOT NULL REFERENCES detect_dirs (id) ON DELETE CASCADE,
    PRIMARY KEY (agent_id, dir_id)
);
CREATE INDEX agent_detect_dirs_dir_id_idx ON agent_detect_dirs (dir_id);

CREATE TABLE scan_target_detect_dirs (
    target_id uuid NOT NULL REFERENCES scan_targets (id) ON DELETE CASCADE,
    dir_id    uuid NOT NULL REFERENCES detect_dirs (id) ON DELETE CASCADE,
    PRIMARY KEY (target_id, dir_id)
);
CREATE INDEX scan_target_detect_dirs_dir_id_idx ON scan_target_detect_dirs (dir_id);
