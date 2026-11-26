-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up

-- last_affected: the highest "up to and including" end of the matching
-- ranges when no fixed version above it is known. affected_ranges: the
-- matching CPE ranges the version is in.
ALTER TABLE component_vulns
    ADD COLUMN last_affected text NOT NULL DEFAULT '',
    ADD COLUMN affected_ranges jsonb NOT NULL DEFAULT '[]';

-- +goose Down

ALTER TABLE component_vulns DROP COLUMN affected_ranges, DROP COLUMN last_affected;
