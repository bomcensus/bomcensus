-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up

-- Set by the feed when every matching range is bounded by a vendor build
-- and the component has none: the match is conservative.
ALTER TABLE component_vulns ADD COLUMN build_unknown boolean NOT NULL DEFAULT false;

-- +goose Down

ALTER TABLE component_vulns DROP COLUMN build_unknown;
