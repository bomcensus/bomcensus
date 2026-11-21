-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up
ALTER TABLE agents ADD COLUMN update_message text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE agents DROP COLUMN update_message;
