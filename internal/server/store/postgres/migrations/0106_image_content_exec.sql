-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up

-- content_exec is set when the content was collected inside a container of
-- the image, where version commands may run. A node agent reads container
-- roots from the host and extracts versions statically only; content from
-- inside the container replaces such content.
ALTER TABLE images ADD COLUMN content_exec boolean NOT NULL DEFAULT false;

-- +goose Down

ALTER TABLE images DROP COLUMN content_exec;
