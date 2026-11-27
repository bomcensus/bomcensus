-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up

-- Security notices (KISA, vendors) as the feed server last returned them.
-- A notice is never a finding: the console shows it with the assets whose
-- software it names.
CREATE TABLE notices (
    notice_id       text PRIMARY KEY,
    source          text NOT NULL,
    title           text NOT NULL DEFAULT '',
    url             text NOT NULL DEFAULT '',
    published       timestamptz,
    summary         text NOT NULL DEFAULT '',
    cve_ids         text[] NOT NULL DEFAULT '{}',
    advisory_ids    text[] NOT NULL DEFAULT '{}',
    -- [{vendor, product, cpe_vendor, cpe_product, affected, fixed}]
    software        jsonb NOT NULL DEFAULT '[]',
    -- When the feed last changed the notice or its classification.
    modified        timestamptz,
    updated_at      timestamptz NOT NULL
);

-- Notices of a component, replaced with each match. linked_at is when the
-- link was made; it stays while the component keeps matching.
CREATE TABLE component_notices (
    component_id uuid NOT NULL REFERENCES components (id) ON DELETE CASCADE,
    notice_id    text NOT NULL REFERENCES notices (notice_id),
    linked_at    timestamptz NOT NULL,
    PRIMARY KEY (component_id, notice_id)
);

CREATE INDEX component_notices_notice_idx ON component_notices (notice_id);

-- Read marks, per notice and data scope id. An asset of the scope that
-- starts matching the notice after read_at makes it unread again.
CREATE TABLE notice_reads (
    notice_id text NOT NULL REFERENCES notices (notice_id) ON DELETE CASCADE,
    scope_id  text NOT NULL,
    read_at   timestamptz NOT NULL,
    read_by   text NOT NULL DEFAULT '',
    PRIMARY KEY (notice_id, scope_id)
);

-- +goose Down
DROP TABLE notice_reads;
DROP TABLE component_notices;
DROP TABLE notices;
