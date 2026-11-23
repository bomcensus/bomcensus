-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up

-- Tags of image digests as each source observed them. A source is a host
-- asset (its runtime image list) or a cluster (the container references of
-- its inventory). The tag set of a source is replaced on each observation
-- with full coverage; a tag the source no
-- longer lists keeps its row with gone_at set. A tag is current for a digest
-- while a live source lists it (gone_at IS NULL); otherwise it is a previous
-- tag.
CREATE TABLE image_tags (
    digest      text NOT NULL REFERENCES images (digest) ON DELETE CASCADE,
    tag         text NOT NULL CHECK (tag <> ''),
    source_kind text NOT NULL CHECK (source_kind IN ('asset', 'cluster')),
    source_id   uuid NOT NULL,
    first_seen  timestamptz NOT NULL,
    last_seen   timestamptz NOT NULL,
    gone_at     timestamptz,
    PRIMARY KEY (digest, tag, source_kind, source_id)
);

CREATE INDEX image_tags_source_idx ON image_tags (source_kind, source_id);

ALTER TABLE images DROP COLUMN repo_tags;

-- +goose Down
ALTER TABLE images ADD COLUMN repo_tags text[] NOT NULL DEFAULT '{}';
DROP TABLE image_tags;
