-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up

-- version_sort_key maps a version to a text that sorts in version order
-- under COLLATE "C": digit runs become their length (two digits) followed by
-- the number without leading zeros, so 1.10 sorts after 1.9; "~" sorts
-- before the end of the version (1.0~rc1 < 1.0). deb and rpm versions
-- without an epoch get epoch 0; golang and semver drop the leading "v" and
-- treat the first "-" as a pre-release mark, maven treats "-" before a
-- letter the same way. This is an ordering for lists, not the matching
-- comparison.
--
-- components.version_key is generated from it. Changing the function needs a
-- migration that drops and re-adds the column so stored keys follow.
-- +goose StatementBegin
CREATE FUNCTION version_sort_key(kind text, version text) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
    SELECT CASE WHEN version = '' THEN '' ELSE COALESCE((
        SELECT string_agg(CASE
                WHEN t.tok ~ '^[0-9]' THEN
                    lpad(least(length(t.num), 99)::text, 2, '0') || t.num
                ELSE translate(t.tok, '~', ' ')
            END, '' ORDER BY t.ord)
        FROM (
            SELECT r.m[1] AS tok, COALESCE(NULLIF(ltrim(r.m[1], '0'), ''), '0') AS num, r.ord
            FROM regexp_matches(
                CASE
                    WHEN kind IN ('deb', 'rpm') AND version !~ '^[0-9]+:' THEN '0:' || version
                    WHEN kind IN ('golang', 'semver') THEN regexp_replace(regexp_replace(version, '^v', ''), '-', '~')
                    WHEN kind = 'maven' THEN regexp_replace(version, '-(?=[A-Za-z])', '~', 'g')
                    ELSE regexp_replace(version, '^v(?=[0-9])', '')
                END,
                '[0-9]+|[^0-9]+', 'g') WITH ORDINALITY AS r(m, ord)
        ) t), '') || '!' END
$$;
-- +goose StatementEnd

ALTER TABLE components
    ADD COLUMN version_key text COLLATE "C" NOT NULL GENERATED ALWAYS AS (version_sort_key(type, version)) STORED;

CREATE INDEX components_name_version_key_idx ON components (name, version_key);

-- +goose Down

DROP INDEX components_name_version_key_idx;
ALTER TABLE components DROP COLUMN version_key;
DROP FUNCTION version_sort_key(text, text);
