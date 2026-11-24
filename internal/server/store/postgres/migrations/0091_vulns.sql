-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up

-- Vulnerability details as the feed server last returned them.
CREATE TABLE vuln_meta (
    vuln_id         text PRIMARY KEY,
    aliases         text[] NOT NULL DEFAULT '{}',
    summary         text NOT NULL DEFAULT '',
    description     text NOT NULL DEFAULT '',
    -- [{source, type, version, vector, score, severity}]
    cvss            jsonb NOT NULL DEFAULT '[]',
    -- Highest CVSS base score, and its rating.
    max_score       real,
    severity        text NOT NULL DEFAULT ''
                    CHECK (severity IN ('', 'critical', 'high', 'medium', 'low', 'none')),
    cwes            text[] NOT NULL DEFAULT '{}',
    refs            text[] NOT NULL DEFAULT '{}',
    kev_added       date,
    kev             jsonb,
    epss            real,
    epss_percentile real,
    published       timestamptz,
    modified        timestamptz,
    updated_at      timestamptz NOT NULL
);

-- The last match of each unique component. A component is matched again
-- when the active server, its data revision or its rules change.
CREATE TABLE component_matches (
    component_id   uuid PRIMARY KEY REFERENCES components (id) ON DELETE CASCADE,
    feed_server_id uuid NOT NULL REFERENCES feed_servers (id) ON DELETE CASCADE,
    revision       bigint NOT NULL,
    rules_digest   text NOT NULL,
    -- The release OS packages were matched against (debian:12); empty for
    -- components matched without an OS.
    os_key         text NOT NULL DEFAULT '',
    status         text NOT NULL CHECK (status IN ('checked', 'unsupported', 'invalid')),
    reason         text NOT NULL DEFAULT '',
    matched_at     timestamptz NOT NULL
);

CREATE INDEX component_matches_server_idx ON component_matches (feed_server_id, status);

-- Vulnerabilities of a component, replaced with each match.
CREATE TABLE component_vulns (
    component_id  uuid NOT NULL REFERENCES components (id) ON DELETE CASCADE,
    vuln_id       text NOT NULL REFERENCES vuln_meta (vuln_id),
    method        text NOT NULL CHECK (method IN ('package', 'cpe')),
    ecosystem     text NOT NULL DEFAULT '',
    fix_state     text NOT NULL
                  CHECK (fix_state IN ('fixed', 'not_fixed', 'will_not_fix', 'under_investigation', 'unknown')),
    fixed_version text NOT NULL DEFAULT '',
    cpe_match     text NOT NULL DEFAULT '',
    range_source  text NOT NULL DEFAULT '',
    platforms     text[] NOT NULL DEFAULT '{}',
    -- [{source, id, severity}]
    advisories    jsonb NOT NULL DEFAULT '[]',
    PRIMARY KEY (component_id, vuln_id, method)
);

CREATE INDEX component_vulns_vuln_idx ON component_vulns (vuln_id);

-- +goose Down
DROP TABLE component_vulns;
DROP TABLE component_matches;
DROP TABLE vuln_meta;
