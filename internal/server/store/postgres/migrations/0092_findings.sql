-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up

-- rpm module stream label (name:stream:version:context). An attribute, not
-- part of the identity: the release of a module package already differs.
ALTER TABLE components ADD COLUMN modularity text NOT NULL DEFAULT '';

-- OS packages owning a process's executable and the shared libraries it
-- maps; NULL when the probe did not report them.
ALTER TABLE processes ADD COLUMN packages text[];

-- A vulnerability of a component on an asset. container is '' for the
-- asset itself. layer tells where the component comes from: '' (the asset
-- itself), 'runtime' (added in the running container), 'image' (the image
-- content; image_digest is set when the content is shared by digest). A row
-- is one presence interval: resolved_at is NULL while the vulnerable
-- component is there.
CREATE TABLE findings (
    id           uuid PRIMARY KEY,
    asset_id     uuid NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    container    text NOT NULL DEFAULT '',
    layer        text NOT NULL DEFAULT '' CHECK (layer IN ('', 'runtime', 'image')),
    image_digest text NOT NULL DEFAULT '',
    component_id uuid NOT NULL REFERENCES components (id) ON DELETE CASCADE,
    vuln_id      text NOT NULL REFERENCES vuln_meta (vuln_id),
    -- listening: a process that loaded the component listens on a
    -- non-loopback address; running: a process loaded it; installed: no
    -- process did; unknown: processes were not fully collected.
    exposure     text NOT NULL CHECK (exposure IN ('listening', 'running', 'installed', 'unknown')),
    -- Reserved for symbol-level reachability; NULL until it is computed.
    reachability text,
    -- [{pid, exe, ports}] of the processes that loaded the component.
    processes    jsonb NOT NULL DEFAULT '[]',
    first_seen   timestamptz NOT NULL,
    resolved_at  timestamptz,
    updated_at   timestamptz NOT NULL
);

CREATE UNIQUE INDEX findings_open_key ON findings (asset_id, container, component_id, vuln_id) WHERE resolved_at IS NULL;
CREATE INDEX findings_open_vuln_idx ON findings (vuln_id) WHERE resolved_at IS NULL;
CREATE INDEX findings_open_component_idx ON findings (component_id) WHERE resolved_at IS NULL;
CREATE INDEX findings_resolved_idx ON findings (resolved_at) WHERE resolved_at IS NOT NULL;

-- What the findings of an asset were last computed from: the asset's
-- last_seen and gone state, and the version of its components'
-- vulnerabilities. The asset is computed again when one of them differs.
-- vulns_version grows whenever the vulnerabilities of one of its components
-- change.
CREATE TABLE asset_findings_state (
    asset_id      uuid PRIMARY KEY REFERENCES assets (id) ON DELETE CASCADE,
    seen_at       timestamptz,
    gone          boolean,
    vulns_version bigint NOT NULL DEFAULT 0,
    vulns_seen    bigint,
    refreshed_at  timestamptz
);

-- +goose Down
DROP TABLE asset_findings_state;
DROP TABLE findings;
ALTER TABLE processes DROP COLUMN packages;
ALTER TABLE components DROP COLUMN modularity;
