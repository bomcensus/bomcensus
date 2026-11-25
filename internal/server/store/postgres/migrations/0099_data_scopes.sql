-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up

-- Data scopes. Every scoped record belongs to one scope id; a request sees
-- the records of the ids in its scope. Register keys, scan targets,
-- Kubernetes clusters and credentials are the roots. Agents take the scope
-- of their register key, listen targets that of theirs, assets that of the
-- agent, scan target or cluster they come from. Everything else follows its
-- asset or cluster. Scanners are shared: scanner register keys and scanner
-- agents have no scope and are visible to every scope. Records that existed
-- before are in the default scope.

ALTER TABLE register_keys ADD COLUMN scope_id text;
UPDATE register_keys SET scope_id = 'default' WHERE target_kind <> 'scanner';
ALTER TABLE register_keys ADD CONSTRAINT register_keys_scope_check
    CHECK ((target_kind = 'scanner') = (scope_id IS NULL));
CREATE INDEX register_keys_scope_idx ON register_keys (scope_id);

ALTER TABLE agents ADD COLUMN scope_id text;
UPDATE agents a SET scope_id = coalesce(
        (SELECT k.scope_id FROM register_keys k WHERE k.id = a.register_key_id), 'default')
    WHERE a.kind <> 'scanner';
ALTER TABLE agents ADD CONSTRAINT agents_scope_check CHECK ((kind = 'scanner') = (scope_id IS NULL));
CREATE INDEX agents_scope_idx ON agents (scope_id);

ALTER TABLE listen_targets ADD COLUMN scope_id text NOT NULL DEFAULT 'default';
CREATE INDEX listen_targets_scope_idx ON listen_targets (scope_id);

ALTER TABLE scan_targets ADD COLUMN scope_id text NOT NULL DEFAULT 'default';
CREATE INDEX scan_targets_scope_idx ON scan_targets (scope_id);

-- Names are unique within a scope, so one scope neither sees nor blocks the
-- names of another.
ALTER TABLE k8s_clusters ADD COLUMN scope_id text NOT NULL DEFAULT 'default';
ALTER TABLE k8s_clusters DROP CONSTRAINT k8s_clusters_name_key;
ALTER TABLE k8s_clusters ADD CONSTRAINT k8s_clusters_scope_name_key UNIQUE (scope_id, name);

ALTER TABLE credentials ADD COLUMN scope_id text NOT NULL DEFAULT 'default';
ALTER TABLE credentials DROP CONSTRAINT credentials_name_key;
ALTER TABLE credentials ADD CONSTRAINT credentials_scope_name_key UNIQUE (scope_id, name);

ALTER TABLE assets ADD COLUMN scope_id text NOT NULL DEFAULT 'default';
CREATE INDEX assets_scope_idx ON assets (scope_id);

-- Rules apply only to findings and assets of their own scope. Asset rules
-- have the scope of their asset.
ALTER TABLE triage_rules ADD COLUMN scope_id text NOT NULL DEFAULT 'default';
CREATE INDEX triage_rules_scope_idx ON triage_rules (scope_id);

ALTER TABLE integrity_allow_rules ADD COLUMN scope_id text NOT NULL DEFAULT 'default';
CREATE INDEX integrity_allow_rules_scope_idx ON integrity_allow_rules (scope_id);

-- triage_rule_for takes the scope ids whose rules apply: the scope of the
-- finding's asset, or for content outside an asset (images) the scope of
-- the request; NULL means every scope.
DROP FUNCTION triage_rule_for(text, uuid, text, text, timestamptz);
-- +goose StatementBegin
CREATE FUNCTION triage_rule_for(p_vuln text, p_asset uuid, p_group text, p_purl text, p_at timestamptz,
    p_scopes text[])
RETURNS TABLE (rule_id uuid, expires_at timestamptz)
LANGUAGE sql STABLE AS $$
    SELECT r.id, r.expires_at FROM triage_rules r
    WHERE r.vuln_id = p_vuln AND r.revoked_at IS NULL
        AND (p_scopes IS NULL OR r.scope_id = ANY (p_scopes))
        AND ((r.scope_kind = 'asset' AND r.scope_value = p_asset::text)
            OR (r.scope_kind = 'group' AND p_group <> '' AND r.scope_value = p_group)
            OR (r.scope_kind = 'purl' AND split_part(p_purl, '?', 1) LIKE r.purl_like))
    ORDER BY (r.expires_at IS NULL OR r.expires_at > p_at) DESC, r.expires_at DESC NULLS FIRST, r.created_at DESC
    LIMIT 1
$$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION triage_rule_for(text, uuid, text, text, timestamptz, text[]);
-- +goose StatementBegin
CREATE FUNCTION triage_rule_for(p_vuln text, p_asset uuid, p_group text, p_purl text, p_at timestamptz)
RETURNS TABLE (rule_id uuid, expires_at timestamptz)
LANGUAGE sql STABLE AS $$
    SELECT r.id, r.expires_at FROM triage_rules r
    WHERE r.vuln_id = p_vuln AND r.revoked_at IS NULL
        AND ((r.scope_kind = 'asset' AND r.scope_value = p_asset::text)
            OR (r.scope_kind = 'group' AND p_group <> '' AND r.scope_value = p_group)
            OR (r.scope_kind = 'purl' AND split_part(p_purl, '?', 1) LIKE r.purl_like))
    ORDER BY (r.expires_at IS NULL OR r.expires_at > p_at) DESC, r.expires_at DESC NULLS FIRST, r.created_at DESC
    LIMIT 1
$$;
-- +goose StatementEnd
ALTER TABLE integrity_allow_rules DROP COLUMN scope_id;
ALTER TABLE triage_rules DROP COLUMN scope_id;
ALTER TABLE assets DROP COLUMN scope_id;
ALTER TABLE credentials DROP CONSTRAINT credentials_scope_name_key;
ALTER TABLE credentials ADD CONSTRAINT credentials_name_key UNIQUE (name);
ALTER TABLE credentials DROP COLUMN scope_id;
ALTER TABLE k8s_clusters DROP CONSTRAINT k8s_clusters_scope_name_key;
ALTER TABLE k8s_clusters ADD CONSTRAINT k8s_clusters_name_key UNIQUE (name);
ALTER TABLE k8s_clusters DROP COLUMN scope_id;
ALTER TABLE scan_targets DROP COLUMN scope_id;
ALTER TABLE listen_targets DROP COLUMN scope_id;
ALTER TABLE agents DROP COLUMN scope_id;
ALTER TABLE register_keys DROP COLUMN scope_id;
