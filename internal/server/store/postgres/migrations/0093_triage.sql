-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up

-- Judgments that a vulnerability does not affect a scope (CycloneDX VEX
-- not_affected with a justification). A rule applies to the open findings of
-- its vulnerability in its scope, now and later: a component version
-- (purl, without qualifiers; a trailing * matches a prefix), one asset, or
-- an asset group. expires_at NULL defers until the rule is revoked;
-- otherwise the findings come back when it passes, and the triage_expire job
-- records that in expired_at and in an event.
CREATE TABLE triage_rules (
    id            uuid PRIMARY KEY,
    vuln_id       text NOT NULL,
    scope_kind    text NOT NULL CHECK (scope_kind IN ('purl', 'asset', 'group')),
    scope_value   text NOT NULL CHECK (scope_value <> ''),
    -- LIKE pattern of a purl scope, derived from scope_value.
    purl_like     text NOT NULL DEFAULT '',
    status        text NOT NULL DEFAULT 'not_affected' CHECK (status IN ('not_affected')),
    justification text NOT NULL CHECK (justification IN ('code_not_present', 'code_not_reachable',
                      'requires_configuration', 'requires_environment', 'protected_at_runtime',
                      'protected_by_mitigating_control')),
    note          text NOT NULL DEFAULT '',
    expires_at    timestamptz,
    expired_at    timestamptz,
    created_by    text NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL,
    revoked_at    timestamptz,
    revoked_by    text NOT NULL DEFAULT ''
);

CREATE INDEX triage_rules_vuln_idx ON triage_rules (vuln_id) WHERE revoked_at IS NULL;
CREATE INDEX triage_rules_expiry_idx ON triage_rules (expires_at)
    WHERE revoked_at IS NULL AND expired_at IS NULL AND expires_at IS NOT NULL;

-- What happened to rules, in order: created, revoked, expired. findings is
-- the number of open findings the rule decided at that moment.
CREATE TABLE triage_events (
    id       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    rule_id  uuid NOT NULL REFERENCES triage_rules (id) ON DELETE CASCADE,
    kind     text NOT NULL CHECK (kind IN ('created', 'revoked', 'expired')),
    at       timestamptz NOT NULL,
    actor    text NOT NULL DEFAULT '',
    findings integer NOT NULL DEFAULT 0
);

CREATE INDEX triage_events_rule_idx ON triage_events (rule_id);

-- The rule that decides a finding at p_at: an active one (not expired)
-- first, otherwise the one that expired last. Callers treat the result as
-- deferring when expires_at is NULL or after p_at.
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

-- +goose Down
DROP FUNCTION triage_rule_for(text, uuid, text, text, timestamptz);
DROP TABLE triage_events;
DROP TABLE triage_rules;
