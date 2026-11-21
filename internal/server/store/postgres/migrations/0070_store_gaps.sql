-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up

-- Best coverage the currently stored items of a section were collected with.
-- A reduced report does not lower it, so items it cannot see are kept until
-- a report with at least this coverage replaces the set.
ALTER TABLE asset_sections ADD COLUMN baseline_coverage text NOT NULL DEFAULT '';
UPDATE asset_sections SET baseline_coverage = coverage;

-- Sender of a raw report, so that a queued report can be applied without
-- looking the sender up.
ALTER TABLE reports ADD COLUMN sender_kind text NOT NULL DEFAULT '';
ALTER TABLE reports ADD COLUMN remote_addr text NOT NULL DEFAULT '';
UPDATE reports r SET sender_kind = a.kind FROM agents a WHERE a.id::text = r.source_id;
UPDATE reports SET sender_kind = 'scanner' WHERE source_id = '';

-- Time of the pending on-demand collection; cleared by a newer report.
ALTER TABLE assets ADD COLUMN collect_requested_at timestamptz;

CREATE INDEX assets_tags_idx ON assets USING gin (tags);
CREATE INDEX assets_group_name_idx ON assets (group_name) WHERE gone_at IS NULL;
CREATE INDEX asset_components_component_id_idx ON asset_components (component_id);
CREATE INDEX asset_containers_image_digest_idx ON asset_containers (image_digest);
CREATE INDEX scan_targets_asset_id_idx ON scan_targets (asset_id);

-- Outcome of the last sync attempt of a cluster. last_sync stays the time of
-- the last stored inventory.
ALTER TABLE k8s_clusters ADD COLUMN sync_status text NOT NULL DEFAULT 'never'
    CHECK (sync_status IN ('never', 'ok', 'failed'));
ALTER TABLE k8s_clusters ADD COLUMN sync_message text NOT NULL DEFAULT '';
ALTER TABLE k8s_clusters ADD COLUMN sync_status_at timestamptz;
UPDATE k8s_clusters SET sync_status = 'ok', sync_status_at = last_sync WHERE last_sync IS NOT NULL;

-- OpenSSH SHA-256 fingerprint of the public key of an ssh_key credential.
ALTER TABLE credentials ADD COLUMN public_key_fingerprint text NOT NULL DEFAULT '';

-- Revocation refreshes read certificates revoked since a point in time.
CREATE INDEX agent_certs_revoked_at_idx ON agent_certs (revoked_at) WHERE revoked_at IS NOT NULL;
CREATE INDEX agents_revoked_at_idx ON agents (revoked_at) WHERE revoked_at IS NOT NULL;

-- +goose Down
DROP INDEX agents_revoked_at_idx;
DROP INDEX agent_certs_revoked_at_idx;
ALTER TABLE credentials DROP COLUMN public_key_fingerprint;
ALTER TABLE k8s_clusters DROP COLUMN sync_status_at;
ALTER TABLE k8s_clusters DROP COLUMN sync_message;
ALTER TABLE k8s_clusters DROP COLUMN sync_status;
DROP INDEX scan_targets_asset_id_idx;
DROP INDEX asset_containers_image_digest_idx;
DROP INDEX asset_components_component_id_idx;
DROP INDEX assets_group_name_idx;
DROP INDEX assets_tags_idx;
ALTER TABLE assets DROP COLUMN collect_requested_at;
ALTER TABLE reports DROP COLUMN remote_addr;
ALTER TABLE reports DROP COLUMN sender_kind;
ALTER TABLE asset_sections DROP COLUMN baseline_coverage;
