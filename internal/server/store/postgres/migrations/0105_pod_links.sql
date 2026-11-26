-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up

-- A host container that the kubelet created for a pod is linked to the pod
-- by its uid; the pod's workload asset owns its findings.
ALTER TABLE k8s_pods ADD COLUMN uid text NOT NULL DEFAULT '';
CREATE INDEX k8s_pods_uid_idx ON k8s_pods (uid) WHERE uid <> '';

ALTER TABLE asset_containers
    ADD COLUMN pod_uid text NOT NULL DEFAULT '',
    ADD COLUMN pod_container text NOT NULL DEFAULT '';
CREATE INDEX asset_containers_pod_uid_idx ON asset_containers (pod_uid) WHERE pod_uid <> '';

-- +goose Down

DROP INDEX asset_containers_pod_uid_idx;
ALTER TABLE asset_containers DROP COLUMN pod_container, DROP COLUMN pod_uid;
DROP INDEX k8s_pods_uid_idx;
ALTER TABLE k8s_pods DROP COLUMN uid;
