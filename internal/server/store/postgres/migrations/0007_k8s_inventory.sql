-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up
CREATE TABLE k8s_workloads (
    id          uuid PRIMARY KEY,
    cluster_id  uuid NOT NULL REFERENCES k8s_clusters (id) ON DELETE CASCADE,
    namespace   text NOT NULL,
    kind        text NOT NULL,
    name        text NOT NULL,
    replicas    integer NOT NULL DEFAULT 0,
    asset_id    uuid REFERENCES assets (id) ON DELETE SET NULL,
    excluded    boolean NOT NULL DEFAULT false,
    excluded_by text NOT NULL DEFAULT '',
    first_seen  timestamptz NOT NULL,
    last_seen   timestamptz NOT NULL,
    gone_at     timestamptz,
    UNIQUE (cluster_id, namespace, kind, name)
);

CREATE INDEX k8s_workloads_asset_id_idx ON k8s_workloads (asset_id);
CREATE INDEX k8s_workloads_gone_at_idx ON k8s_workloads (gone_at) WHERE gone_at IS NOT NULL;

CREATE TABLE k8s_pods (
    id          uuid PRIMARY KEY,
    cluster_id  uuid NOT NULL REFERENCES k8s_clusters (id) ON DELETE CASCADE,
    workload_id uuid NOT NULL REFERENCES k8s_workloads (id) ON DELETE CASCADE,
    namespace   text NOT NULL,
    name        text NOT NULL,
    node        text NOT NULL DEFAULT '',
    phase       text NOT NULL DEFAULT '',
    started_at  timestamptz,
    first_seen  timestamptz NOT NULL,
    last_seen   timestamptz NOT NULL,
    gone_at     timestamptz,
    UNIQUE (cluster_id, namespace, name)
);

CREATE INDEX k8s_pods_workload_id_idx ON k8s_pods (workload_id);
CREATE INDEX k8s_pods_gone_at_idx ON k8s_pods (gone_at) WHERE gone_at IS NOT NULL;

CREATE TABLE k8s_pod_containers (
    pod_id          uuid NOT NULL REFERENCES k8s_pods (id) ON DELETE CASCADE,
    name            text NOT NULL,
    image_ref       text NOT NULL DEFAULT '',
    image_digest    text NOT NULL DEFAULT '',
    coverage        text NOT NULL DEFAULT 'inventory_only',
    coverage_reason text NOT NULL DEFAULT '',
    PRIMARY KEY (pod_id, name)
);

CREATE INDEX k8s_pod_containers_digest_idx ON k8s_pod_containers (image_digest);

-- +goose Down
DROP TABLE k8s_pod_containers;
DROP TABLE k8s_pods;
DROP TABLE k8s_workloads;
