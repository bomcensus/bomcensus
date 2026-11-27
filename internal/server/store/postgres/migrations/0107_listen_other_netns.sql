-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up

-- other_netns is set for a socket of a process in another network namespace
-- than the host's (a pod network). Such a socket of a host container linked
-- to a pod is listed under the pod's workload asset, not the host.
ALTER TABLE listen_ports ADD COLUMN other_netns boolean NOT NULL DEFAULT false;

-- +goose Down

ALTER TABLE listen_ports DROP COLUMN other_netns;
