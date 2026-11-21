-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up

-- Current processes. pod is '' for a host; for a workload, (pod, container)
-- is the scope the process set was collected from.
CREATE TABLE processes (
    id            uuid PRIMARY KEY,
    asset_id      uuid NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    pod           text NOT NULL DEFAULT '',
    container     text NOT NULL DEFAULT '',
    pid           integer NOT NULL,
    ppid          integer NOT NULL DEFAULT 0,
    user_name     text NOT NULL DEFAULT '',
    uid           integer NOT NULL DEFAULT 0,
    exe           text NOT NULL DEFAULT '',
    exe_source    text NOT NULL DEFAULT '',
    exe_state     text NOT NULL DEFAULT 'normal',
    sha256        text NOT NULL DEFAULT '',
    cmdline       text NOT NULL DEFAULT '',
    started_at    timestamptz NOT NULL,
    libs          jsonb NOT NULL DEFAULT '[]',
    needs_restart boolean NOT NULL DEFAULT false,
    suspicious    boolean NOT NULL DEFAULT false,
    component_id  uuid REFERENCES components (id),
    first_seen    timestamptz NOT NULL,
    last_seen     timestamptz NOT NULL,
    UNIQUE (asset_id, pod, container, pid, started_at)
);

CREATE INDEX processes_needs_restart_idx ON processes (asset_id) WHERE needs_restart;
CREATE INDEX processes_suspicious_idx ON processes (asset_id) WHERE suspicious;

-- Listening sockets. process_id is NULL for a socket whose process is not
-- known; uid is then the socket owner.
CREATE TABLE listen_ports (
    asset_id   uuid NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    pod        text NOT NULL DEFAULT '',
    container  text NOT NULL DEFAULT '',
    process_id uuid REFERENCES processes (id) ON DELETE CASCADE,
    proto      text NOT NULL,
    address    text NOT NULL,
    port       integer NOT NULL,
    uid        integer
);

CREATE INDEX listen_ports_asset_id_idx ON listen_ports (asset_id, pod, container);
CREATE INDEX listen_ports_process_id_idx ON listen_ports (process_id);
CREATE INDEX listen_ports_port_idx ON listen_ports (port);

-- Appeared and disappeared processes. A plain append-only table; old rows are
-- deleted by retention.
CREATE TABLE process_events (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    asset_id   uuid NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    at         timestamptz NOT NULL,
    kind       text NOT NULL CHECK (kind IN ('appeared', 'disappeared')),
    pod        text NOT NULL DEFAULT '',
    container  text NOT NULL DEFAULT '',
    pid        integer NOT NULL,
    user_name  text NOT NULL DEFAULT '',
    exe        text NOT NULL DEFAULT '',
    exe_state  text NOT NULL DEFAULT '',
    sha256     text NOT NULL DEFAULT '',
    started_at timestamptz NOT NULL
);

CREATE INDEX process_events_asset_at_idx ON process_events (asset_id, at DESC);
CREATE INDEX process_events_at_idx ON process_events USING brin (at);

-- +goose Down
DROP TABLE process_events;
DROP TABLE listen_ports;
DROP TABLE processes;
