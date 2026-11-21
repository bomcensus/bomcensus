#!/bin/sh
# Copyright (C) 2026 JC-Lab
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
# Additional terms apply. See LICENSING.md.

# Entry point of the agent image.
#
#   run (default)  enroll when the state directory holds no enrollment yet,
#                  then run the agent
#   anything else  passed to bomcensus-agent (for example: version)
#
# Enrollment on first start needs:
#   BOMCENSUS_SERVER       https://HOST:PORT of the agent listener
#   BOMCENSUS_TOKEN        enrollment string of a Register Key
# Optional:
#   BOMCENSUS_SERVER_NAME  name in the server certificate (default: host of BOMCENSUS_SERVER)
#   BOMCENSUS_TLS_VERIFY   pinned (default), system or none
#   BOMCENSUS_TLS_CA       PEM file with extra CA certificates (tls-verify system)
#   BOMCENSUS_STATE_DIR    state directory (default /var/lib/bomcensus/agent)
# The token is passed through the environment, never on a command line,
# and is removed from the environment before the agent runs.

set -eu

agent=/opt/bomcensus/current/bomcensus-agent
state=${BOMCENSUS_STATE_DIR:-/var/lib/bomcensus/agent}

log() { echo "bomcensus-agent-entrypoint: $*" >&2; }

# enroll runs with its own positional parameters; the caller's stay for run.
enroll() {
	set -- --if-not-enrolled --server "$BOMCENSUS_SERVER" --state-dir "$state"
	if [ -n "${BOMCENSUS_SERVER_NAME:-}" ]; then set -- "$@" --server-name "$BOMCENSUS_SERVER_NAME"; fi
	if [ -n "${BOMCENSUS_TLS_VERIFY:-}" ]; then set -- "$@" --tls-verify "$BOMCENSUS_TLS_VERIFY"; fi
	if [ -n "${BOMCENSUS_TLS_CA:-}" ]; then set -- "$@" --tls-ca "$BOMCENSUS_TLS_CA"; fi
	"$agent" enroll "$@"
}

if [ "$#" -eq 0 ]; then
	set -- run
fi
if [ "$1" != run ]; then
	exec "$agent" "$@"
fi
shift

# enroll --if-not-enrolled returns at once for an approved enrollment and
# resumes a pending one. Without the variables, run reports a missing
# enrollment itself.
if [ -n "${BOMCENSUS_SERVER:-}" ] && [ -n "${BOMCENSUS_TOKEN:-}" ]; then
	enroll
fi

unset BOMCENSUS_TOKEN
exec "$agent" run --state-dir "$state" "$@"
