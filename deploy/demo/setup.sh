#!/bin/sh
# Copyright (C) 2026 JC-Lab
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
# Additional terms apply. See LICENSING.md.

# Demo setup, run by the setup service of compose.yaml through the admin API:
#   - a Register Key for the demo agent; its enrollment string is written to
#     /demo/agent-token, where the agent container reads it on first start
#   - an SSH password credential demo / demo
#   - one scan target per host in DEMO_SSH_TARGETS, each scanned once
# Objects found by name are reused.

set -eu

api=$DEMO_API
jar=$(mktemp)
trap 'rm -f "$jar"' EXIT

log() { echo "demo-setup: $*" >&2; }

call() {
	curl -fsS -b "$jar" -c "$jar" -H 'X-Requested-With: bomcensus' -H 'Content-Type: application/json' "$@"
}

# id_by_name PATH NAME: id of the first item of a list endpoint with that name.
id_by_name() {
	call "$api$1?limit=1000" | jq -r --arg n "$2" '[.items[] | select(.name == $n)][0].id // empty'
}

call -o /dev/null --data "$(jq -n --arg u "$DEMO_ADMIN_USER" --arg p "$DEMO_ADMIN_PASSWORD" '{username: $u, password: $p}')" \
	"$api/auth/login"

if [ -s /demo/agent-token ]; then
	log "agent Register Key: already created"
else
	call --data '{"name":"demo agent","target":"agent","approval":"auto","maxUses":1}' "$api/register-keys" |
		jq -er .enrollment >/demo/agent-token.tmp
	# The agent runs as another user; this string is a demo secret.
	chmod 0644 /demo/agent-token.tmp
	mv /demo/agent-token.tmp /demo/agent-token
	log "agent Register Key: created"
fi

cred=$(id_by_name /credentials demo-ssh)
if [ -z "$cred" ]; then
	cred=$(call --data '{"name":"demo-ssh","kind":"ssh_password","username":"demo","password":"demo"}' \
		"$api/credentials" | jq -er .id)
	log "credential demo-ssh: created"
fi

for host in $DEMO_SSH_TARGETS; do
	target=$(id_by_name /scan-targets "$host")
	if [ -z "$target" ]; then
		target=$(call --data "$(jq -n --arg h "$host" --arg c "$cred" \
			'{name: $h, address: $h, port: 22, credentialId: $c, intervalMinutes: 60}')" \
			"$api/scan-targets" | jq -er .id)
		call -o /dev/null -X POST "$api/scan-targets/$target/run"
		log "scan target $host: created, first scan started"
	else
		log "scan target $host: already created"
	fi
done
