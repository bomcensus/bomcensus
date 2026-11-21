#!/bin/sh
# Copyright (C) 2026 JC-Lab
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
# Additional terms apply. See LICENSING.md.

# Creates deploy/docker/.env from .env.example: a random master key, a
# random PostgreSQL password and the argon2id hash of the admin password,
# made with the server image's hash-password command. No secret is printed.
#
# The password is read from the terminal; without a terminal, the first
# line of stdin is used. ADMIN_USER in the environment sets the user name.
# The server image must exist (make docker-build) or be buildable.

set -eu

cd "$(dirname "$0")"

die() { echo "init.sh: $*" >&2; exit 1; }

[ -e .env ] && die ".env exists; remove it first to start over (this discards the master key)"
command -v docker >/dev/null 2>&1 || die "docker not found"

umask 077

# random BYTES ENCODING: BYTES random bytes in base64 or hex.
random() {
	if [ "$2" = base64 ]; then
		head -c "$1" /dev/urandom | base64 | tr -d '\n'
	else
		head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'
	fi
}

# setvar NAME VALUE: replaces the line NAME=... in .env.tmp. The value
# reaches awk through the environment, not through its arguments.
setvar() {
	VALUE=$2
	export VALUE
	awk -v name="$1" 'BEGIN { v = ENVIRON["VALUE"] }
		index($0, name "=") == 1 { print name "=" v; next }
		{ print }' .env.tmp >.env.tmp2
	unset VALUE
	mv .env.tmp2 .env.tmp
}

read_password() {
	if [ -t 0 ]; then
		stty -echo
		trap 'stty echo' EXIT INT TERM
		printf 'Admin password: ' >&2
		IFS= read -r pw1
		printf '\nRepeat password: ' >&2
		IFS= read -r pw2
		printf '\n' >&2
		stty echo
		trap - EXIT INT TERM
		[ "$pw1" = "$pw2" ] || die "passwords do not match"
	else
		IFS= read -r pw1 || true
	fi
	[ -n "$pw1" ] || die "empty password"
	password=$pw1
	pw1= pw2=
}

user=${ADMIN_USER:-admin}
read_password

trap 'rm -f .env.tmp .env.tmp2' EXIT
cp .env.example .env.tmp
chmod 600 .env.tmp

setvar ADMIN_USER "$user"
setvar BOMCENSUS_MASTER_KEY "$(random 32 base64)"
setvar POSTGRES_PASSWORD "$(random 24 hex)"

# hash-password reads the password from stdin. The placeholder only
# satisfies the interpolation of compose.yaml for this one run.
echo "init.sh: hashing the admin password with the server image" >&2
if ! hash=$(printf '%s\n' "$password" | ADMIN_PASSWORD_HASH=unset \
	docker compose --env-file .env.tmp run --rm --no-deps -T --quiet-pull server hash-password); then
	die "hash-password failed (is the server image built? make docker-build)"
fi
password=
case "$hash" in
'$argon2id$'*) ;;
*) die "hash-password returned no argon2id hash" ;;
esac
# Single quotes keep compose from interpolating the $ signs of the hash.
setvar ADMIN_PASSWORD_HASH "'$hash'"
mv .env.tmp .env
trap - EXIT
echo "init.sh: wrote $(pwd)/.env (user: $user); start with: docker compose up -d" >&2
