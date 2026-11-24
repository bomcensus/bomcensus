#!/usr/bin/env bash
# Copyright (C) 2026 JC-Lab
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
# Additional terms apply. See LICENSING.md.

# Installs bomcensus from the latest GitHub release.
#
#   curl -fsSL https://github.com/bomcensus/bomcensus/releases/latest/download/install.sh \
#       | bash -s -- server [options]
#   curl -fsSL https://github.com/bomcensus/bomcensus/releases/latest/download/install.sh \
#       | sudo bash -s -- agent --server https://HOST:8443 --token bc1.… [options]
#
# See docs/DEPLOYMENT.md, chapter "Quick install". Everything is inside main()
# so that bash has read the whole script before anything runs (the script may
# be a pipe), and every child process gets /dev/null as stdin.

set -euo pipefail

usage() {
	cat >&2 <<'USAGE'
usage: install.sh server [options]    Docker Compose: PostgreSQL + bomcensus server
       install.sh agent [options]     Linux host agent (systemd), run as root

Common options:
  --rc                    also consider pre-releases (vX.Y.Z-rc.N); the highest
                          version of all releases is installed
  --version VERSION       install this version instead of the latest
  --attest MODE           check the build provenance (SLSA attestation) of the
                          downloads with the GitHub CLI (gh attestation verify):
                            prefer    (default) verify when gh is installed and
                                      logged in, otherwise warn and go on
                            required  fail unless gh can verify
                            disabled  do not verify
                          A failed verification always stops the installation.
  -h, --help

server options:
  --dir DIR               installation directory (default /opt/bomcensus-server
                          as root, ~/bomcensus-server otherwise); an existing
                          installation there is upgraded
  --admin-user NAME       console user of a new installation (default admin)
  --admin-password-file F first line is the console password; without it the
                          password is read from the terminal
  --env NAME=VALUE        set a variable of .env (repeatable), for example
                          --env AGENT_SERVER_NAMES=bomcensus.example.com
  --no-start              prepare everything, do not start the containers

agent options (passed on to the systemd installer; the token may also be
given in $BOMCENSUS_TOKEN):
  --server URL --token TOKEN [--connect-mode connect|listen] [--listen ADDR]
  [--server-name NAME] [--tls-verify pinned|system|none] [--unit-dir DIR]
  [--no-start]
USAGE
	exit "${1:-2}"
}

REPO=${BOMCENSUS_INSTALL_REPO:-bomcensus/bomcensus}
GITHUB=https://github.com
API=https://api.github.com
TAG_RE='^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'

RC=no
VERSION=
ATTEST=prefer
TAG=
WORK=
UNVERIFIED=no
SUMS=SHA256SUMS

log() { echo "install.sh: $*" >&2; }
warn() { echo "install.sh: WARNING: $*" >&2; }
die() { echo "install.sh: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
need() { have "$1" || die "$1 is required"; }

lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

fetch() { # URL FILE
	curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$2" "$1" </dev/null
}

sha256_of() {
	if have sha256sum; then sha256sum "$1" | cut -d' ' -f1
	elif have shasum; then shasum -a 256 "$1" | cut -d' ' -f1
	else die "sha256sum or shasum is required"; fi
}

# ---- version ---------------------------------------------------------------

# Highest semantic version of the tags on stdin. Numbers are compared as
# numbers (also in the pre-release part) and a release ranks above its
# pre-releases.
highest_tag() {
	LC_ALL=C awk '
	function padnum(s,   r) {
		r = ""
		while (match(s, /[0-9]+/)) {
			r = r substr(s, 1, RSTART - 1) sprintf("%09d", substr(s, RSTART, RLENGTH) + 0)
			s = substr(s, RSTART + RLENGTH)
		}
		return r s
	}
	{
		t = $0; v = substr(t, 2); pre = ""
		i = index(v, "-")
		if (i) { pre = substr(v, i + 1); v = substr(v, 1, i - 1) }
		split(v, n, ".")
		key = sprintf("%09d.%09d.%09d", n[1], n[2], n[3]) "|" (pre == "" ? "1" : "0") "|" padnum(pre)
		if (best == "" || key > bestkey) { best = t; bestkey = key }
	}
	END { if (best != "") print best }'
}

resolve_tag() {
	if [ -n "$VERSION" ]; then
		TAG=v$VERSION
	elif [ "$RC" = yes ]; then
		local json tags
		json=$(curl -fsSL --proto '=https' --tlsv1.2 --retry 3 "$API/repos/$REPO/releases?per_page=100" </dev/null) ||
			die "cannot list the releases of $REPO (GitHub API rate limit? use --version)"
		tags=$(printf '%s\n' "$json" | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' |
			sed 's/.*"\([^"]*\)"$/\1/' | grep -E "$TAG_RE" || true)
		TAG=$(printf '%s\n' "$tags" | highest_tag)
		[ -n "$TAG" ] || die "no release found in $REPO"
	else
		# GitHub's own "latest release": never a pre-release or a draft.
		local url
		url=$(curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o /dev/null -w '%{url_effective}' \
			"$GITHUB/$REPO/releases/latest" </dev/null) || die "cannot reach $GITHUB"
		case $url in
		*/releases/tag/*) TAG=${url##*/} ;;
		*) die "no stable release found in $REPO (--rc also considers pre-releases)" ;;
		esac
	fi
	[[ $TAG =~ $TAG_RE ]] || die "'$TAG' is not a release tag (vMAJOR.MINOR.PATCH[-PRERELEASE])"
	VERSION=${TAG#v}
	log "version $VERSION"
}

# ---- download and verification --------------------------------------------

# download NAME...: release assets into $WORK, checked against SHA256SUMS.
download() {
	local f want got
	WORK=$(mktemp -d)
	chmod 700 "$WORK"
	trap 'rm -rf "${WORK:?}"' EXIT
	fetch "$GITHUB/$REPO/releases/download/$TAG/$SUMS" "$WORK/$SUMS" ||
		die "cannot download $SUMS of $TAG from $REPO"
	for f in "$@"; do
		log "downloading $f"
		fetch "$GITHUB/$REPO/releases/download/$TAG/$f" "$WORK/$f" ||
			die "cannot download $f of $TAG"
		want=$(awk -v n="$f" '$2 == n { print $1 }' "$WORK/$SUMS")
		[ -n "$want" ] || die "$f is not listed in $SUMS"
		got=$(sha256_of "$WORK/$f")
		[ "$got" = "$want" ] || die "$f: checksum mismatch"
	done
}

# attest SUBJECT: gh attestation verify of a file or oci://image@digest.
# Returns 0 when verified, 1 when skipped (disabled, or prefer without a
# usable gh); a skip sets UNVERIFIED.
attest() {
	local subject=$1 out
	if [ "$ATTEST" = disabled ]; then
		UNVERIFIED=yes
		return 1
	fi
	if ! have gh; then
		[ "$ATTEST" != required ] || die "--attest required: the GitHub CLI (gh) is not installed"
		warn "gh is not installed: provenance of $(basename "${subject#oci://}") not verified"
		UNVERIFIED=yes
		return 1
	fi
	if out=$(gh attestation verify "$subject" --repo "$REPO" \
		--signer-workflow "$REPO/.github/workflows/release.yml" \
		--source-ref "refs/tags/$TAG" 2>&1 </dev/null); then
		log "attestation ok: $(basename "${subject#oci://}")"
		return 0
	fi
	# gh needs a login even for public repositories. That is "cannot
	# verify", not "does not verify".
	if ! gh auth status >/dev/null 2>&1 </dev/null && [ -z "${GH_TOKEN:-}${GITHUB_TOKEN:-}" ]; then
		[ "$ATTEST" != required ] || die "--attest required: gh is not logged in (gh auth login, or set GH_TOKEN)"
		warn "gh is not logged in: provenance of $(basename "${subject#oci://}") not verified"
		UNVERIFIED=yes
		return 1
	fi
	printf '%s\n' "$out" >&2
	die "attestation of $subject does not verify; nothing was installed"
}

# ---- agent -----------------------------------------------------------------

cmd_agent() {
	[ "$(uname -s)" = Linux ] || die "the agent installer is for Linux (Windows: install.ps1 in bomcensus-windows_VERSION.zip)"
	[ "$(id -u)" = 0 ] || die "must run as root (curl ... | sudo bash -s -- agent ...)"
	need curl
	need tar
	resolve_tag
	local bundle=bomcensus-$VERSION.tar units=bomcensus-systemd_$VERSION.tar.gz
	download "$bundle" "$units"
	attest "$WORK/$bundle" || true
	attest "$WORK/$units" || true
	[ "$UNVERIFIED" = no ] ||
		warn "build provenance not verified: the installer below runs as root and trusts these downloads (checksums only)"
	tar -C "$WORK" -xzf "$WORK/$units"
	local dir=$WORK/bomcensus-systemd_$VERSION
	[ -f "$dir/install.sh" ] || die "$units has no install.sh"
	log "running the systemd installer"
	# $@ is empty when the agent has no options (set -u safe).
	sh "$dir/install.sh" "$WORK/$bundle" ${AGENT_ARGS[@]+"${AGENT_ARGS[@]}"} </dev/null
}

# ---- server ----------------------------------------------------------------

# set_var FILE NAME VALUE: replaces NAME=... in FILE (or appends it). The
# value reaches awk through the environment, not its arguments.
set_var() {
	VALUE=$3 awk -v name="$2" 'BEGIN { v = ENVIRON["VALUE"] }
		index($0, name "=") == 1 { print name "=" v; found = 1; next }
		{ print }
		END { if (!found) print name "=" v }' "$1" >"$1.tmp"
	mv "$1.tmp" "$1"
}

get_var() { # FILE NAME
	sed -n "s/^$2=//p" "$1" | head -n 1
}

cmd_server() {
	need curl
	need tar
	need docker
	docker compose version >/dev/null 2>&1 </dev/null || die "the docker compose plugin is required"
	docker info >/dev/null 2>&1 </dev/null || die "cannot talk to the Docker daemon (is it running, are you in the docker group?)"
	if [ -z "$SERVER_DIR" ]; then
		if [ "$(id -u)" = 0 ]; then SERVER_DIR=/opt/bomcensus-server; else SERVER_DIR=$HOME/bomcensus-server; fi
	fi
	umask 077
	resolve_tag
	local images
	images=ghcr.io/$(lower "$REPO")
	local pack=bomcensus-compose_$VERSION.tar.gz
	download "$pack"
	attest "$WORK/$pack" || true
	tar -C "$WORK" -xzf "$WORK/$pack"
	local src=$WORK/bomcensus-compose_$VERSION
	local f
	for f in compose.yaml .env.example init.sh; do [ -f "$src/$f" ] || die "$pack has no $f"; done

	local fresh=yes cur_repo cur_version=
	if [ -f "$SERVER_DIR/.env" ]; then
		fresh=no
		cur_repo=$(get_var "$SERVER_DIR/.env" BOMCENSUS_REPO)
		cur_version=$(get_var "$SERVER_DIR/.env" BOMCENSUS_VERSION)
		# Images of another origin (a local build, with its own release keys)
		# must not be swapped for these: agents trust one key.
		[ "$cur_repo" = "$images" ] ||
			die "$SERVER_DIR/.env uses images from '$cur_repo', not $images; refusing to switch (see docs/DEPLOYMENT.md, Upgrading)"
		[ "$cur_version" != "$VERSION" ] || log "version $VERSION is already installed"
	fi

	# The server image first: init.sh hashes the password with it, and the
	# compose file must not build it.
	local image=$images/server:$VERSION digest
	log "pulling $image"
	docker pull "$image" >&2 </dev/null
	digest=$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$image" </dev/null |
		grep -F "$images/server@" | head -n 1 || true)
	[ -n "$digest" ] || die "no registry digest for $image"
	attest "oci://$digest" || true
	[ "$UNVERIFIED" = no ] || warn "build provenance not verified: the installation trusts these downloads (checksums only)"

	mkdir -p "$SERVER_DIR"
	install -m 0644 "$src/compose.yaml" "$SERVER_DIR/compose.yaml"
	install -m 0644 "$src/.env.example" "$SERVER_DIR/.env.example"
	install -m 0755 "$src/init.sh" "$SERVER_DIR/init.sh"

	if [ "$fresh" = yes ]; then
		log "creating $SERVER_DIR/.env"
		if [ -n "$ADMIN_PASSWORD_FILE" ]; then
			(cd "$SERVER_DIR" && ADMIN_USER=$ADMIN_USER BOMCENSUS_REPO=$images BOMCENSUS_VERSION=$VERSION \
				./init.sh <"$ADMIN_PASSWORD_FILE") || die "init.sh failed"
		elif { : </dev/tty; } 2>/dev/null; then
			(cd "$SERVER_DIR" && ADMIN_USER=$ADMIN_USER BOMCENSUS_REPO=$images BOMCENSUS_VERSION=$VERSION \
				./init.sh </dev/tty) || die "init.sh failed"
		else
			die "no terminal for the admin password: give --admin-password-file"
		fi
	else
		log "upgrading $SERVER_DIR from ${cur_version:-?} to $VERSION"
		[ "$cur_version" = "$VERSION" ] ||
			warn "back up the database and .env first if you have not (docs/DEPLOYMENT.md, Backup); the server migrates the database at start"
	fi
	set_var "$SERVER_DIR/.env" BOMCENSUS_REPO "$images"
	set_var "$SERVER_DIR/.env" BOMCENSUS_VERSION "$VERSION"
	local kv
	for kv in ${SERVER_ENV[@]+"${SERVER_ENV[@]}"}; do
		set_var "$SERVER_DIR/.env" "${kv%%=*}" "${kv#*=}"
	done

	if [ "$START" = no ]; then
		log "prepared $SERVER_DIR; start with: cd $SERVER_DIR && docker compose up -d --wait --no-build"
		return 0
	fi
	log "starting"
	(cd "$SERVER_DIR" && docker compose up -d --wait --no-build >&2 </dev/null) ||
		die "docker compose up failed (see 'docker compose logs' in $SERVER_DIR)"
	local web
	web=$(get_var "$SERVER_DIR/.env" WEB_PORT)
	log "bomcensus $VERSION is running: https://localhost:${web:-8080} (user $(get_var "$SERVER_DIR/.env" ADMIN_USER))"
	log "agents connect to port $(get_var "$SERVER_DIR/.env" AGENT_PORT); their server name must be in AGENT_SERVER_NAMES ($(get_var "$SERVER_DIR/.env" AGENT_SERVER_NAMES)) of $SERVER_DIR/.env"
}

# ---- main ------------------------------------------------------------------

value() { [ $# -ge 2 ] || { echo "$1 needs a value" >&2; usage; }; }

main() {
	SERVER_DIR= ADMIN_USER=admin ADMIN_PASSWORD_FILE= START=yes
	SERVER_ENV=()
	AGENT_ARGS=()
	[ $# -gt 0 ] || usage
	local sub=$1
	case $sub in
	server | agent) shift ;;
	-h | --help) usage 0 ;;
	*) echo "unknown command '$sub'" >&2; usage ;;
	esac

	while [ $# -gt 0 ]; do
		case $1 in
		-h | --help) usage 0 ;;
		--rc) RC=yes; shift ;;
		--version) value "$@"; VERSION=${2#v}; shift 2 ;;
		--attest)
			value "$@"
			case $2 in
			prefer | required | disabled) ATTEST=$2 ;;
			*) die "--attest takes prefer, required or disabled" ;;
			esac
			shift 2
			;;
		--no-start) START=no; [ "$sub" = server ] || AGENT_ARGS+=("$1"); shift ;;
		--dir | --admin-user | --admin-password-file | --env)
			[ "$sub" = server ] || die "$1 is a server option"
			value "$@"
			case $1 in
			--dir) SERVER_DIR=$2 ;;
			--admin-user) ADMIN_USER=$2 ;;
			--admin-password-file) ADMIN_PASSWORD_FILE=$2 ;;
			--env)
				[[ $2 =~ ^[A-Z][A-Z0-9_]*=. ]] || die "--env takes NAME=VALUE (NAME in capitals)"
				SERVER_ENV+=("$2")
				;;
			esac
			shift 2
			;;
		--server | --token | --connect-mode | --listen | --server-name | --tls-verify | --unit-dir)
			[ "$sub" = agent ] || die "$1 is an agent option"
			value "$@"
			AGENT_ARGS+=("$1" "$2")
			shift 2
			;;
		*) echo "unknown option $1" >&2; usage ;;
		esac
	done
	[ -z "$VERSION" ] || [[ v$VERSION =~ $TAG_RE ]] || die "--version '$VERSION' is not MAJOR.MINOR.PATCH[-PRERELEASE]"
	[ -z "$VERSION" ] || [ "$RC" = no ] || warn "--version given: --rc has no effect"

	"cmd_$sub"
}

main "$@"
