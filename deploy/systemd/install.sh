#!/bin/sh
# Copyright (C) 2026 JC-Lab
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
# Additional terms apply. See LICENSING.md.

# Install the bomcensus host agent as systemd units. Run as root.
# See docs/DEPLOYMENT.md, chapter "systemd (host agent)".
set -eu

OPT=/opt/bomcensus
VAR=/var/lib/bomcensus
STATE=$VAR/agent
SPOOL=$VAR/update-spool
UNIT_DIR=/etc/systemd/system
UNITS="bomcensus-agent.service bomcensus-boot-check.service bomcensus-probe.socket bomcensus-probe@.service bomcensus-updater.path bomcensus-updater.service"
U_AGENT=bomcensus
U_PROBE=bomcensus-probe
U_UPDATE=bomcensus-update

SRC_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SOURCE=
SERVER=
TOKEN=${BOMCENSUS_TOKEN:-}
CONNECT_MODE=
LISTEN=
SERVER_NAME=
TLS_VERIFY=
START=yes

usage() {
	cat >&2 <<USAGE
usage: install.sh [SOURCE] [--server URL --token TOKEN [--connect-mode connect|listen]
                  [--listen ADDR] [--server-name NAME] [--tls-verify pinned|system|none]]
                  [--unit-dir DIR] [--no-start]

SOURCE is a release bundle (bomcensus-<version>.tar) or a directory with the
binaries bomcensus-agent, bomcensus-probe and bomcensus-updater (or with a
linux-<arch>/ directory holding them). Without SOURCE only users, directories
and units are (re)installed.

A bundle is installed by the updater, which verifies it. A directory is
copied as it is (no signature check by this script); the updater adopts it.
The token may also be given in \$BOMCENSUS_TOKEN.
USAGE
	exit 2
}

die() { echo "install.sh: $*" >&2; exit 1; }
info() { echo "install.sh: $*"; }

while [ $# -gt 0 ]; do
	case $1 in
	--server) [ $# -ge 2 ] || usage; SERVER=$2; shift 2 ;;
	--token) [ $# -ge 2 ] || usage; TOKEN=$2; shift 2 ;;
	--connect-mode) [ $# -ge 2 ] || usage; CONNECT_MODE=$2; shift 2 ;;
	--listen) [ $# -ge 2 ] || usage; LISTEN=$2; shift 2 ;;
	--server-name) [ $# -ge 2 ] || usage; SERVER_NAME=$2; shift 2 ;;
	--tls-verify) [ $# -ge 2 ] || usage; TLS_VERIFY=$2; shift 2 ;;
	--unit-dir) [ $# -ge 2 ] || usage; UNIT_DIR=$2; shift 2 ;;
	--no-start) START=no; shift ;;
	-h | --help) usage ;;
	-*) echo "unknown option $1" >&2; usage ;;
	*) [ -z "$SOURCE" ] || usage; SOURCE=$1; shift ;;
	esac
done

[ "$(id -u)" = 0 ] || die "must run as root"
[ -d /run/systemd/system ] || die "systemd is not running; see 'non-systemd / unprivileged' in docs/DEPLOYMENT.md"
if [ -n "$SERVER" ] && [ -z "$TOKEN" ]; then die "--server needs --token (or \$BOMCENSUS_TOKEN)"; fi
if [ -z "$SERVER" ] && [ "$CONNECT_MODE" != listen ] && [ -n "$TOKEN" ]; then die "--token needs --server"; fi

case $(uname -m) in
x86_64 | amd64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
*) die "unsupported architecture $(uname -m)" ;;
esac

# Run a command as another user without a login shell; the environment is kept.
as_user() {
	_u=$1
	shift
	if command -v runuser >/dev/null 2>&1; then
		runuser -u "$_u" -- "$@"
	elif command -v setpriv >/dev/null 2>&1; then
		setpriv --reuid "$_u" --regid "$_u" --init-groups "$@"
	else
		die "runuser or setpriv (util-linux) is required"
	fi
}

nologin=/usr/sbin/nologin
[ -x "$nologin" ] || nologin=/sbin/nologin
[ -x "$nologin" ] || nologin=/bin/false

add_user() {
	if id "$1" >/dev/null 2>&1; then return; fi
	info "creating user $1"
	useradd --system --user-group --no-create-home --home-dir "$VAR" \
		--shell "$nologin" --comment "bomcensus $2" "$1"
}

# 1. Users.
add_user $U_AGENT agent
add_user $U_PROBE probe
add_user $U_UPDATE updater

# 2. Directories.
#   /opt/bomcensus      written only by the update user (installs releases)
#   .../agent           agent only
#   .../update-spool    agent writes, updater reads and deletes: owner agent,
#                       group updater, setgid so that files of the agent get
#                       the updater group.
mkdir -p $OPT $VAR $STATE $SPOOL
chown $U_UPDATE:$U_UPDATE $OPT && chmod 0755 $OPT
chown root:root $VAR && chmod 0755 $VAR
chown $U_AGENT:$U_AGENT $STATE && chmod 0700 $STATE
chown $U_AGENT:$U_UPDATE $SPOOL && chmod 2770 $SPOOL

# 3. Release.
# Scratch directory for the bootstrap updater. It is under /opt (not /run or
# /tmp), which are often mounted noexec.
tmp=$(mktemp -d $OPT/.bootstrap.XXXXXX)
trap 'rm -rf "${tmp:?}"' EXIT INT TERM
chmod 0755 "$tmp"

set_current() { # version
	if [ -e $OPT/current ] || [ -L $OPT/current ]; then return 0; fi
	info "creating $OPT/current -> versions/$1"
	ln -s "versions/$1" $OPT/.current.tmp
	chown -h $U_UPDATE:$U_UPDATE $OPT/.current.tmp
	mv -f $OPT/.current.tmp $OPT/current
}

install_bundle() { # file
	_b=$1
	_v=$(tar -xOf "$_b" manifest.json | sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
	[ -n "$_v" ] || die "$_b: no version in manifest.json"
	if [ -d "$OPT/versions/$_v" ] && [ -L $OPT/current ]; then
		info "version $_v is already installed"
		return 0
	fi
	# The updater is taken from the bundle for this first run only. It
	# verifies the bundle, but a modified bundle could carry a modified
	# updater: check where the bundle came from before running this.
	tar -xOf "$_b" "linux-$ARCH/bomcensus-updater" >"$tmp/bomcensus-updater" ||
		die "$_b has no linux-$ARCH/bomcensus-updater"
	chmod 0755 "$tmp/bomcensus-updater"
	# A private spool: root must not write into the shared spool, where the
	# agent user could have planted a symlink under the name used here.
	mkdir "$tmp/spool"
	cp "$_b" "$tmp/spool/bomcensus-$_v.tar"
	chown -R $U_UPDATE:$U_UPDATE "$tmp/spool"
	chmod 0700 "$tmp/spool"
	info "installing $_v through the updater"
	as_user $U_UPDATE "$tmp/bomcensus-updater" apply --spool "$tmp/spool" --install $OPT ||
		die "the updater failed"
	if [ ! -d "$OPT/versions/$_v" ] || [ ! -L $OPT/current ]; then
		die "the updater did not install $_v (see the messages above; a bundle that fails verification is rejected and deleted)"
	fi
}

install_dir() { # directory
	_d=$1
	[ -d "$_d/linux-$ARCH" ] && _d=$_d/linux-$ARCH
	for _f in bomcensus-agent bomcensus-probe bomcensus-updater; do
		[ -f "$_d/$_f" ] || die "$_d/$_f not found"
	done
	_v=$("$_d/bomcensus-updater" version) || die "cannot run $_d/bomcensus-updater version"
	[ -n "$_v" ] || die "empty version from $_d/bomcensus-updater"
	if [ -d "$OPT/versions/$_v" ]; then
		info "version $_v is already installed"
	else
		info "copying binaries of version $_v (not verified by this script)"
		mkdir -p $OPT/versions
		_t=$OPT/versions/.tmp-install.$$
		rm -rf "${_t:?}"
		mkdir "$_t"
		for _f in bomcensus-agent bomcensus-probe bomcensus-updater; do
			cp "$_d/$_f" "$_t/$_f"
		done
		chown -R $U_UPDATE:$U_UPDATE "$_t"
		chmod 0755 "$_t" "$_t"/*
		mv "$_t" "$OPT/versions/$_v"
		chown $U_UPDATE:$U_UPDATE $OPT/versions
	fi
	set_current "$_v"
}

if [ -n "$SOURCE" ]; then
	if [ -d "$SOURCE" ]; then
		install_dir "$SOURCE"
	elif [ -f "$SOURCE" ]; then
		# Do not let a spool event start the updater before current exists.
		systemctl stop bomcensus-updater.path 2>/dev/null || true
		install_bundle "$SOURCE"
	else
		die "$SOURCE: no such file or directory"
	fi
fi
[ -L $OPT/current ] || die "no release installed: $OPT/current is missing; give a bundle or a directory of binaries"

# 4. Units.
for u in $UNITS; do
	[ -f "$SRC_DIR/$u" ] || die "$SRC_DIR/$u not found"
	install -m 0644 -o root -g root "$SRC_DIR/$u" "$UNIT_DIR/$u"
done
systemctl daemon-reload
systemctl enable bomcensus-probe.socket bomcensus-updater.path bomcensus-agent.service >/dev/null

# 5. Enrollment, as the agent user, before the agent starts.
if [ -n "$SERVER" ] || [ "$CONNECT_MODE" = listen ]; then
	if [ -f $STATE/enrollment.json ]; then
		info "already enrolled ($STATE/enrollment.json); not enrolling again"
	else
		[ -n "$TOKEN" ] || die "listen mode needs --token"
		set -- enroll
		[ -z "$SERVER" ] || set -- "$@" --server "$SERVER"
		[ -z "$CONNECT_MODE" ] || set -- "$@" --connect-mode "$CONNECT_MODE"
		[ -z "$LISTEN" ] || set -- "$@" --listen "$LISTEN"
		[ -z "$SERVER_NAME" ] || set -- "$@" --server-name "$SERVER_NAME"
		[ -z "$TLS_VERIFY" ] || set -- "$@" --tls-verify "$TLS_VERIFY"
		info "enrolling"
		BOMCENSUS_TOKEN=$TOKEN as_user $U_AGENT $OPT/current/bomcensus-agent "$@" --state-dir $STATE ||
			die "enrollment failed"
	fi
fi

# 6. Start.
if [ "$START" = yes ]; then
	systemctl start bomcensus-probe.socket bomcensus-updater.path
	if [ -f $STATE/enrollment.json ]; then
		systemctl restart bomcensus-agent.service
		info "agent started"
	else
		info "not enrolled: the agent is enabled but not started; run 'bomcensus-agent enroll' as $U_AGENT, then 'systemctl start bomcensus-agent'"
	fi
fi
info "done"
