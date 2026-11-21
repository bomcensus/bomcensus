#!/bin/sh
# Copyright (C) 2026 JC-Lab
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
# Additional terms apply. See LICENSING.md.

# Remove the bomcensus host agent units and releases. Run as root.
# State (/var/lib/bomcensus/agent) and the users are kept unless --purge.
set -eu

OPT=/opt/bomcensus
VAR=/var/lib/bomcensus
UNIT_DIR=/etc/systemd/system
PURGE=no
UNITS="bomcensus-agent.service bomcensus-boot-check.service bomcensus-probe.socket bomcensus-probe@.service bomcensus-updater.path bomcensus-updater.service"

usage() { echo "usage: uninstall.sh [--purge] [--unit-dir DIR]" >&2; exit 2; }

while [ $# -gt 0 ]; do
	case $1 in
	--purge) PURGE=yes; shift ;;
	--unit-dir) [ $# -ge 2 ] || usage; UNIT_DIR=$2; shift 2 ;;
	*) usage ;;
	esac
done
[ "$(id -u)" = 0 ] || { echo "uninstall.sh: must run as root" >&2; exit 1; }
[ -n "$UNIT_DIR" ] || usage

systemd=no
[ -d /run/systemd/system ] && systemd=yes
if [ $systemd = yes ]; then
	systemctl disable --now bomcensus-agent.service bomcensus-updater.path bomcensus-probe.socket >/dev/null 2>&1 || true
	systemctl stop 'bomcensus-probe@*.service' bomcensus-updater.service bomcensus-boot-check.service >/dev/null 2>&1 || true
fi
for u in $UNITS; do
	rm -f "${UNIT_DIR:?}/${u:?}"
done
[ $systemd = no ] || systemctl daemon-reload
rm -rf /run/bomcensus

# The agent is stopped, so nothing writes the install directory any more.
rm -rf "${OPT:?}"
if [ "$PURGE" = yes ]; then
	rm -rf "${VAR:?}"
	for u in bomcensus bomcensus-probe bomcensus-update; do
		if id "$u" >/dev/null 2>&1; then userdel "$u" 2>/dev/null || true; fi
		if getent group "$u" >/dev/null 2>&1; then groupdel "$u" 2>/dev/null || true; fi
	done
	echo "uninstall.sh: removed everything including state and users"
else
	rm -rf "${VAR:?}/update-spool"
	echo "uninstall.sh: kept $VAR/agent and the users; --purge removes them"
fi
