#!/usr/bin/env bash
# Copyright (C) 2026 JC-Lab
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
# Additional terms apply. See LICENSING.md.

# Packages the Helm charts of a release.
#
# Usage: scripts/package-charts.sh VERSION IMAGE_REPO [OUTDIR]
#
# Copies deploy/charts, sets version and appVersion of both charts and the
# manager's dependency on the scanner chart to VERSION, points the default
# images to IMAGE_REPO/{server,scanner} (for example ghcr.io/OWNER/bomcensus),
# and writes bomcensus-scanner-VERSION.tgz and bomcensus-manager-VERSION.tgz
# to OUTDIR (default dist/charts).
set -euo pipefail

VERSION=${1:?usage: package-charts.sh VERSION IMAGE_REPO [OUTDIR]}
REPO=${2:?usage: package-charts.sh VERSION IMAGE_REPO [OUTDIR]}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=$(realpath -m "${3:-$ROOT/dist/charts}")
HELM=${HELM:-helm}

[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] ||
	{ echo "package-charts.sh: '$VERSION' is not MAJOR.MINOR.PATCH[-PRERELEASE]" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp -R "$ROOT/deploy/charts/bomcensus-manager" "$ROOT/deploy/charts/bomcensus-scanner" "$work/"
rm -rf "$work/bomcensus-manager/charts"

# set_top FILE KEY VALUE replaces a top-level "KEY: ..." line.
set_top() {
	grep -q "^$2:" "$1" || { echo "package-charts.sh: no $2 in $1" >&2; exit 1; }
	sed -i "s|^$2:.*|$2: $3|" "$1"
}
for c in bomcensus-manager bomcensus-scanner; do
	set_top "$work/$c/Chart.yaml" version "$VERSION"
	set_top "$work/$c/Chart.yaml" appVersion "\"$VERSION\""
done
# The only dependency of the manager is the scanner chart.
sed -i "/^dependencies:/,\$ s|^\(    version:\).*|\1 $VERSION|" "$work/bomcensus-manager/Chart.yaml"
sed -i "s|^  repository: ghcr.io/bomcensus/bomcensus/server$|  repository: $REPO/server|" "$work/bomcensus-manager/values.yaml"
sed -i "s|^  repository: ghcr.io/bomcensus/bomcensus/scanner$|  repository: $REPO/scanner|" "$work/bomcensus-scanner/values.yaml"
if ! grep -q "repository: $REPO/server$" "$work/bomcensus-manager/values.yaml" ||
	! grep -q "repository: $REPO/scanner$" "$work/bomcensus-scanner/values.yaml"; then
	echo "package-charts.sh: default image repositories not found in values.yaml" >&2
	exit 1
fi

mkdir -p "$OUT"
# Chart.lock names the old version; update rewrites it from the local chart.
"$HELM" dependency update --skip-refresh "$work/bomcensus-manager" >&2
"$HELM" package "$work/bomcensus-scanner" --destination "$OUT" >&2
"$HELM" package "$work/bomcensus-manager" --destination "$OUT" >&2
ls "$OUT"/bomcensus-scanner-"$VERSION".tgz "$OUT"/bomcensus-manager-"$VERSION".tgz
