#!/usr/bin/env bash
# Copyright (C) 2026 JC-Lab
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
# Additional terms apply. See LICENSING.md.

# Builds, signs and packs a release.
#
# Usage: scripts/release.sh VERSION [OUTDIR]     (VERSION without a leading v)
#
# Writes OUTDIR (default dist/release):
#   assets/  files for the GitHub release
#            bomcensus-VERSION.tar                  agent bundle (signed manifest), Linux
#                                                   and Windows files
#            <command>_VERSION_linux_<arch>         every command, AuthentiELF-signed
#            <command>_VERSION_windows_<arch>.exe   every command, Authenticode-signed
#            bomcensus-systemd_VERSION.tar.gz       Linux host agent units and installer
#            bomcensus-windows_VERSION.zip          Windows installer scripts
#            SHA256SUMS
#   docker/  build context "dist" for deploy/docker/Dockerfile, with the same files
#
# Trust compiled into every binary (see docs/SECURITY.md §5):
#   MANIFEST_KEY_FILE / MANIFEST_KEY      Ed25519 manifest key: PEM file or text, or
#                                         MANIFEST_KEY_FILE=gcp-kms://<CryptoKeyVersion>
#                                         (EC_SIGN_ED25519). Its public key is compiled
#                                         in; it signs the bundle.
#   CODESIGN_ROOTS_FILE / CODESIGN_ROOTS  root certificates (PEM) that code
#                                         signatures must chain to
# Code signing, read by authentielf and scripts/sign-pe.sh:
#   SIGN_KEY_FILE / SIGN_KEY              PEM key, or gcp-kms://<Cloud KMS key>
#                                         (token in $GOOGLE_OAUTH_ACCESS_TOKEN)
#   SIGN_CERT_FILE / SIGN_CERT            signer certificate, then intermediates
#   SIGN_CHAIN_FILE / SIGN_CHAIN          further intermediates (optional)
#   SIGN_TSA                              RFC 3161 timestamp server (optional; set it
#                                         for releases, see docs/SECURITY.md §5.1)
#   GOOGLE_OAUTH_ACCESS_TOKEN             access token for the gcp-kms:// keys
# Tools:
#   AUTHENTIELF      authentielf command (default: authentielf)
#   JSIGN            jsign command (default: jsign)
#   PE_SIGNER        jsign (default), or go: sign Windows files with
#                    "bomcensus-release sign-pe" (PEM key files only, for local builds)
#   GO, node + pnpm (console), tar, gzip, sha256sum, zip (Windows)
set -euo pipefail

VERSION=${1:?usage: release.sh VERSION [OUTDIR]}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=$(realpath -m "${2:-$ROOT/dist/release}")
GO=${GO:-go}
read -ra authentielf <<<"${AUTHENTIELF:-authentielf}"
ARCHES=(amd64 arm64)
WINDOWS_ARCHES=(amd64 arm64)
# Commands packed into the agent bundle; the updater installs only the agent's.
BUNDLED=(bomcensus-agent bomcensus-probe bomcensus-updater bomcensus-scanner)
cd "$ROOT"

log() { echo "release.sh: $*" >&2; }
die() { log "$*"; exit 1; }

[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] ||
	die "version '$VERSION' is not MAJOR.MINOR.PATCH[-PRERELEASE]"
for tool in tar gzip sha256sum pnpm "${authentielf[0]}"; do
	command -v "$tool" >/dev/null || die "$tool is required"
done
PE_SIGNER=${PE_SIGNER:-jsign}
case $PE_SIGNER in
jsign)
	read -ra jsign <<<"${JSIGN:-jsign}"
	command -v "${jsign[0]}" >/dev/null || die "${jsign[0]} (\$JSIGN) is required for Windows"
	;;
go)
	case ${SIGN_KEY_FILE:-} in gcp-kms://*) die "PE_SIGNER=go takes PEM keys only" ;; esac
	;;
*) die "PE_SIGNER must be jsign or go" ;;
esac
command -v zip >/dev/null || die "zip is required for Windows"
[ -d deploy/windows ] || die "deploy/windows (Windows installer) is missing"
[ -n "${SIGN_KEY_FILE:-}${SIGN_KEY:-}" ] || die "SIGN_KEY_FILE or SIGN_KEY is required"
[ -n "${SIGN_CERT_FILE:-}${SIGN_CERT:-}" ] || die "SIGN_CERT_FILE or SIGN_CERT is required"
[ -n "${SIGN_TSA:-}" ] || log "WARNING: SIGN_TSA is not set; signatures stop verifying when the signing certificate expires"

: "${SOURCE_DATE_EPOCH:=$(git log -1 --format=%ct 2>/dev/null || date +%s)}"
export SOURCE_DATE_EPOCH

case $OUT in /*/*) ;; *) die "refusing output directory $OUT" ;; esac
rm -rf "${OUT:?}"
mkdir -p "$OUT/assets" "$OUT/docker"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
chmod 700 "$work"

# pem_source VAR_FILE VAR NAME prints the path in $VAR_FILE, or writes the
# text of $VAR to $work/NAME and prints that path.
pem_source() {
	local f=${!1:-} t=${!2:-}
	if [ -n "$f" ] && [ -n "$t" ]; then die "both \$$1 and \$$2 are set; use one"; fi
	if [ -n "$t" ]; then
		(umask 077 && printf '%s\n' "$t" >"$work/$3")
		echo "$work/$3"
	elif [ -n "$f" ]; then
		echo "$f"
	else
		die "\$$1 or \$$2 is required"
	fi
}

# retry runs a signing command again on failure (KMS and TSA hiccups). Both
# signers replace an earlier signature, so a retry is idempotent.
retry() {
	local i
	for i in 1 2 3; do
		"$@" >&2 && return 0
		log "'$*' failed (attempt $i)"
		sleep $((i * 5))
	done
	return 1
}

# ---- trust -----------------------------------------------------------------
manifest_key=$(pem_source MANIFEST_KEY_FILE MANIFEST_KEY manifest.key)
roots=$(pem_source CODESIGN_ROOTS_FILE CODESIGN_ROOTS codesign-roots.pem)
keys=$work/keys
mkdir "$keys"
cp "$roots" "$keys/codesign-ca.crt"

host=$work/bomcensus-release
CGO_ENABLED=0 "$GO" build -trimpath -o "$host" ./cmd/bomcensus-release
"$host" manifest-pub --manifest-key "$manifest_key" >"$keys/manifest.pub"
log "manifest key $(sha256sum <"$keys/manifest.pub" | cut -c1-16)…"
trust=$("$host" print-ldflags --keys "$keys")
ldflags="-s -w -buildid= -X github.com/bomcensus/bomcensus/internal/version.Version=$VERSION $trust"
# Host build with the trust, for verifying the bundle below.
CGO_ENABLED=0 "$GO" build -trimpath -ldflags "$ldflags" -o "$host" ./cmd/bomcensus-release

# ---- console ---------------------------------------------------------------
log "building the console"
(cd frontend && CI=true NUXT_TELEMETRY_DISABLED=1 pnpm install --frozen-lockfile && pnpm exec nuxt generate) >&2
test -f frontend/.output/public/index.html || die "console: no index.html"
embed=internal/server/console/dist
find "$embed" -mindepth 1 -maxdepth 1 ! -name placeholder -exec rm -rf -- {} +
cp -R frontend/.output/public/. "$embed/"

# ---- build -----------------------------------------------------------------
commands=()
for d in cmd/bomcensus-*/; do
	if ls "$d"*.go >/dev/null 2>&1; then commands+=("$(basename "$d")"); fi
done
bin=$work/bin
elf=()
for arch in "${ARCHES[@]}"; do
	for c in "${commands[@]}"; do
		log "build $c linux/$arch"
		CGO_ENABLED=0 GOOS=linux GOARCH=$arch "$GO" build -trimpath -buildvcs=false \
			-ldflags "$ldflags" -o "$bin/linux-$arch/$c" "./cmd/$c"
		elf+=("$bin/linux-$arch/$c")
	done
done
pe=()
for arch in "${WINDOWS_ARCHES[@]}"; do
	for c in "${commands[@]}"; do
		log "build $c windows/$arch"
		CGO_ENABLED=0 GOOS=windows GOARCH=$arch "$GO" build -trimpath -buildvcs=false \
			-ldflags "$ldflags" -o "$bin/windows-$arch/$c.exe" "./cmd/$c"
		pe+=("$bin/windows-$arch/$c.exe")
	done
done

# ---- sign ------------------------------------------------------------------
sign_elf=(sign -n bomcensus)
if [ -n "${SIGN_TSA:-}" ]; then sign_elf+=(-t "$SIGN_TSA"); fi
for f in "${elf[@]}"; do
	log "sign ${f#"$bin"/}"
	retry "${authentielf[@]}" "${sign_elf[@]}" "$f"
done
if [ "$PE_SIGNER" = go ]; then
	pe_key=$(pem_source SIGN_KEY_FILE SIGN_KEY sign.key)
	pe_cert=$work/sign-chain.pem
	cat "$(pem_source SIGN_CERT_FILE SIGN_CERT sign.crt)" >"$pe_cert"
	if [ -n "${SIGN_CHAIN_FILE:-}${SIGN_CHAIN:-}" ]; then cat "$(pem_source SIGN_CHAIN_FILE SIGN_CHAIN chain.pem)" >>"$pe_cert"; fi
	pe_args=(sign-pe --key "$pe_key" --cert "$pe_cert")
	if [ -n "${SIGN_TSA:-}" ]; then pe_args+=(--timestamp-url "$SIGN_TSA"); fi
	log "sign ${#pe[@]} Windows files with bomcensus-release sign-pe"
	retry "$host" "${pe_args[@]}" "${pe[@]}"
else
	# One jsign run per command (it starts a JVM each time).
	for c in "${commands[@]}"; do
		files=()
		for arch in "${WINDOWS_ARCHES[@]}"; do files+=("$bin/windows-$arch/$c.exe"); done
		log "sign $c.exe (${WINDOWS_ARCHES[*]})"
		SIGN_NAME=$c retry "$ROOT/scripts/sign-pe.sh" "${files[@]}"
	done
fi
for f in "${elf[@]}"; do
	"${authentielf[@]}" verify -q -ca "$roots" "$f" || die "${f#"$bin"/}: signature does not verify"
done

# ---- bundle ----------------------------------------------------------------
bundle=$work/bundle
for arch in "${ARCHES[@]}"; do
	mkdir -p "$bundle/linux-$arch"
	for c in "${BUNDLED[@]}"; do
		cp "$bin/linux-$arch/$c" "$bundle/linux-$arch/$c"
	done
done
for arch in "${WINDOWS_ARCHES[@]}"; do
	mkdir -p "$bundle/windows-$arch"
	for c in "${BUNDLED[@]}"; do
		cp "$bin/windows-$arch/$c.exe" "$bundle/windows-$arch/$c.exe"
	done
done
tarball=bomcensus-$VERSION.tar
"$host" bundle --version "$VERSION" --manifest-key "$manifest_key" --dir "$bundle" --out "$OUT/assets/$tarball"
"$host" verify "$OUT/assets/$tarball"

# ---- assets ----------------------------------------------------------------
for f in "${elf[@]}" "${pe[@]}"; do
	platform=$(basename "$(dirname "$f")")
	name=$(basename "$f")
	ext=
	case $name in *.exe) ext=.exe name=${name%.exe} ;; esac
	cp "$f" "$OUT/assets/${name}_${VERSION}_${platform%%-*}_${platform#*-}$ext"
done

units=bomcensus-systemd_$VERSION
mkdir -p "$work/$units"
cp deploy/systemd/* LICENSE LICENSING.md "$work/$units/"
touch -d "@$SOURCE_DATE_EPOCH" "$work/$units" "$work/$units"/*
tar -C "$work" --sort=name --owner=0 --group=0 --numeric-owner \
	--mtime="@$SOURCE_DATE_EPOCH" -cf - "$units" | gzip -9n >"$OUT/assets/$units.tar.gz"

win=bomcensus-windows_$VERSION
mkdir -p "$work/$win"
cp deploy/windows/* LICENSE LICENSING.md "$work/$win/"
touch -d "@$SOURCE_DATE_EPOCH" "$work/$win" "$work/$win"/*
# Members in sorted order; zip -r would follow directory order.
(cd "$work" && LC_ALL=C find "$win" | LC_ALL=C sort | zip -qX -@ "$OUT/assets/$win.zip")

(cd "$OUT/assets" && sha256sum -- * >SHA256SUMS)

# ---- docker build context --------------------------------------------------
# Same layout as the /out directory of the Dockerfile's build stage.
mkdir -p "$OUT/docker/release"
cp "$OUT/assets/$tarball" "$OUT/docker/release/"
for arch in "${ARCHES[@]}"; do
	cp "$bin/linux-$arch/bomcensus-server" "$OUT/docker/bomcensus-server-linux-$arch"
done
for arch in "${ARCHES[@]}"; do
	mkdir -p "$OUT/docker/bundle"
	cp -R "$bundle/linux-$arch" "$OUT/docker/bundle/"
done

log "wrote $(find "$OUT/assets" -type f | wc -l) assets to $OUT/assets"
