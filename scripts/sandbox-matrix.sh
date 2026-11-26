#!/usr/bin/env bash
# Copyright (C) 2026 JC-Lab
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
# Additional terms apply. See LICENSING.md.

# Runs the sandbox tests (SECURITY.md 6.2, 6.6) under the privilege
# scenarios that `go test ./...` as an ordinary user does not reach.
#
#   scripts/sandbox-matrix.sh docker   every scenario in a throwaway container
#                                      (default; needs Docker)
#   scripts/sandbox-matrix.sh host     the scenarios on this host as root
#                                      (needs passwordless sudo, setpriv and
#                                      unshare)
#   scripts/sandbox-matrix.sh build    only build the test binaries
#
# The test binaries are static (CGO_ENABLED=0) and need no Go toolchain
# where they run. Each scenario sets BOMCENSUS_SANDBOX_SCENARIO, and the
# tests assert what it promises (internal/sandbox/sandboxtest), so a
# regression is a test failure. A scenario also fails when a test is
# skipped, when no test ran, or when `bomcensus-probe self-test` reports a
# failed check. BOMCENSUS_TEST_LANDLOCK_ABI is the kernel's Landlock ABI as
# seen here, outside any container; the tests fail when they see another.
#
# Environment:
#   SANDBOX_BIN       directory for the binaries (default: a new temporary
#                     directory); it must be readable by every user
#   SANDBOX_NO_BUILD  1: use the binaries already in SANDBOX_BIN
#   SANDBOX_ONLY      run only the scenarios whose label matches this
#                     extended regular expression
#   SANDBOX_IMAGE     container image (default debian:trixie-slim)
#   DOCKER            docker command (default docker)
#   SUDO              command that runs its arguments as root on the host
#                     (default sudo -n)

set -euo pipefail

IMAGE=${SANDBOX_IMAGE:-debian:trixie-slim}
DOCKER=${DOCKER:-docker}
SUDO=${SUDO-sudo -n}
ONLY=${SANDBOX_ONLY:-}
PROBE_TEST_VERSION=9.9.9-test

# Test selection per binary. Root without capabilities runs no version
# command, so the tests that need one are left out there.
ARTIFACT_TESTS='^(TestRunVersion.*|TestCommandSandboxCheck|TestExecutable|TestCollectExec.*|TestSandboxScenario)$'
ARTIFACT_TESTS_NOCAPS='^(TestSandboxScenario|TestExecutable|TestCollectExecDisabled|TestCollectExecNotOnContainerRoot|TestCollectExecFailureFallsBack|TestCollectExecFileChanged)$'

log() { printf '%s\n' "$*" >&2; }

# ---------------------------------------------------------------------------
# inner: runs inside a container or as the scenario's user on the host.
# Reads SANDBOX_BIN, SCENARIO and LANDLOCK_ABI.

inner_failed=0

# check NAME LOGFILE STATUS: a step fails on a non-zero status, a skipped
# test or a test binary that ran nothing.
check() {
	local name=$1 out=$2 status=$3 why=
	if [ "$status" -ne 0 ]; then
		why="exit status $status"
	elif grep -qE '^[[:space:]]*--- SKIP' "$out"; then
		why="skipped: $(grep -E '^[[:space:]]*--- SKIP' "$out" | sed 's/^[[:space:]]*--- SKIP: //; s/ (.*//' | tr '\n' ' ')"
	elif grep -q 'no tests to run' "$out"; then
		why="no tests ran"
	fi
	cat "$out"
	if [ -n "$why" ]; then
		echo "=== RESULT $SCENARIO $name: FAIL ($why)"
		inner_failed=1
	else
		echo "=== RESULT $SCENARIO $name: ok"
	fi
}

# step NAME COMMAND...: runs one test binary or command.
step() {
	local name=$1 out status
	shift
	out=$(mktemp)
	echo "=== STEP $SCENARIO $name: $*"
	set +e
	"$@" >"$out" 2>&1
	status=$?
	set -e
	check "$name" "$out" "$status"
	rm -f "$out"
}

run_inner() {
	local b=$SANDBOX_BIN
	export BOMCENSUS_SANDBOX_SCENARIO=$SCENARIO
	export BOMCENSUS_TEST_LANDLOCK_ABI=$LANDLOCK_ABI
	export BOMCENSUS_TEST_HELPER=$b/fakesw
	export BOMCENSUS_PROBE_TEST_FAKE_NODE=$b/fakenode
	export BOMCENSUS_TEST_PROBE_BINARY=$b/bomcensus-probe
	export BOMCENSUS_PROBE_ROOT_TEST=1
	cd /

	echo "=== $SCENARIO: $(id)"
	grep -E '^(Cap(Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp):' /proc/self/status
	echo "Landlock ABI expected: $LANDLOCK_ABI"

	local artifact=$ARTIFACT_TESTS probe=TestSandboxRestrictions
	case $SCENARIO in *nocaps) artifact=$ARTIFACT_TESTS_NOCAPS ;; esac
	[ "$(id -u)" -eq 0 ] && probe=TestSandboxRoot
	step sandbox "$b/sandbox.test" -test.v -test.timeout=5m
	step artifact "$b/artifact.test" -test.v -test.timeout=5m -test.run "$artifact"
	step probe "$b/probe.test" -test.v -test.timeout=5m -test.run "^$probe\$"
	step self-test-checks "$b/probecmd.test" -test.v -test.timeout=5m -test.run '^TestSelfTest$'
	step self-test "$b/bomcensus-probe" self-test
	return $inner_failed
}

# run_hostroot: collect --host-root against a read-only bind of /, in a
# private mount namespace (started with unshare -m) so that nothing remains
# mounted afterwards.
run_hostroot() {
	local mnt
	mnt=$(mktemp -d)
	export BOMCENSUS_PROBE_TEST_FAKE_NODE=$SANDBOX_BIN/fakenode
	export BOMCENSUS_TEST_PROBE_BINARY=$SANDBOX_BIN/bomcensus-probe
	export BOMCENSUS_TEST_HOST_ROOT=$mnt
	echo "=== $SCENARIO: $(id), host root $mnt"
	mount --make-rprivate /
	mount --rbind / "$mnt"
	mount -o remount,bind,ro "$mnt"
	step collect-host-root "$SANDBOX_BIN/probecmd.test" -test.v -test.timeout=5m -test.run '^TestCollectHostRoot$'
	return $inner_failed
}

# ---------------------------------------------------------------------------
# outer

build() {
	local b=$1 root
	root=$(cd "$(dirname "$0")/.." && pwd)
	log "building test binaries in $b"
	(
		cd "$root"
		export CGO_ENABLED=0
		go test -c -o "$b/sandbox.test" ./internal/sandbox
		go test -c -o "$b/artifact.test" ./internal/collect/artifact
		go test -c -o "$b/probe.test" ./internal/probe
		go test -c -o "$b/probecmd.test" ./cmd/bomcensus-probe
		go build -trimpath -ldflags "-s -w -X github.com/bomcensus/bomcensus/internal/version.Version=$PROBE_TEST_VERSION" \
			-o "$b/bomcensus-probe" ./cmd/bomcensus-probe
		go build -o "$b/fakesw" ./internal/collect/artifact/testdata/fakesw
		go build -o "$b/fakenode" ./internal/probe/testdata/fakenode
	)
	cp "$0" "$b/sandbox-matrix.sh"
	chmod 755 "$b"
	chmod -R a+rX "$b"
}

landlock_abi() {
	BOMCENSUS_SANDBOX_TEST_CHILD=abi "$1/sandbox.test"
}

results=()
failed=0

# record LABEL STATUS LOG
record() {
	if [ "$2" -eq 0 ]; then
		results+=("ok    $1")
	else
		results+=("FAIL  $1  (log: $3)")
		failed=1
		if [ -n "${GITHUB_ACTIONS:-}" ]; then
			echo "::error title=sandbox scenario $1::$(grep -E '^=== RESULT .*FAIL' "$3" | head -5 | tr '\n' ' ')"
		fi
	fi
}

selected() { [ -z "$ONLY" ] || [[ $1 =~ $ONLY ]]; }

# run_logged LABEL COMMAND...: runs a scenario, keeps its log, records it.
run_logged() {
	local label=$1 lf status
	shift
	selected "$label" || return 0
	lf=$LOGS/$label.log
	log "--- $label"
	set +e
	"$@" >"$lf" 2>&1
	status=$?
	set -e
	grep -E '^=== RESULT' "$lf" >&2 || true
	if [ "$status" -ne 0 ]; then
		if [ -n "${GITHUB_ACTIONS:-}" ]; then
			echo "::group::$label log"
			cat "$lf"
			echo "::endgroup::"
		else
			grep -E -- '--- FAIL' "$lf" >&2 || true
		fi
	fi
	record "$label" "$status" "$lf"
}

docker_scenario() {
	local label=$1 scenario=$2
	shift 2
	run_logged "$label" "$DOCKER" run --rm --init --network none \
		-v "$BIN:/t:ro" -e SANDBOX_BIN=/t -e SCENARIO="$scenario" -e LANDLOCK_ABI="$ABI" \
		"$@" "$IMAGE" bash /t/sandbox-matrix.sh inner
}

run_docker() {
	local unconfined=(--security-opt seccomp=unconfined)
	local s args
	for s in \
		"root-default|" \
		"root-drop|--cap-add DAC_READ_SEARCH --cap-add SYS_PTRACE" \
		"root-nocaps|--cap-drop ALL" \
		"user|--user 1000:1000" \
		"root-sysadmin|--cap-add SYS_ADMIN"; do
		read -r -a args <<<"${s#*|}"
		docker_scenario "${s%%|*}" "${s%%|*}" ${args[@]+"${args[@]}"}
		docker_scenario "${s%%|*}-unconfined" "${s%%|*}" ${args[@]+"${args[@]}"} "${unconfined[@]}"
	done
}

# Runs this script's inner mode as root through SUDO, with only the
# variables it needs, optionally under a setpriv wrapper.
as_root() {
	local scenario=$1
	shift
	# shellcheck disable=SC2086 # SUDO is a command with arguments
	$SUDO env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
		SANDBOX_BIN="$BIN" SCENARIO="$scenario" LANDLOCK_ABI="$ABI" "$@"
}

run_host() {
	local inner=(bash "$BIN/sandbox-matrix.sh" inner)
	# shellcheck disable=SC2086
	if ! $SUDO true; then
		log "host scenarios need root without a password through: $SUDO"
		exit 1
	fi
	command -v setpriv >/dev/null || { log "setpriv (util-linux) not found"; exit 1; }

	# Root with every capability: the probe switches to 65534 and keeps
	# the two read capabilities.
	run_logged host-root as_root host-root "${inner[@]}"
	# What deploy/systemd/bomcensus-probe@.service gives the probe: a
	# non-root user with CAP_DAC_READ_SEARCH and CAP_SYS_PTRACE as ambient
	# capabilities, no_new_privs.
	local two=+dac_read_search,+sys_ptrace
	run_logged host-unit as_root host-unit setpriv --reuid=65533 --regid=65533 --clear-groups \
		--inh-caps=-all,$two --ambient-caps=-all,$two --bounding-set=-all,$two --no-new-privs "${inner[@]}"
	# Root with every capability dropped: no version command may run.
	run_logged host-nocaps as_root host-nocaps setpriv --inh-caps=-all --ambient-caps=-all --bounding-set=-all "${inner[@]}"
	# The invoking user, or uid 1000 when that is root.
	if [ "$(id -u)" -ne 0 ]; then
		run_logged host-user env -i PATH="$PATH" SANDBOX_BIN="$BIN" SCENARIO=host-user LANDLOCK_ABI="$ABI" "${inner[@]}"
	else
		run_logged host-user as_root host-user setpriv --reuid=1000 --regid=1000 --clear-groups --inh-caps=-all "${inner[@]}"
	fi
	# collect --host-root against a read-only bind of /.
	if command -v unshare >/dev/null; then
		run_logged host-hostroot as_root host-hostroot unshare -m bash "$BIN/sandbox-matrix.sh" inner-hostroot
	else
		log "host-hostroot skipped: unshare (util-linux) not found"
		results+=("skip  host-hostroot  (no unshare)")
	fi
}

main() {
	local mode=${1:-docker}
	case $mode in
	inner)
		run_inner
		return
		;;
	inner-hostroot)
		run_hostroot
		return
		;;
	build | docker | host) ;;
	*)
		log "usage: $0 [docker|host|build]"
		exit 2
		;;
	esac

	BIN=${SANDBOX_BIN:-$(mktemp -d "${TMPDIR:-/tmp}/bomcensus-sandbox.XXXXXX")}
	mkdir -p "$BIN"
	BIN=$(cd "$BIN" && pwd)
	if [ "${SANDBOX_NO_BUILD:-}" != 1 ]; then
		build "$BIN"
	fi
	[ "$mode" = build ] && { log "binaries in $BIN"; return; }

	ABI=$(landlock_abi "$BIN")
	LOGS=$BIN/logs
	mkdir -p "$LOGS"
	log "kernel $(uname -r) $(uname -m), Landlock ABI $ABI; logs in $LOGS"
	case $mode in
	docker) run_docker ;;
	host) run_host ;;
	esac

	log ""
	log "sandbox matrix ($mode, $(uname -m), kernel $(uname -r), Landlock ABI $ABI):"
	printf '  %s\n' "${results[@]}" >&2
	[ "${#results[@]}" -gt 0 ] || { log "no scenario selected"; exit 1; }
	exit $failed
}

main "$@"
