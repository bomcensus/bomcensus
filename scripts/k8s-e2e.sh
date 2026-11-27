#!/usr/bin/env bash
# Copyright (C) 2026 JC-Lab
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
# Additional terms apply. See LICENSING.md.

# End-to-end test of a pod that both the node agent and the in-cluster
# scanner collect (DEPLOYMENT.md 3.7), on a k3d cluster:
#
#   - builds the server, scanner and node-agent images and imports them
#   - deploys a test workload (redis, built from source on Alpine) and
#     PostgreSQL
#   - installs the manager chart with the scanner (exec allowed) and the
#     node agent, registers the cluster and syncs it
#   - gives musl a vulnerability directly in the database (there is no feed
#     server) and waits for the findings
#
# and checks that the pod's findings, processes and listening ports belong
# to the workload asset only, with the node that saw them, and that the
# image content comes from inside the container: redis-server is not an OS
# package, so its version is that of its version command.
#
# Environment:
#   K8S_E2E_CLUSTER   k3d cluster name (default bomcensus-e2e)
#   K8S_E2E_KEEP      1: keep the cluster after the run
#   K8S_E2E_NO_BUILD  1: use the images already built for VERSION
#   K8S_E2E_LOGS      directory for logs and API answers (default: a new
#                     temporary directory)
#   K8S_E2E_TIMEOUT   seconds for each wait (default 600)
#   K8S_E2E_APP_IMAGE image of the test workload (default redis:7.4-alpine);
#                     it must listen on K8S_E2E_APP_PORT (default 6379) and
#                     contain K8S_E2E_APP_SOFTWARE (default redis), detected
#                     by a version command, and the apk package musl
#   VERSION           image tag (default 0.0.0-e2e)
#   DOCKER_REPO       image repository prefix (default bomcensus)

set -euo pipefail

CLUSTER=${K8S_E2E_CLUSTER:-bomcensus-e2e}
KEEP=${K8S_E2E_KEEP:-0}
NO_BUILD=${K8S_E2E_NO_BUILD:-0}
LOGS=${K8S_E2E_LOGS:-$(mktemp -d)}
TIMEOUT=${K8S_E2E_TIMEOUT:-600}
APP_IMAGE=${K8S_E2E_APP_IMAGE:-redis:7.4-alpine}
APP_PORT=${K8S_E2E_APP_PORT:-6379}
APP_SOFTWARE=${K8S_E2E_APP_SOFTWARE:-redis}
# kubectl create deployment names the container after the image.
APP_CONTAINER=${APP_IMAGE##*/}
APP_CONTAINER=${APP_CONTAINER%%[:@]*}
VERSION=${VERSION:-0.0.0-e2e}
REPO=${DOCKER_REPO:-bomcensus}

NS=bomcensus
APP_NS=e2e-app
RELEASE=bomcensus
ADMIN_PASSWORD=e2e-admin
VULN=CVE-E2E-0001
API=
KUBECTL="kubectl --context k3d-$CLUSTER"

mkdir -p "$LOGS"
JAR=$LOGS/cookies
PF_PID=

log() { printf '== %s\n' "$*" >&2; }
fail() {
	printf 'FAIL: %s\n' "$*" >&2
	exit 1
}

# wait_for DESCRIPTION COMMAND...: runs COMMAND every 5 seconds until it
# succeeds or K8S_E2E_TIMEOUT passes.
wait_for() {
	local what=$1 deadline=$((SECONDS + TIMEOUT))
	shift
	log "waiting for $what"
	until "$@"; do
		if ((SECONDS >= deadline)); then
			fail "timed out waiting for $what"
		fi
		sleep 5
	done
}

collect_logs() {
	log "logs in $LOGS"
	$KUBECTL get pods -A -o wide >"$LOGS/pods.txt" 2>&1 || true
	$KUBECTL get events -A --sort-by=.lastTimestamp >"$LOGS/events.txt" 2>&1 || true
	local p
	for p in $($KUBECTL -n "$NS" get pods -o name 2>/dev/null); do
		$KUBECTL -n "$NS" logs "$p" --all-containers --prefix >"$LOGS/$(basename "$p").log" 2>&1 || true
	done
}

cleanup() {
	local status=$?
	if [ -n "$PF_PID" ]; then
		kill "$PF_PID" 2>/dev/null || true
	fi
	if [ "$status" -ne 0 ]; then
		collect_logs
	fi
	if [ "$KEEP" != 1 ]; then
		k3d cluster delete "$CLUSTER" >/dev/null 2>&1 || true
	else
		log "cluster $CLUSTER kept"
	fi
	exit "$status"
}

# api METHOD PATH [BODY]: calls the admin API and prints the answer.
api() {
	local method=$1 path=$2 body=${3:-}
	local args=(-ksS --fail-with-body -b "$JAR" -c "$JAR" -X "$method" -H 'X-Requested-With: bomcensus')
	if [ -n "$body" ]; then
		args+=(-H 'Content-Type: application/json' --data "$body")
	fi
	curl "${args[@]}" "$API$path"
}

psql_q() {
	$KUBECTL -n "$NS" exec deploy/postgres -- psql -U postgres -d bomcensus -v ON_ERROR_STOP=1 -tAc "$1"
}

build_images() {
	if [ "$NO_BUILD" = 1 ]; then
		return
	fi
	log "building images $REPO/{server,scanner,node-agent}:$VERSION"
	make docker-build DOCKER_TARGETS="server scanner node-agent" VERSION="$VERSION" DOCKER_REPO="$REPO"
}

cluster_up() {
	log "creating k3d cluster $CLUSTER"
	k3d cluster delete "$CLUSTER" >/dev/null 2>&1 || true
	k3d cluster create "$CLUSTER" --agents 1 --wait --timeout 300s \
		--k3s-arg '--disable=traefik@server:0' --k3s-arg '--disable=metrics-server@server:0'
	k3d image import -c "$CLUSTER" "$REPO/server:$VERSION" "$REPO/scanner:$VERSION" "$REPO/node-agent:$VERSION"
}

# The workload runs before the node agents start, so that their first
# collection sees it. Its image is pulled from the registry: an imported
# image has another digest on the node than in the pod status.
deploy_app() {
	log "deploying the test workload"
	$KUBECTL create namespace "$APP_NS"
	$KUBECTL -n "$APP_NS" create deployment web --image="$APP_IMAGE" --port="$APP_PORT"
	$KUBECTL -n "$APP_NS" rollout status deployment/web --timeout="${TIMEOUT}s"
}

deploy_postgres() {
	log "deploying PostgreSQL"
	$KUBECTL create namespace "$NS"
	$KUBECTL label namespace "$NS" pod-security.kubernetes.io/enforce=privileged
	$KUBECTL -n "$NS" apply -f - <<-EOF
		apiVersion: apps/v1
		kind: Deployment
		metadata:
		  name: postgres
		spec:
		  selector:
		    matchLabels: {app: postgres}
		  template:
		    metadata:
		      labels: {app: postgres}
		    spec:
		      containers:
		        - name: postgres
		          image: postgres:17-alpine
		          env:
		            - {name: POSTGRES_PASSWORD, value: e2e}
		            - {name: POSTGRES_DB, value: bomcensus}
		          ports:
		            - containerPort: 5432
		          readinessProbe:
		            exec:
		              command: [pg_isready, -U, postgres]
		            periodSeconds: 2
		---
		apiVersion: v1
		kind: Service
		metadata:
		  name: postgres
		spec:
		  selector: {app: postgres}
		  ports:
		    - port: 5432
	EOF
	$KUBECTL -n "$NS" rollout status deployment/postgres --timeout="${TIMEOUT}s"
}

install_bomcensus() {
	log "installing the manager chart with the scanner and the node agent"
	local hash
	hash=$(printf '%s' "$ADMIN_PASSWORD" | docker run --rm -i "$REPO/server:$VERSION" hash-password)
	make helm-deps >/dev/null
	# A values file: the hash has commas, which --set would split.
	cat >"$LOGS/values.yaml" <<-EOF
		image: {repository: "$REPO/server", tag: "$VERSION"}
		database:
		  url: "postgres://postgres:e2e@postgres.$NS.svc:5432/bomcensus?sslmode=disable"
		admin:
		  passwordHash: '$hash'
		scanner:
		  enabled: true
		  image: {repository: "$REPO/scanner", tag: "$VERSION"}
		  rbac: {exec: true}
		  nodeAgent:
		    enabled: true
		    image: {repository: "$REPO/node-agent", tag: "$VERSION"}
	EOF
	helm --kube-context "k3d-$CLUSTER" install "$RELEASE" deploy/charts/bomcensus-manager -n "$NS" -f "$LOGS/values.yaml"
	$KUBECTL -n "$NS" rollout status deployment/"$RELEASE" --timeout="${TIMEOUT}s"

	# A free local port, read from kubectl's first line.
	$KUBECTL -n "$NS" port-forward --address 127.0.0.1 svc/"$RELEASE"-web :8080 >"$LOGS/port-forward.log" 2>&1 &
	PF_PID=$!
	wait_for "the port forward" grep -q '^Forwarding from 127.0.0.1:' "$LOGS/port-forward.log"
	API=https://127.0.0.1:$(sed -n 's/^Forwarding from 127\.0\.0\.1:\([0-9]*\) .*/\1/p' "$LOGS/port-forward.log" | head -1)/api/v1
	wait_for "the console" curl -ks -o /dev/null "$API/auth/login"
	api POST /auth/login "{\"username\":\"admin\",\"password\":\"$ADMIN_PASSWORD\"}" >/dev/null
}

scanner_id() {
	api GET '/agents?kind=scanner&limit=10' | jq -er '[.items[] | select(.status == "online")][0].id'
}

node_agents_seen() {
	local n
	n=$(api GET '/assets?kind=host&limit=10' | jq '.items | length')
	[ "$n" -ge 2 ]
}

register_cluster() {
	wait_for "the scanner" scanner_id
	wait_for "both node agents" node_agents_seen
	local sid body
	sid=$(scanner_id)
	body=$(jq -n --arg s "$sid" --arg ns "$APP_NS" '{name: "e2e", connection: "in_cluster", scannerId: $s,
		execEnabled: true, filter: {nsInclude: [$ns], nsExclude: [], labelInclude: [], labelExclude: [],
		annotationInclude: [], annotationExclude: []}}')
	CLUSTER_ID=$(api POST /k8s/clusters "$body" | jq -er .id)
	api POST "/k8s/clusters/$CLUSTER_ID/sync" >/dev/null
}

workload_id() {
	WORKLOAD=$(api GET "/assets?kind=workload&clusterId=$CLUSTER_ID&limit=10" | jq -er '.items[0].id') && [ -n "$WORKLOAD" ]
}

# linked_host: the host asset that runs the pod, and the name of its
# container, linked to the workload.
linked_host() {
	local id link
	for id in $(api GET '/assets?kind=host&limit=10' | jq -r '.items[].id'); do
		link=$(api GET "/assets/$id" | jq -r --arg w "$WORKLOAD" \
			'[.containers[]? | select(.workload.assetId == $w)][0] // empty | .name')
		if [ -n "$link" ]; then
			HOST=$id HOST_CONTAINER=$link
			HOST_NAME=$(api GET "/assets/$id" | jq -r .name)
			return 0
		fi
	done
	return 1
}

app_digest() {
	DIGEST=$($KUBECTL -n "$APP_NS" get pods -l app=web -o jsonpath='{.items[0].status.containerStatuses[0].imageID}')
	DIGEST=sha256:${DIGEST##*sha256:}
}

exec_content() {
	[ "$(psql_q "SELECT content_exec FROM images WHERE digest = '$DIGEST'")" = t ]
}

seed_vuln() {
	log "seeding $VULN on musl"
	local n
	n=$(psql_q "SELECT count(*) FROM components WHERE type = 'apk' AND name = 'musl'")
	[ "$n" -ge 1 ] || fail "no musl component"
	psql_q "INSERT INTO vuln_meta (vuln_id, summary, severity, updated_at) VALUES ('$VULN', 'e2e', 'high', now())
		ON CONFLICT DO NOTHING" >/dev/null
	psql_q "INSERT INTO component_vulns (component_id, vuln_id, method, fix_state)
		SELECT id, '$VULN', 'package', 'not_fixed' FROM components WHERE type = 'apk' AND name = 'musl'
		ON CONFLICT DO NOTHING" >/dev/null
	psql_q "INSERT INTO asset_findings_state (asset_id, vulns_version) SELECT id, 1 FROM assets
		ON CONFLICT (asset_id) DO UPDATE SET vulns_version = asset_findings_state.vulns_version + 1" >/dev/null
}

# workload_finding: the workload's finding of VULN, with a process the node
# agent saw (node set) that listens on APP_PORT.
workload_finding() {
	api GET "/assets/$WORKLOAD/vulnerabilities" >"$LOGS/workload-vulns.json"
	jq -e --arg v "$VULN" --arg n "$HOST_NAME" --arg p "tcp/$APP_PORT" '[.items[] | select(.vulnId == $v)
		| select(any(.processes[]?; .node == $n and (.ports | index($p))))] | length > 0' \
		"$LOGS/workload-vulns.json" >/dev/null
}

check() {
	log "checking the host's findings"
	api GET "/assets/$HOST/vulnerabilities" >"$LOGS/host-vulns.json"
	if jq -e --arg c "$HOST_CONTAINER" '[.items[] | select(.container == $c)] | length > 0' "$LOGS/host-vulns.json" >/dev/null; then
		fail "host $HOST_NAME has findings of the pod container $HOST_CONTAINER"
	fi

	log "checking listening ports"
	# Every process holding the socket is a row; all are the workload's,
	# seen by the node agent (rows of exec collections are left out).
	api GET "/listen-ports?assetId=$WORKLOAD&port=$APP_PORT&limit=200" >"$LOGS/workload-ports.json"
	jq -e --arg n "$HOST_NAME" --arg c "$APP_CONTAINER" \
		'(.items | length > 0) and all(.items[]; .node == $n and .container == $c)' \
		"$LOGS/workload-ports.json" >/dev/null || fail "workload ports: $(cat "$LOGS/workload-ports.json")"
	api GET "/listen-ports?port=$APP_PORT&limit=200" >"$LOGS/ports.json"
	if jq -e --arg h "$HOST" '[.items[] | select(.assetId == $h)] | length > 0' "$LOGS/ports.json" >/dev/null; then
		fail "host $HOST_NAME lists the pod's port $APP_PORT: $(cat "$LOGS/ports.json")"
	fi

	log "checking the image content"
	# The node reports the image by the digest of the pod status, so both
	# collections wrote the content of the same digest.
	[ "$(psql_q "SELECT count(*) FROM asset_containers WHERE asset_id = '$HOST' AND name = '$HOST_CONTAINER'
		AND image_digest = '$DIGEST'")" = 1 ] || fail "the node reports $HOST_CONTAINER by another digest than $DIGEST"
	local method
	method=$(psql_q "SELECT ic.method FROM image_components ic JOIN components c ON c.id = ic.component_id
		WHERE ic.digest = '$DIGEST' AND c.name = '$APP_SOFTWARE' AND c.type <> 'apk' LIMIT 1")
	[ "$method" = exec ] || fail "$APP_SOFTWARE of $DIGEST detected by '$method', not by its version command"
}

main() {
	trap cleanup EXIT
	build_images
	cluster_up
	deploy_app
	deploy_postgres
	install_bomcensus
	register_cluster
	wait_for "the workload asset" workload_id
	wait_for "the link of the pod container to the workload" linked_host
	log "pod container $HOST_CONTAINER on $HOST_NAME"
	app_digest
	wait_for "image content collected through exec ($DIGEST)" exec_content
	seed_vuln
	wait_for "the workload's finding with the node's process" workload_finding
	check
	log "ok"
}

main "$@"
