#!/usr/bin/env bash
set -euo pipefail

POC_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TARGET_IMAGE=${TARGET_IMAGE:-nextgenhealthcare/connect:4.5.2@sha256:4afa295cfe7c5ffd596efee69594157fea87202e33d66bb4a98a52db4598f836}
ATTACKER_IMAGE=${ATTACKER_IMAGE:-python:3.11-slim@sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7}
LAB_PLATFORM=${LAB_PLATFORM:-linux/amd64}
LAB_SUFFIX=${LAB_SUFFIX:-$(date -u +%Y%m%dT%H%M%SZ)-$$-$RANDOM}
LAB_NETWORK="mirth-poc-${LAB_SUFFIX}"
TARGET_CONTAINER="mirth-poc-target-${LAB_SUFFIX}"
ATTACKER_CONTAINER="mirth-poc-attacker-${LAB_SUFFIX}"
LAB_OWNER="$(date -u +%Y%m%dT%H%M%SZ)-$$-$RANDOM-$RANDOM"
LAB_OWNER_LABEL="mirth.poc.owner"
LAB_STATE_DIR=""

container_is_owned() {
  local name=$1
  [[ "$(docker inspect --format '{{ index .Config.Labels "mirth.poc.owner" }}' \
    "$name" 2>/dev/null || true)" == "$LAB_OWNER" ]]
}

network_is_owned() {
  [[ "$(docker network inspect --format '{{ index .Labels "mirth.poc.owner" }}' \
    "$LAB_NETWORK" 2>/dev/null || true)" == "$LAB_OWNER" ]]
}

cleanup_lab() {
  if container_is_owned "$ATTACKER_CONTAINER"; then
    docker rm -f "$ATTACKER_CONTAINER" >/dev/null 2>&1 || true
  fi
  if container_is_owned "$TARGET_CONTAINER"; then
    docker rm -f "$TARGET_CONTAINER" >/dev/null 2>&1 || true
  fi
  if network_is_owned; then
    docker network rm "$LAB_NETWORK" >/dev/null 2>&1 || true
  fi
  if [[ -n "$LAB_STATE_DIR" && -d "$LAB_STATE_DIR" ]]; then
    rm -f -- "$LAB_STATE_DIR/canary.txt"
    rm -f -- "$LAB_STATE_DIR/xslt-control-channel.xml"
    rmdir -- "$LAB_STATE_DIR"
  fi
}

require_image() {
  local image=$1
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    docker pull --platform "$LAB_PLATFORM" "$image"
  fi
}

start_target() {
  local canary_value=$1
  require_image "$TARGET_IMAGE"
  require_image "$ATTACKER_IMAGE"
  LAB_STATE_DIR=$(mktemp -d)
  printf '%s' "$canary_value" >"$LAB_STATE_DIR/canary.txt"
  chmod 0644 "$LAB_STATE_DIR/canary.txt"

  docker network create --internal --label "$LAB_OWNER_LABEL=$LAB_OWNER" "$LAB_NETWORK" >/dev/null
  docker run -d --platform "$LAB_PLATFORM" --name "$TARGET_CONTAINER" \
    --label "$LAB_OWNER_LABEL=$LAB_OWNER" \
    --network "$LAB_NETWORK" \
    --mount "type=bind,src=$LAB_STATE_DIR/canary.txt,dst=/tmp/mirth-poc-canary.txt,readonly" \
    "$TARGET_IMAGE" >/dev/null

  wait_target_ready

  local version
  version=$(docker exec "$TARGET_CONTAINER" curl -skf \
    -H 'X-Requested-With: OpenAPI' \
    https://localhost:8443/api/server/version)
  [[ "$version" == "4.5.2" ]] || {
    printf 'unexpected target version: %s\n' "$version" >&2
    return 1
  }

  printf 'target_image=%s\n' "$TARGET_IMAGE"
  docker image inspect "$TARGET_IMAGE" --format 'target_image_id={{.Id}} target_repo_digests={{json .RepoDigests}}'
  printf 'target_version=%s target_container=%s lab_network=%s\n' "$version" "$TARGET_CONTAINER" "$LAB_NETWORK"
}

wait_target_ready() {
  for _ in $(seq 1 60); do
    if docker exec "$TARGET_CONTAINER" curl -skf \
      -H 'X-Requested-With: OpenAPI' \
      https://localhost:8443/api/server/version >/dev/null 2>&1; then
      printf 'target_ready=true\n'
      return 0
    fi
    sleep 2
  done
  printf 'target did not become ready\n' >&2
  return 1
}

install_channel() {
  local fixture=$1
  local channel_id=$2
  docker cp "$fixture" "$TARGET_CONTAINER:/tmp/poc-channel.xml" >/dev/null
  local create_response create_status created
  create_response=$(docker exec "$TARGET_CONTAINER" curl -skS -u admin:admin \
    -X POST https://localhost:8443/api/channels \
    -H 'Content-Type: application/xml' \
    -H 'Accept: text/plain' \
    -H 'X-Requested-With: OpenAPI' \
    -w $'\n%{http_code}' \
    --data-binary @/tmp/poc-channel.xml)
  create_status=${create_response##*$'\n'}
  created=${create_response%$'\n'*}
  printf 'channel_create_http_status=%s channel_create_body=%q\n' "$create_status" "$created"
  [[ "$create_status" == "200" && "$created" == "true" ]] || {
    printf 'channel creation failed\n' >&2
    docker logs --tail 160 "$TARGET_CONTAINER" >&2 || true
    return 1
  }

  local deploy_status
  deploy_status=$(docker exec "$TARGET_CONTAINER" curl -skS -u admin:admin \
    -X POST "https://localhost:8443/api/channels/${channel_id}/_deploy?returnErrors=true" \
    -H 'X-Requested-With: OpenAPI' \
    -o /dev/null -w '%{http_code}')
  printf 'channel_deploy_http_status=%s deployed_channel=%s\n' "$deploy_status" "$channel_id"
  [[ "$deploy_status" == "204" ]] || return 1
}

wait_listener() {
  local port=$1
  for _ in $(seq 1 30); do
    if docker exec "$TARGET_CONTAINER" curl -sS -o /dev/null \
      --connect-timeout 1 "http://localhost:${port}/" 2>/dev/null; then
      printf 'listener_ready_port=%s\n' "$port"
      return 0
    fi
    sleep 1
  done
  printf 'listener did not become ready on port %s\n' "$port" >&2
  return 1
}

run_attacker() {
  local poc_dir=$1
  shift
  docker run --rm --platform "$LAB_PLATFORM" --name "$ATTACKER_CONTAINER" \
    --label "$LAB_OWNER_LABEL=$LAB_OWNER" \
    --network "$LAB_NETWORK" \
    --mount "type=bind,src=$poc_dir,dst=/poc,readonly" \
    "$ATTACKER_IMAGE" python3 /poc/exploit.py "$@"
}
