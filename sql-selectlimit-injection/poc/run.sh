#!/usr/bin/env bash
set -euo pipefail

POC_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$POC_DIR/../../lab/common.sh"
trap cleanup_lab EXIT
mkdir -p "$POC_DIR/../evidence"
exec > >(tee "$POC_DIR/../evidence/current-run.log") 2>&1

CANARY="SQLI_CANARY_NOT_USED_${LAB_OWNER}"
start_target "$CANARY"
run_attacker "$POC_DIR" \
  --target "https://${TARGET_CONTAINER}:8443" \
  --confirm-dos

printf 'target_restart=begin\n'
docker restart "$TARGET_CONTAINER" >/dev/null
wait_target_ready

recovery_status=000
for _ in $(seq 1 30); do
  recovery_status=$(docker exec "$TARGET_CONTAINER" curl -skS -u admin:admin \
    -H 'X-Requested-With: OpenAPI' \
    -o /dev/null -w '%{http_code}' \
    https://localhost:8443/api/channels || true)
  [[ "$recovery_status" == "200" ]] && break
  sleep 2
done
printf 'database_api_post_restart_status=%s\n' "$recovery_status"
[[ "$recovery_status" == "200" ]] || {
  printf 'FAIL: DB-backed API did not recover after target restart\n' >&2
  exit 1
}
printf 'PASS: target restart restored DB-backed API availability\n'
